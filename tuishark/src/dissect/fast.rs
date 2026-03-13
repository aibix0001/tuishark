use etherparse::{LinkSlice, NetSlice, SlicedPacket, TransportSlice};

use super::model::{
    EncMeta, Layer, LayerField, LinkMeta, LinkType, PacketDetail, PacketSummary, PfAction,
    PfDirection, PflogMeta, Protocol,
};

#[cfg(test)]
pub fn parse_packet(index: usize, timestamp: f64, data: &[u8]) -> PacketSummary {
    parse_packet_with_wire_len(index, timestamp, data, data.len(), LinkType::Ethernet)
}

pub fn parse_packet_with_wire_len(
    index: usize,
    timestamp: f64,
    data: &[u8],
    original_length: usize,
    link_type: LinkType,
) -> PacketSummary {
    let mut source = String::new();
    let mut destination = String::new();
    let mut protocol = Protocol::Unknown("???".into());
    let mut info = String::new();
    let mut src_port: Option<u16> = None;
    let mut dst_port: Option<u16> = None;
    let mut link_meta: Option<LinkMeta> = None;

    // For pflog/enc, parse the link header first; on failure, return early with Unknown protocol.
    let parsed_result = match link_type {
        LinkType::Ethernet => Some(SlicedPacket::from_ethernet(data)),
        LinkType::RawIp => Some(SlicedPacket::from_ip(data)),
        LinkType::LinuxSll => Some(SlicedPacket::from_linux_sll(data)),
        LinkType::Null => Some(parse_null_loopback(data)),
        LinkType::Pflog => {
            if let Some((meta, ip_data)) = parse_pflog_header(data) {
                protocol = Protocol::Pflog;
                info = format!(
                    "pflog {} {} on {} rule {}",
                    meta.action, meta.direction, meta.ifname, meta.rule_number
                );
                link_meta = Some(LinkMeta::Pflog(meta));
                Some(SlicedPacket::from_ip(ip_data))
            } else {
                None // unparseable pflog header
            }
        }
        LinkType::Enc => {
            if let Some((meta, ip_data)) = parse_enc_header(data) {
                protocol = Protocol::Enc;
                info = format!(
                    "enc AF={} SPI=0x{:08x} flags=0x{:x}",
                    meta.address_family, meta.spi, meta.flags
                );
                link_meta = Some(LinkMeta::Enc(meta));
                Some(SlicedPacket::from_ip(ip_data))
            } else {
                None // unparseable enc header
            }
        }
    };

    if let Some(Ok(parsed)) = parsed_result {
        // Link layer (Ethernet only)
        if let Some(LinkSlice::Ethernet2(ref eth)) = parsed.link {
            source = format_mac(eth.source());
            destination = format_mac(eth.destination());
            if matches!(protocol, Protocol::Unknown(_)) {
                protocol = Protocol::Ethernet;
            }
        }

        // Network layer
        match &parsed.net {
            Some(NetSlice::Ipv4(ipv4)) => {
                source = format!("{}", ipv4.header().source_addr());
                destination = format!("{}", ipv4.header().destination_addr());
                if !matches!(protocol, Protocol::Pflog | Protocol::Enc) {
                    protocol = Protocol::Ipv4;
                }
            }
            Some(NetSlice::Ipv6(ipv6)) => {
                source = format!("{}", ipv6.header().source_addr());
                destination = format!("{}", ipv6.header().destination_addr());
                if !matches!(protocol, Protocol::Pflog | Protocol::Enc) {
                    protocol = Protocol::Ipv6;
                }
            }
            _ => {}
        }

        // Transport layer
        match &parsed.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                let sp = tcp.source_port();
                let dp = tcp.destination_port();
                src_port = Some(sp);
                dst_port = Some(dp);
                if !matches!(protocol, Protocol::Pflog | Protocol::Enc) {
                    protocol = classify_tcp_port(sp, dp);
                }
                if info.is_empty() {
                    info = format_tcp_info(tcp);
                }
            }
            Some(TransportSlice::Udp(udp)) => {
                let sp = udp.source_port();
                let dp = udp.destination_port();
                src_port = Some(sp);
                dst_port = Some(dp);
                if !matches!(protocol, Protocol::Pflog | Protocol::Enc) {
                    protocol = classify_udp_port(sp, dp);
                }
                if info.is_empty() {
                    info = format!(
                        "{sp} → {dp} Len={}",
                        udp.length().saturating_sub(8)
                    );
                }
            }
            Some(TransportSlice::Icmpv4(icmp)) => {
                if !matches!(protocol, Protocol::Pflog | Protocol::Enc) {
                    protocol = Protocol::Icmp;
                }
                if info.is_empty() {
                    info = format!("ICMP {:?}", icmp.header().icmp_type);
                }
            }
            Some(TransportSlice::Icmpv6(icmp)) => {
                if !matches!(protocol, Protocol::Pflog | Protocol::Enc) {
                    protocol = Protocol::Icmpv6;
                }
                if info.is_empty() {
                    info = format!("ICMPv6 {:?}", icmp.header().icmp_type);
                }
            }
            _ => {}
        }

        // ARP detection: no IP/transport layer, check EtherType
        if parsed.net.is_none() && parsed.transport.is_none() {
            if let Some(LinkSlice::Ethernet2(ref eth)) = parsed.link {
                if eth.ether_type() == etherparse::EtherType::ARP {
                    protocol = Protocol::Arp;
                    info = "ARP".into();
                }
            }
        }
    }

    if info.is_empty() {
        info = protocol.to_string();
    }

    PacketSummary {
        index,
        timestamp,
        source,
        destination,
        protocol,
        length: data.len(),
        original_length,
        info,
        src_port,
        dst_port,
        link_meta,
    }
}

pub fn dissect_detail(data: &[u8], link_type: LinkType) -> PacketDetail {
    let mut detail = PacketDetail::default();

    // Link-layer header offset for byte ranges in deeper layers
    let link_hdr_len: usize;

    match link_type {
        LinkType::Pflog => {
            if let Some((meta, ip_data)) = parse_pflog_header(data) {
                link_hdr_len = meta.header_len;
                detail.layers.push(Layer {
                    name: format!("pflog ({} {} on {})", meta.action, meta.direction, meta.ifname),
                    fields: vec![
                        LayerField {
                            name: "Header Length".into(),
                            value: format!("{}", meta.header_len),
                            byte_range: Some((0, 1)),
                        },
                        LayerField {
                            name: "Address Family".into(),
                            value: format!("{}", data.get(1).copied().unwrap_or(0)),
                            byte_range: Some((1, 2)),
                        },
                        LayerField {
                            name: "Action".into(),
                            value: format!("{}", meta.action),
                            byte_range: Some((2, 3)),
                        },
                        LayerField {
                            name: "Reason".into(),
                            value: format!("{}", meta.reason),
                            byte_range: Some((3, 4)),
                        },
                        LayerField {
                            name: "Interface".into(),
                            value: meta.ifname.clone(),
                            byte_range: Some((4, 20)),
                        },
                        LayerField {
                            name: "Rule Number".into(),
                            value: format!("{}", meta.rule_number),
                            byte_range: Some((20, 24)),
                        },
                        LayerField {
                            name: "Direction".into(),
                            value: format!("{}", meta.direction),
                            byte_range: Some((44, 45)),
                        },
                    ],
                });
                dissect_ip_layers(&mut detail, ip_data, link_hdr_len);
            }
            return detail;
        }
        LinkType::Enc => {
            if let Some((meta, ip_data)) = parse_enc_header(data) {
                link_hdr_len = 12;
                detail.layers.push(Layer {
                    name: "enc (IPsec tunnel)".into(),
                    fields: vec![
                        LayerField {
                            name: "Address Family".into(),
                            value: format!("{}", meta.address_family),
                            byte_range: Some((0, 4)),
                        },
                        LayerField {
                            name: "SPI".into(),
                            value: format!("0x{:08x}", meta.spi),
                            byte_range: Some((4, 8)),
                        },
                        LayerField {
                            name: "Flags".into(),
                            value: format!("0x{:x}", meta.flags),
                            byte_range: Some((8, 12)),
                        },
                    ],
                });
                dissect_ip_layers(&mut detail, ip_data, link_hdr_len);
            }
            return detail;
        }
        LinkType::Null => {
            link_hdr_len = 4;
            if data.len() >= 4 {
                let af = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                let af_name = match af {
                    2 => "IPv4",
                    24 | 28 | 30 => "IPv6",
                    _ => "Unknown",
                };
                detail.layers.push(Layer {
                    name: format!("BSD Loopback (AF: {af_name})"),
                    fields: vec![LayerField {
                        name: "Address Family".into(),
                        value: format!("{af} ({af_name})"),
                        byte_range: Some((0, 4)),
                    }],
                });
                dissect_ip_layers(&mut detail, &data[4..], link_hdr_len);
            }
            return detail;
        }
        LinkType::RawIp => {
            link_hdr_len = 0;
            dissect_ip_layers(&mut detail, data, link_hdr_len);
            return detail;
        }
        LinkType::LinuxSll | LinkType::Ethernet => {
            // handled below via etherparse; both have fixed-size headers
            link_hdr_len = link_type.header_len().unwrap();
        }
    }

    let parsed_result = match link_type {
        LinkType::Ethernet => SlicedPacket::from_ethernet(data),
        LinkType::LinuxSll => SlicedPacket::from_linux_sll(data),
        _ => unreachable!(),
    };

    if let Ok(parsed) = parsed_result {
        // Ethernet layer
        if let Some(LinkSlice::Ethernet2(ref eth)) = parsed.link {
            detail.layers.push(Layer {
                name: "Ethernet II".into(),
                fields: vec![
                    LayerField {
                        name: "Destination".into(),
                        value: format_mac(eth.destination()),
                        byte_range: Some((0, 6)),
                    },
                    LayerField {
                        name: "Source".into(),
                        value: format_mac(eth.source()),
                        byte_range: Some((6, 12)),
                    },
                    LayerField {
                        name: "Type".into(),
                        value: format!("0x{:04x}", eth.ether_type().0),
                        byte_range: Some((12, 14)),
                    },
                ],
            });
        }

        // Linux SLL layer
        if let Some(LinkSlice::LinuxSll(ref sll)) = parsed.link {
            detail.layers.push(Layer {
                name: "Linux cooked capture (SLL)".into(),
                fields: vec![
                    LayerField {
                        name: "Packet type".into(),
                        value: format!("{:?}", sll.packet_type()),
                        byte_range: Some((0, 2)),
                    },
                    LayerField {
                        name: "Protocol".into(),
                        value: format!("{:?}", sll.protocol_type()),
                        byte_range: Some((14, 16)),
                    },
                ],
            });
        }

        // IP + transport layers (shared with non-Ethernet paths)
        dissect_ip_layers_from_parsed(&mut detail, &parsed, link_hdr_len);
    }

    detail
}

/// Parse the BSD Null/Loopback 4-byte header and dispatch to from_ip.
fn parse_null_loopback(data: &[u8]) -> Result<SlicedPacket<'_>, etherparse::err::packet::SliceError> {
    if data.len() < 4 {
        return Err(etherparse::err::packet::SliceError::Len(
            etherparse::err::LenError {
                required_len: 4,
                len: data.len(),
                len_source: etherparse::LenSource::Slice,
                layer: etherparse::err::Layer::Ethernet2Header,
                layer_start_offset: 0,
            },
        ));
    }
    SlicedPacket::from_ip(&data[4..])
}

/// Parse pflog header. Returns (metadata, remaining IP payload).
pub fn parse_pflog_header(data: &[u8]) -> Option<(PflogMeta, &[u8])> {
    // Minimum pflog header is determined by the length field at byte 0
    if data.is_empty() {
        return None;
    }
    let hdr_len = data[0] as usize;
    // Sanity: minimum 48 bytes (standard FreeBSD pflog), but respect the length field
    let actual_len = if hdr_len == 0 { 48 } else { hdr_len };
    if data.len() < actual_len {
        return None;
    }

    let action = match data[2] {
        0 => PfAction::Pass,
        1 => PfAction::Block,
        2 => PfAction::Scrub,
        3 => PfAction::NoScrub,
        4 => PfAction::Nat,
        5 => PfAction::NoNat,
        6 => PfAction::Binat,
        7 => PfAction::NoBinat,
        8 => PfAction::Rdr,
        9 => PfAction::NoRdr,
        10 => PfAction::Match,
        v => PfAction::Unknown(v),
    };

    let reason = data[3];

    // Interface name: bytes 4..20 (16 bytes, null-terminated)
    let ifname_bytes = &data[4..20];
    let ifname = std::str::from_utf8(ifname_bytes)
        .unwrap_or("")
        .trim_end_matches('\0')
        .to_string();

    // Rule number: bytes 20..24 (big-endian u32)
    let rule_number = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);

    // Direction: byte 44
    let direction = if actual_len > 44 {
        match data[44] {
            0 => PfDirection::In,    // PF_IN
            1 => PfDirection::Out,   // PF_OUT
            v => PfDirection::Unknown(v),
        }
    } else {
        PfDirection::Unknown(0xFF) // header too short — direction unavailable
    };

    Some((
        PflogMeta {
            action,
            direction,
            ifname,
            rule_number,
            reason,
            header_len: actual_len,
        },
        &data[actual_len..],
    ))
}

/// Parse enc (IPsec tunnel) header. Returns (metadata, remaining IP payload).
pub fn parse_enc_header(data: &[u8]) -> Option<(EncMeta, &[u8])> {
    if data.len() < 12 {
        return None;
    }
    // enc header is host-endian on BSD
    let address_family = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    let spi = u32::from_ne_bytes([data[4], data[5], data[6], data[7]]);
    let flags = u32::from_ne_bytes([data[8], data[9], data[10], data[11]]);

    Some((EncMeta { address_family, spi, flags }, &data[12..]))
}

/// Dissect IP layers from raw IP data, used by pflog/enc/null/raw link types.
fn dissect_ip_layers(detail: &mut PacketDetail, ip_data: &[u8], base_offset: usize) {
    if let Ok(parsed) = SlicedPacket::from_ip(ip_data) {
        dissect_ip_layers_from_parsed(detail, &parsed, base_offset);
    }
}

/// Dissect IP + transport layers from an already-parsed SlicedPacket.
/// Shared by both Ethernet/SLL and non-Ethernet paths.
fn dissect_ip_layers_from_parsed(detail: &mut PacketDetail, parsed: &SlicedPacket<'_>, base_offset: usize) {
    match &parsed.net {
        Some(NetSlice::Ipv4(ipv4)) => {
            let h = ipv4.header();
            detail.layers.push(Layer {
                name: format!(
                    "IPv4, Src: {}, Dst: {}",
                    h.source_addr(),
                    h.destination_addr()
                ),
                fields: vec![
                    LayerField {
                        name: "Version".into(),
                        value: "4".into(),
                        byte_range: Some((base_offset, base_offset + 1)),
                    },
                    LayerField {
                        name: "Header Length".into(),
                        value: format!("{} bytes", h.ihl() * 4),
                        byte_range: Some((base_offset, base_offset + 1)),
                    },
                    LayerField {
                        name: "Total Length".into(),
                        value: format!("{}", h.total_len()),
                        byte_range: Some((base_offset + 2, base_offset + 4)),
                    },
                    LayerField {
                        name: "TTL".into(),
                        value: format!("{}", h.ttl()),
                        byte_range: Some((base_offset + 8, base_offset + 9)),
                    },
                    LayerField {
                        name: "Protocol".into(),
                        value: format!("{}", h.protocol().0),
                        byte_range: Some((base_offset + 9, base_offset + 10)),
                    },
                    LayerField {
                        name: "Source".into(),
                        value: format!("{}", h.source_addr()),
                        byte_range: Some((base_offset + 12, base_offset + 16)),
                    },
                    LayerField {
                        name: "Destination".into(),
                        value: format!("{}", h.destination_addr()),
                        byte_range: Some((base_offset + 16, base_offset + 20)),
                    },
                ],
            });
        }
        Some(NetSlice::Ipv6(ipv6)) => {
            let h = ipv6.header();
            detail.layers.push(Layer {
                name: format!(
                    "IPv6, Src: {}, Dst: {}",
                    h.source_addr(),
                    h.destination_addr()
                ),
                fields: vec![
                    LayerField {
                        name: "Version".into(),
                        value: "6".into(),
                        byte_range: None,
                    },
                    LayerField {
                        name: "Payload Length".into(),
                        value: format!("{}", h.payload_length()),
                        byte_range: None,
                    },
                    LayerField {
                        name: "Hop Limit".into(),
                        value: format!("{}", h.hop_limit()),
                        byte_range: None,
                    },
                    LayerField {
                        name: "Source".into(),
                        value: format!("{}", h.source_addr()),
                        byte_range: None,
                    },
                    LayerField {
                        name: "Destination".into(),
                        value: format!("{}", h.destination_addr()),
                        byte_range: None,
                    },
                ],
            });
        }
        _ => {}
    }

    dissect_transport(detail, &parsed.transport);
}

/// Dissect transport layer (shared between Ethernet and non-Ethernet paths).
fn dissect_transport(detail: &mut PacketDetail, transport: &Option<TransportSlice<'_>>) {
    match transport {
        Some(TransportSlice::Tcp(tcp)) => {
            detail.layers.push(Layer {
                name: format!(
                    "TCP, Src Port: {}, Dst Port: {}",
                    tcp.source_port(),
                    tcp.destination_port()
                ),
                fields: vec![
                    LayerField {
                        name: "Source Port".into(),
                        value: format!("{}", tcp.source_port()),
                        byte_range: None,
                    },
                    LayerField {
                        name: "Destination Port".into(),
                        value: format!("{}", tcp.destination_port()),
                        byte_range: None,
                    },
                    LayerField {
                        name: "Sequence Number".into(),
                        value: format!("{}", tcp.sequence_number()),
                        byte_range: None,
                    },
                    LayerField {
                        name: "Acknowledgment Number".into(),
                        value: format!("{}", tcp.acknowledgment_number()),
                        byte_range: None,
                    },
                    LayerField {
                        name: "Flags".into(),
                        value: format_tcp_flags(tcp),
                        byte_range: None,
                    },
                    LayerField {
                        name: "Window Size".into(),
                        value: format!("{}", tcp.window_size()),
                        byte_range: None,
                    },
                ],
            });
        }
        Some(TransportSlice::Udp(udp)) => {
            detail.layers.push(Layer {
                name: format!(
                    "UDP, Src Port: {}, Dst Port: {}",
                    udp.source_port(),
                    udp.destination_port()
                ),
                fields: vec![
                    LayerField {
                        name: "Source Port".into(),
                        value: format!("{}", udp.source_port()),
                        byte_range: None,
                    },
                    LayerField {
                        name: "Destination Port".into(),
                        value: format!("{}", udp.destination_port()),
                        byte_range: None,
                    },
                    LayerField {
                        name: "Length".into(),
                        value: format!("{}", udp.length()),
                        byte_range: None,
                    },
                ],
            });
        }
        Some(TransportSlice::Icmpv4(_)) => {
            detail.layers.push(Layer {
                name: "ICMPv4".into(),
                fields: vec![],
            });
        }
        Some(TransportSlice::Icmpv6(_)) => {
            detail.layers.push(Layer {
                name: "ICMPv6".into(),
                fields: vec![],
            });
        }
        _ => {}
    }
}

fn format_mac(bytes: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

fn classify_tcp_port(src: u16, dst: u16) -> Protocol {
    match (src, dst) {
        (80, _) | (_, 80) | (8080, _) | (_, 8080) => Protocol::Http,
        (443, _) | (_, 443) => Protocol::Tls,
        _ => Protocol::Tcp,
    }
}

fn classify_udp_port(src: u16, dst: u16) -> Protocol {
    match (src, dst) {
        (53, _) | (_, 53) => Protocol::Dns,
        _ => Protocol::Udp,
    }
}

fn format_tcp_info(tcp: &etherparse::TcpSlice) -> String {
    let flags = format_tcp_flags(tcp);
    format!(
        "{} → {} [{}] Seq={} Ack={} Win={}",
        tcp.source_port(),
        tcp.destination_port(),
        flags,
        tcp.sequence_number(),
        tcp.acknowledgment_number(),
        tcp.window_size(),
    )
}

fn format_tcp_flags(tcp: &etherparse::TcpSlice) -> String {
    let mut flags = Vec::new();
    if tcp.syn() {
        flags.push("SYN");
    }
    if tcp.ack() {
        flags.push("ACK");
    }
    if tcp.fin() {
        flags.push("FIN");
    }
    if tcp.rst() {
        flags.push("RST");
    }
    if tcp.psh() {
        flags.push("PSH");
    }
    if tcp.urg() {
        flags.push("URG");
    }
    flags.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_eth_ipv4_tcp(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet header
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst mac
        pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // src mac
        pkt.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
        // IPv4 header (20 bytes)
        pkt.push(0x45); // version + IHL
        pkt.push(0x00); // DSCP
        pkt.extend_from_slice(&((40u16).to_be_bytes())); // total length (20 IP + 20 TCP)
        pkt.extend_from_slice(&[0x00, 0x00]); // identification
        pkt.extend_from_slice(&[0x40, 0x00]); // flags + fragment offset
        pkt.push(64); // TTL
        pkt.push(6);  // protocol TCP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);
        // TCP header (20 bytes)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&1000u32.to_be_bytes()); // seq
        pkt.extend_from_slice(&2000u32.to_be_bytes()); // ack
        pkt.push(0x50); // data offset = 5 (20 bytes)
        pkt.push(flags);
        pkt.extend_from_slice(&65535u16.to_be_bytes()); // window
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&[0x00, 0x00]); // urgent pointer
        pkt
    }

    fn make_eth_ipv4_udp(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet header
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        pkt.extend_from_slice(&[0x08, 0x00]);
        // IPv4 header
        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&((28u16).to_be_bytes())); // 20 IP + 8 UDP
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x40, 0x00]);
        pkt.push(64);
        pkt.push(17); // UDP
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);
        // UDP header
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&8u16.to_be_bytes()); // length
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt
    }

    fn make_raw_ipv4_tcp(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
        let mut pkt = Vec::new();
        // IPv4 header (20 bytes) — no Ethernet header
        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&((40u16).to_be_bytes()));
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x40, 0x00]);
        pkt.push(64);
        pkt.push(6); // TCP
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);
        // TCP header (20 bytes)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&1000u32.to_be_bytes());
        pkt.extend_from_slice(&2000u32.to_be_bytes());
        pkt.push(0x50);
        pkt.push(flags);
        pkt.extend_from_slice(&65535u16.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt
    }

    fn make_pflog_packet(action: u8, direction: u8, ifname: &str, rule_number: u32) -> Vec<u8> {
        let mut pkt = vec![0u8; 48];
        pkt[0] = 48; // header length
        pkt[1] = 2;  // AF_INET
        pkt[2] = action;
        pkt[3] = 0;  // reason: match
        // interface name (bytes 4..20)
        let ifname_bytes = ifname.as_bytes();
        let copy_len = ifname_bytes.len().min(16);
        pkt[4..4 + copy_len].copy_from_slice(&ifname_bytes[..copy_len]);
        // rule number (bytes 20..24, big-endian)
        pkt[20..24].copy_from_slice(&rule_number.to_be_bytes());
        // direction at byte 44
        pkt[44] = direction;
        // Append a raw IPv4 TCP packet
        let ip_tcp = make_raw_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 0x02);
        pkt.extend_from_slice(&ip_tcp);
        pkt
    }

    fn make_enc_packet(af: u32, spi: u32, flags: u32) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&af.to_ne_bytes());
        pkt.extend_from_slice(&spi.to_ne_bytes());
        pkt.extend_from_slice(&flags.to_ne_bytes());
        // Append raw IPv4 TCP
        let ip_tcp = make_raw_ipv4_tcp([192, 168, 1, 1], [10, 0, 0, 1], 54321, 443, 0x10);
        pkt.extend_from_slice(&ip_tcp);
        pkt
    }

    fn make_null_loopback_packet(af: u32) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&af.to_ne_bytes());
        // Append raw IPv4 TCP
        let ip_tcp = make_raw_ipv4_tcp([127, 0, 0, 1], [127, 0, 0, 1], 8080, 80, 0x18);
        pkt.extend_from_slice(&ip_tcp);
        pkt
    }

    #[test]
    fn parse_tcp_syn() {
        let data = make_eth_ipv4_tcp([192, 168, 1, 10], [93, 184, 216, 34], 54321, 443, 0x02);
        let pkt = parse_packet(0, 0.0, &data);
        assert_eq!(pkt.source, "192.168.1.10");
        assert_eq!(pkt.destination, "93.184.216.34");
        assert!(matches!(pkt.protocol, Protocol::Tls)); // port 443
        assert!(pkt.info.contains("SYN"));
    }

    #[test]
    fn parse_udp_dns() {
        let data = make_eth_ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 12345, 53);
        let pkt = parse_packet(0, 1.0, &data);
        assert_eq!(pkt.source, "10.0.0.1");
        assert_eq!(pkt.destination, "8.8.8.8");
        assert!(matches!(pkt.protocol, Protocol::Dns));
    }

    #[test]
    fn parse_http_port() {
        let data = make_eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 54321, 80, 0x18);
        let pkt = parse_packet(0, 0.0, &data);
        assert!(matches!(pkt.protocol, Protocol::Http));
    }

    #[test]
    fn parse_plain_tcp() {
        let data = make_eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 12345, 9999, 0x10);
        let pkt = parse_packet(0, 0.0, &data);
        assert!(matches!(pkt.protocol, Protocol::Tcp));
    }

    #[test]
    fn parse_empty_data() {
        let pkt = parse_packet(0, 0.0, &[]);
        assert!(matches!(pkt.protocol, Protocol::Unknown(_)));
        assert_eq!(pkt.length, 0);
    }

    #[test]
    fn parse_truncated_data() {
        let pkt = parse_packet(0, 0.0, &[0xff, 0xff, 0xff]);
        assert!(matches!(pkt.protocol, Protocol::Unknown(_)));
    }

    #[test]
    fn dissect_detail_tcp() {
        let data = make_eth_ipv4_tcp([192, 168, 1, 10], [10, 0, 0, 1], 54321, 80, 0x02);
        let detail = dissect_detail(&data, LinkType::Ethernet);
        assert_eq!(detail.layers.len(), 3); // Ethernet, IPv4, TCP
        assert!(detail.layers[0].name.contains("Ethernet"));
        assert!(detail.layers[1].name.contains("IPv4"));
        assert!(detail.layers[2].name.contains("TCP"));
    }

    #[test]
    fn dissect_detail_empty() {
        let detail = dissect_detail(&[], LinkType::Ethernet);
        assert_eq!(detail.layers.len(), 0);
    }

    #[test]
    fn format_mac_test() {
        assert_eq!(format_mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]), "00:11:22:33:44:55");
        assert_eq!(format_mac([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), "ff:ff:ff:ff:ff:ff");
    }

    #[test]
    fn classify_ports() {
        assert!(matches!(classify_tcp_port(12345, 80), Protocol::Http));
        assert!(matches!(classify_tcp_port(80, 12345), Protocol::Http));
        assert!(matches!(classify_tcp_port(12345, 443), Protocol::Tls));
        assert!(matches!(classify_tcp_port(12345, 9999), Protocol::Tcp));
        assert!(matches!(classify_udp_port(12345, 53), Protocol::Dns));
        assert!(matches!(classify_udp_port(53, 12345), Protocol::Dns));
        assert!(matches!(classify_udp_port(12345, 9999), Protocol::Udp));
    }

    // --- Raw IP tests ---

    #[test]
    fn parse_raw_ip_tcp() {
        let data = make_raw_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 54321, 80, 0x02);
        let pkt = parse_packet_with_wire_len(0, 0.0, &data, data.len(), LinkType::RawIp);
        assert_eq!(pkt.source, "10.0.0.1");
        assert_eq!(pkt.destination, "10.0.0.2");
        assert!(matches!(pkt.protocol, Protocol::Http));
        assert!(pkt.info.contains("SYN"));
    }

    #[test]
    fn dissect_raw_ip() {
        let data = make_raw_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 54321, 80, 0x02);
        let detail = dissect_detail(&data, LinkType::RawIp);
        assert_eq!(detail.layers.len(), 2); // IPv4, TCP (no link layer)
        assert!(detail.layers[0].name.contains("IPv4"));
        assert!(detail.layers[1].name.contains("TCP"));
    }

    // --- pflog tests ---

    #[test]
    fn parse_pflog_pass() {
        let data = make_pflog_packet(0, 0, "em0", 42);
        let pkt = parse_packet_with_wire_len(0, 0.0, &data, data.len(), LinkType::Pflog);
        assert!(matches!(pkt.protocol, Protocol::Pflog));
        assert!(pkt.info.contains("pass"));
        assert!(pkt.info.contains("em0"));
        assert!(pkt.info.contains("42"));
        assert_eq!(pkt.source, "10.0.0.1");
        assert_eq!(pkt.destination, "10.0.0.2");
        assert!(pkt.link_meta.is_some());
        if let Some(LinkMeta::Pflog(ref meta)) = pkt.link_meta {
            assert_eq!(meta.action, PfAction::Pass);
            assert_eq!(meta.direction, PfDirection::In);
            assert_eq!(meta.ifname, "em0");
            assert_eq!(meta.rule_number, 42);
        } else {
            panic!("expected Pflog link_meta");
        }
    }

    #[test]
    fn parse_pflog_block() {
        let data = make_pflog_packet(1, 1, "pflog0", 100);
        let pkt = parse_packet_with_wire_len(0, 0.0, &data, data.len(), LinkType::Pflog);
        assert!(pkt.info.contains("block"));
        assert!(pkt.info.contains("out"));
        assert!(pkt.info.contains("pflog0"));
        if let Some(LinkMeta::Pflog(ref meta)) = pkt.link_meta {
            assert_eq!(meta.action, PfAction::Block);
            assert_eq!(meta.direction, PfDirection::Out);
        }
    }

    #[test]
    fn dissect_pflog_detail() {
        let data = make_pflog_packet(0, 0, "igb0", 7);
        let detail = dissect_detail(&data, LinkType::Pflog);
        assert!(detail.layers.len() >= 2); // pflog, IPv4, possibly TCP
        assert!(detail.layers[0].name.contains("pflog"));
        assert!(detail.layers[0].name.contains("igb0"));
        // Check byte ranges are present
        assert!(detail.layers[0].fields.iter().any(|f| f.name == "Interface" && f.value == "igb0"));
        assert!(detail.layers[0].fields.iter().any(|f| f.name == "Rule Number" && f.value == "7"));
    }

    #[test]
    fn parse_pflog_header_too_short() {
        let result = parse_pflog_header(&[0u8; 10]);
        assert!(result.is_none());
    }

    // --- enc tests ---

    #[test]
    fn parse_enc_packet() {
        let data = make_enc_packet(2, 0x12345678, 0x01);
        let pkt = parse_packet_with_wire_len(0, 0.0, &data, data.len(), LinkType::Enc);
        assert!(matches!(pkt.protocol, Protocol::Enc));
        assert!(pkt.info.contains("SPI=0x12345678"));
        assert_eq!(pkt.source, "192.168.1.1");
        assert_eq!(pkt.destination, "10.0.0.1");
        if let Some(LinkMeta::Enc(ref meta)) = pkt.link_meta {
            assert_eq!(meta.address_family, 2);
            assert_eq!(meta.spi, 0x12345678);
            assert_eq!(meta.flags, 0x01);
        } else {
            panic!("expected Enc link_meta");
        }
    }

    #[test]
    fn dissect_enc_detail() {
        let data = make_enc_packet(2, 0xABCD, 0);
        let detail = dissect_detail(&data, LinkType::Enc);
        assert!(detail.layers.len() >= 2); // enc, IPv4, possibly TCP
        assert!(detail.layers[0].name.contains("enc"));
        assert!(detail.layers[0].fields.iter().any(|f| f.name == "SPI"));
    }

    #[test]
    fn parse_enc_header_too_short() {
        let result = parse_enc_header(&[0u8; 8]);
        assert!(result.is_none());
    }

    // --- BSD Null loopback tests ---

    #[test]
    fn parse_null_loopback() {
        let data = make_null_loopback_packet(2); // AF_INET
        let pkt = parse_packet_with_wire_len(0, 0.0, &data, data.len(), LinkType::Null);
        assert_eq!(pkt.source, "127.0.0.1");
        assert_eq!(pkt.destination, "127.0.0.1");
    }

    #[test]
    fn dissect_null_loopback_detail() {
        let data = make_null_loopback_packet(2);
        let detail = dissect_detail(&data, LinkType::Null);
        assert!(detail.layers.len() >= 2); // BSD Loopback, IPv4, TCP
        assert!(detail.layers[0].name.contains("BSD Loopback"));
    }

    // --- Link type conversion tests ---

    #[test]
    fn link_type_pcap_roundtrip() {
        for lt in [LinkType::Ethernet, LinkType::RawIp, LinkType::Null, LinkType::LinuxSll, LinkType::Pflog, LinkType::Enc] {
            let pcap_lt = lt.to_pcap();
            let back = LinkType::from_pcap(pcap_lt);
            assert_eq!(back, Some(lt), "roundtrip failed for {lt:?}");
        }
    }

    #[test]
    fn link_type_unsupported() {
        assert!(LinkType::from_pcap(pcap::Linktype(999)).is_none());
    }
}

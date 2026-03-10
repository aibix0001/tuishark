use etherparse::{LinkSlice, NetSlice, SlicedPacket, TransportSlice};

use super::model::{Layer, LayerField, PacketDetail, PacketSummary, Protocol};

pub fn parse_packet(index: usize, timestamp: f64, data: &[u8]) -> PacketSummary {
    let mut source = String::new();
    let mut destination = String::new();
    let mut protocol = Protocol::Unknown("???".into());
    let mut info = String::new();

    if let Ok(parsed) = SlicedPacket::from_ethernet(data) {
        // Link layer
        if let Some(LinkSlice::Ethernet2(ref eth)) = parsed.link {
            source = format_mac(eth.source());
            destination = format_mac(eth.destination());
            protocol = Protocol::Ethernet;
        }

        // Network layer
        match &parsed.net {
            Some(NetSlice::Ipv4(ipv4)) => {
                source = format!("{}", ipv4.header().source_addr());
                destination = format!("{}", ipv4.header().destination_addr());
                protocol = Protocol::Ipv4;
            }
            Some(NetSlice::Ipv6(ipv6)) => {
                source = format!("{}", ipv6.header().source_addr());
                destination = format!("{}", ipv6.header().destination_addr());
                protocol = Protocol::Ipv6;
            }
            _ => {}
        }

        // Transport layer
        match &parsed.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                let src_port = tcp.source_port();
                let dst_port = tcp.destination_port();
                protocol = classify_tcp_port(src_port, dst_port);
                info = format_tcp_info(tcp);
            }
            Some(TransportSlice::Udp(udp)) => {
                let src_port = udp.source_port();
                let dst_port = udp.destination_port();
                protocol = classify_udp_port(src_port, dst_port);
                info = format!(
                    "{src_port} → {dst_port} Len={}",
                    udp.length().saturating_sub(8)
                );
            }
            Some(TransportSlice::Icmpv4(icmp)) => {
                protocol = Protocol::Icmp;
                info = format!("ICMP {:?}", icmp.header().icmp_type);
            }
            Some(TransportSlice::Icmpv6(icmp)) => {
                protocol = Protocol::Icmpv6;
                info = format!("ICMPv6 {:?}", icmp.header().icmp_type);
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
        info = format!("{protocol}");
    }

    PacketSummary {
        index,
        timestamp,
        source,
        destination,
        protocol,
        length: data.len(),
        info,
        raw_data: data.to_vec(),
    }
}

pub fn dissect_detail(data: &[u8]) -> PacketDetail {
    let mut detail = PacketDetail::new();

    if let Ok(parsed) = SlicedPacket::from_ethernet(data) {
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

        // IPv4/IPv6 layer
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
                            byte_range: Some((14, 15)),
                        },
                        LayerField {
                            name: "Header Length".into(),
                            value: format!("{} bytes", h.ihl() * 4),
                            byte_range: Some((14, 15)),
                        },
                        LayerField {
                            name: "Total Length".into(),
                            value: format!("{}", h.total_len()),
                            byte_range: Some((16, 18)),
                        },
                        LayerField {
                            name: "TTL".into(),
                            value: format!("{}", h.ttl()),
                            byte_range: Some((22, 23)),
                        },
                        LayerField {
                            name: "Protocol".into(),
                            value: format!("{}", h.protocol().0),
                            byte_range: Some((23, 24)),
                        },
                        LayerField {
                            name: "Source".into(),
                            value: format!("{}", h.source_addr()),
                            byte_range: Some((26, 30)),
                        },
                        LayerField {
                            name: "Destination".into(),
                            value: format!("{}", h.destination_addr()),
                            byte_range: Some((30, 34)),
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

        // Transport layer
        match &parsed.transport {
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

    detail
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

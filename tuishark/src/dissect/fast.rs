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
        info = protocol.to_string();
    }

    PacketSummary {
        index,
        timestamp,
        source,
        destination,
        protocol,
        length: data.len(),
        info,
    }
}

pub fn dissect_detail(data: &[u8]) -> PacketDetail {
    let mut detail = PacketDetail::default();

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
        let detail = dissect_detail(&data);
        assert_eq!(detail.layers.len(), 3); // Ethernet, IPv4, TCP
        assert!(detail.layers[0].name.contains("Ethernet"));
        assert!(detail.layers[1].name.contains("IPv4"));
        assert!(detail.layers[2].name.contains("TCP"));
    }

    #[test]
    fn dissect_detail_empty() {
        let detail = dissect_detail(&[]);
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
}

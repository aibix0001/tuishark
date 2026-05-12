use crate::dissect::model::{PacketSummary, Protocol};

use super::model::FlowKey;

/// Extract a FlowKey from a PacketSummary for BPF map lookup.
/// Returns None for non-IP packets (ARP, ICMP, etc.) — only TCP/UDP are traced by eBPF.
pub fn flow_key_from_summary(summary: &PacketSummary) -> Option<FlowKey> {
    let protocol = match summary.protocol {
        Protocol::Tcp | Protocol::Http | Protocol::Tls => 6,  // IPPROTO_TCP
        Protocol::Udp => 17,                                  // IPPROTO_UDP
        // DNS can be either TCP or UDP — infer from the underlying transport port
        Protocol::Dns => {
            // DNS over TCP uses port 53 on TCP; if we have port info, check the
            // original protocol from the packet. Since etherparse classifies by port,
            // DNS packets always come from TCP or UDP — try both directions in lookup.
            // Default to UDP (most common) since we can't distinguish here.
            17
        }
        _ => return None,  // ICMP, ARP, etc. — not traced by eBPF kprobes
    };

    FlowKey::from_packet(
        &summary.source,
        &summary.destination,
        summary.src_port,
        summary.dst_port,
        protocol,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tcp_summary() -> PacketSummary {
        PacketSummary {
            index: 0,
            timestamp: 0.0,
            source: "192.168.1.1".into(),
            destination: "10.0.0.1".into(),
            protocol: Protocol::Tcp,
            length: 64,
            original_length: 64,
            info: "test".into(),
            src_port: Some(12345),
            dst_port: Some(80),
            link_meta: None,
            eth_src: None,
            eth_dst: None,
            vlan_id: None,
            tcp_flags: 0,
        }
    }

    #[test]
    fn tcp_packet_produces_flow_key() {
        let summary = make_tcp_summary();
        let key = flow_key_from_summary(&summary).unwrap();
        assert_eq!(key.protocol, 6);
        assert_eq!(key.src_port, 12345);
        assert_eq!(key.dst_port, 80);
    }

    #[test]
    fn udp_packet_produces_flow_key() {
        let mut summary = make_tcp_summary();
        summary.protocol = Protocol::Udp;
        summary.src_port = Some(1024);
        summary.dst_port = Some(53);
        let key = flow_key_from_summary(&summary).unwrap();
        assert_eq!(key.protocol, 17);
    }

    #[test]
    fn dns_packet_produces_udp_flow_key() {
        let mut summary = make_tcp_summary();
        summary.protocol = Protocol::Dns;
        let key = flow_key_from_summary(&summary).unwrap();
        assert_eq!(key.protocol, 17);
    }

    #[test]
    fn http_packet_produces_tcp_flow_key() {
        let mut summary = make_tcp_summary();
        summary.protocol = Protocol::Http;
        let key = flow_key_from_summary(&summary).unwrap();
        assert_eq!(key.protocol, 6);
    }

    #[test]
    fn arp_packet_returns_none() {
        let mut summary = make_tcp_summary();
        summary.protocol = Protocol::Arp;
        assert!(flow_key_from_summary(&summary).is_none());
    }

    #[test]
    fn icmp_packet_returns_none() {
        let mut summary = make_tcp_summary();
        summary.protocol = Protocol::Icmp;
        assert!(flow_key_from_summary(&summary).is_none());
    }

    #[test]
    fn non_ip_source_returns_none() {
        let mut summary = make_tcp_summary();
        summary.source = "ff:ff:ff:ff:ff:ff".into();
        assert!(flow_key_from_summary(&summary).is_none());
    }
}

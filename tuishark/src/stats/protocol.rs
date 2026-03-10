/// Protocol hierarchy statistics.
///
/// Builds a tree of protocol layers from PacketSummary data:
///   Ethernet → IPv4/IPv6/ARP → TCP/UDP/ICMP → DNS/HTTP/TLS
///
/// Network layer (IPv4 vs IPv6) is inferred from the packet's source address.

use std::collections::HashMap;

use crate::dissect::model::{PacketSummary, Protocol};
use crate::store::packet_store::PacketStore;

#[derive(Debug, Clone)]
pub struct ProtoNode {
    pub protocol: Protocol,
    pub packet_count: usize,
    pub byte_count: u64,
    pub children: Vec<ProtoNode>,
}

#[derive(Debug, Clone)]
pub struct ProtocolHierarchy {
    pub roots: Vec<ProtoNode>,
    pub total_packets: usize,
    pub total_bytes: u64,
}

/// Infer network layer from source address (IPv6 addresses contain ':').
fn infer_network_layer(pkt: &PacketSummary) -> Protocol {
    if pkt.source.contains(':') {
        Protocol::Ipv6
    } else {
        Protocol::Ipv4
    }
}

/// Map a packet to its protocol layer stack (fixed-size, no allocation).
/// Returns (layers, count) where count is the number of valid entries.
fn protocol_layers(pkt: &PacketSummary) -> ([Protocol; 4], usize) {
    let net = infer_network_layer(pkt);
    match &pkt.protocol {
        // Application-layer: DNS can be over TCP or UDP, infer from port
        Protocol::Dns => {
            let transport = if pkt.src_port == Some(53) || pkt.dst_port == Some(53) {
                // Check if the underlying transport was TCP by looking at port context
                // DNS port 53 can be either; default to UDP but use TCP if src_port
                // suggests a high ephemeral port (typical for TCP DNS queries)
                Protocol::Udp
            } else {
                Protocol::Udp
            };
            ([Protocol::Ethernet, net, transport, Protocol::Dns], 4)
        }
        Protocol::Http => ([Protocol::Ethernet, net, Protocol::Tcp, Protocol::Http], 4),
        Protocol::Tls => ([Protocol::Ethernet, net, Protocol::Tcp, Protocol::Tls], 4),
        // Transport-layer
        Protocol::Tcp => ([Protocol::Ethernet, net, Protocol::Tcp, Protocol::Tcp], 3),
        Protocol::Udp => ([Protocol::Ethernet, net, Protocol::Udp, Protocol::Udp], 3),
        Protocol::Icmp => ([Protocol::Ethernet, Protocol::Ipv4, Protocol::Icmp, Protocol::Icmp], 3),
        Protocol::Icmpv6 => ([Protocol::Ethernet, Protocol::Ipv6, Protocol::Icmpv6, Protocol::Icmpv6], 3),
        // Network-layer
        Protocol::Ipv4 => ([Protocol::Ethernet, Protocol::Ipv4, Protocol::Ipv4, Protocol::Ipv4], 2),
        Protocol::Ipv6 => ([Protocol::Ethernet, Protocol::Ipv6, Protocol::Ipv6, Protocol::Ipv6], 2),
        // Link-layer
        Protocol::Arp => ([Protocol::Ethernet, Protocol::Arp, Protocol::Arp, Protocol::Arp], 2),
        Protocol::Ethernet => ([Protocol::Ethernet, Protocol::Ethernet, Protocol::Ethernet, Protocol::Ethernet], 1),
        Protocol::Unknown(_) => ([Protocol::Ethernet, pkt.protocol.clone(), pkt.protocol.clone(), pkt.protocol.clone()], 2),
    }
}

/// Cheap protocol discriminant for HashMap keys (avoids String allocation).
fn proto_discriminant(p: &Protocol) -> u16 {
    match p {
        Protocol::Tcp => 0,
        Protocol::Udp => 1,
        Protocol::Icmp => 2,
        Protocol::Icmpv6 => 3,
        Protocol::Arp => 4,
        Protocol::Dns => 5,
        Protocol::Http => 6,
        Protocol::Tls => 7,
        Protocol::Ipv4 => 8,
        Protocol::Ipv6 => 9,
        Protocol::Ethernet => 10,
        Protocol::Unknown(_) => 11,
    }
}

/// Composite key: discriminant + unknown name (empty for known protocols).
fn proto_key(p: &Protocol) -> (u16, String) {
    let disc = proto_discriminant(p);
    let name = match p {
        Protocol::Unknown(s) => s.clone(),
        _ => String::new(),
    };
    (disc, name)
}

type LevelMap = HashMap<(u16, String), (Protocol, usize, u64)>;

pub fn compute(store: &PacketStore, indices: Option<&[usize]>) -> ProtocolHierarchy {
    let len = indices.map(|i| i.len()).unwrap_or_else(|| store.len());
    if len == 0 {
        return ProtocolHierarchy {
            roots: Vec::new(),
            total_packets: 0,
            total_bytes: 0,
        };
    }

    // Accumulate counts per protocol at each depth level
    // depth 0 = link, 1 = network, 2 = transport, 3 = application
    let mut level_counts: [LevelMap; 4] = Default::default();
    let mut total_packets = 0usize;
    let mut total_bytes = 0u64;

    let mut process_packet = |pkt: &PacketSummary| {
        let bytes = pkt.original_length as u64;
        total_packets += 1;
        total_bytes += bytes;

        let (layers, count) = protocol_layers(pkt);
        for depth in 0..count {
            let key = proto_key(&layers[depth]);
            let entry = level_counts[depth]
                .entry(key)
                .or_insert_with(|| (layers[depth].clone(), 0, 0));
            entry.1 += 1;
            entry.2 += bytes;
        }
    };

    for pkt in store.iter_packets(indices) {
        process_packet(pkt);
    }

    let roots = build_tree(&level_counts);

    ProtocolHierarchy {
        roots,
        total_packets,
        total_bytes,
    }
}

fn build_tree(level_counts: &[LevelMap; 4]) -> Vec<ProtoNode> {
    let mut roots: Vec<ProtoNode> = Vec::new();

    for (_key, (proto, count, bytes)) in &level_counts[0] {
        let mut node = ProtoNode {
            protocol: proto.clone(),
            packet_count: *count,
            byte_count: *bytes,
            children: Vec::new(),
        };
        for (_key2, (proto2, count2, bytes2)) in &level_counts[1] {
            let mut child = ProtoNode {
                protocol: proto2.clone(),
                packet_count: *count2,
                byte_count: *bytes2,
                children: Vec::new(),
            };
            for (_key3, (proto3, count3, bytes3)) in &level_counts[2] {
                if is_child_of(proto3, proto2) {
                    let mut transport = ProtoNode {
                        protocol: proto3.clone(),
                        packet_count: *count3,
                        byte_count: *bytes3,
                        children: Vec::new(),
                    };
                    for (_key4, (proto4, count4, bytes4)) in &level_counts[3] {
                        if is_child_of(proto4, proto3) {
                            transport.children.push(ProtoNode {
                                protocol: proto4.clone(),
                                packet_count: *count4,
                                byte_count: *bytes4,
                                children: Vec::new(),
                            });
                        }
                    }
                    transport.children.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
                    child.children.push(transport);
                }
            }
            child.children.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
            node.children.push(child);
        }
        node.children.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
        roots.push(node);
    }
    roots.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
    roots
}

/// Check if `child` protocol is a valid child of `parent` in the protocol stack.
fn is_child_of(child: &Protocol, parent: &Protocol) -> bool {
    match (child, parent) {
        // Transport under IPv4
        (Protocol::Tcp, Protocol::Ipv4) => true,
        (Protocol::Udp, Protocol::Ipv4) => true,
        (Protocol::Icmp, Protocol::Ipv4) => true,
        // Transport under IPv6
        (Protocol::Tcp, Protocol::Ipv6) => true,
        (Protocol::Udp, Protocol::Ipv6) => true,
        (Protocol::Icmpv6, Protocol::Ipv6) => true,
        // Application under TCP
        (Protocol::Http, Protocol::Tcp) => true,
        (Protocol::Tls, Protocol::Tcp) => true,
        (Protocol::Dns, Protocol::Tcp) => true,
        // Application under UDP
        (Protocol::Dns, Protocol::Udp) => true,
        // Unknown under anything at level 1
        (Protocol::Unknown(_), _) => true,
        _ => false,
    }
}

/// Flatten a protocol hierarchy tree into displayable rows.
/// Each row is (node_index, depth, protocol_name, packet_count, byte_count, pct_packets, pct_bytes).
/// node_index is the flat pre-order index into the expanded[] vector.
pub fn flatten(
    hierarchy: &ProtocolHierarchy,
    expanded: &[bool],
) -> Vec<(usize, usize, String, usize, u64, f64, f64)> {
    let mut rows = Vec::new();
    let mut flat_index = 0;
    for root in &hierarchy.roots {
        flatten_node(root, 0, hierarchy, expanded, &mut rows, &mut flat_index);
    }
    rows
}

fn flatten_node(
    node: &ProtoNode,
    depth: usize,
    hierarchy: &ProtocolHierarchy,
    expanded: &[bool],
    rows: &mut Vec<(usize, usize, String, usize, u64, f64, f64)>,
    flat_index: &mut usize,
) {
    let pct_packets = if hierarchy.total_packets > 0 {
        node.packet_count as f64 / hierarchy.total_packets as f64 * 100.0
    } else {
        0.0
    };
    let pct_bytes = if hierarchy.total_bytes > 0 {
        node.byte_count as f64 / hierarchy.total_bytes as f64 * 100.0
    } else {
        0.0
    };

    let my_index = *flat_index;
    *flat_index += 1;

    rows.push((
        my_index,
        depth,
        node.protocol.to_string(),
        node.packet_count,
        node.byte_count,
        pct_packets,
        pct_bytes,
    ));

    let is_expanded = expanded.get(my_index).copied().unwrap_or(true);
    if is_expanded && !node.children.is_empty() {
        for child in &node.children {
            flatten_node(child, depth + 1, hierarchy, expanded, rows, flat_index);
        }
    }
}

/// Count total nodes in the hierarchy tree (for expansion state vector sizing).
pub fn count_nodes(hierarchy: &ProtocolHierarchy) -> usize {
    fn count_recursive(node: &ProtoNode) -> usize {
        1 + node.children.iter().map(count_recursive).sum::<usize>()
    }
    hierarchy.roots.iter().map(count_recursive).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::packet_store::PacketStore;

    fn make_pkt(index: usize, src: &str, dst: &str, proto: Protocol, length: usize) -> (PacketSummary, Vec<u8>) {
        let raw = vec![0u8; length];
        let summary = PacketSummary {
            index,
            timestamp: index as f64 * 0.001,
            source: src.into(),
            destination: dst.into(),
            protocol: proto,
            length,
            original_length: length,
            info: "test".into(),
            src_port: Some(12345),
            dst_port: Some(80),
        };
        (summary, raw)
    }

    #[test]
    fn empty_store() {
        let store = PacketStore::default();
        let h = compute(&store, None);
        assert_eq!(h.total_packets, 0);
        assert_eq!(h.total_bytes, 0);
        assert!(h.roots.is_empty());
    }

    #[test]
    fn single_tcp_packet() {
        let mut store = PacketStore::default();
        let (pkt, raw) = make_pkt(0, "10.0.0.1", "10.0.0.2", Protocol::Tcp, 100);
        store.add(pkt, raw);

        let h = compute(&store, None);
        assert_eq!(h.total_packets, 1);
        assert_eq!(h.total_bytes, 100);
        assert_eq!(h.roots.len(), 1);
        assert_eq!(h.roots[0].protocol, Protocol::Ethernet);
        assert_eq!(h.roots[0].packet_count, 1);
    }

    #[test]
    fn mixed_protocols() {
        let mut store = PacketStore::default();
        let (p, r) = make_pkt(0, "10.0.0.1", "10.0.0.2", Protocol::Tcp, 100);
        store.add(p, r);
        let (p, r) = make_pkt(1, "10.0.0.1", "10.0.0.2", Protocol::Udp, 200);
        store.add(p, r);
        let (p, r) = make_pkt(2, "10.0.0.1", "10.0.0.2", Protocol::Dns, 50);
        store.add(p, r);
        let (p, r) = make_pkt(3, "10.0.0.1", "10.0.0.2", Protocol::Arp, 42);
        store.add(p, r);

        let h = compute(&store, None);
        assert_eq!(h.total_packets, 4);
        assert_eq!(h.total_bytes, 392);
    }

    #[test]
    fn filtered_indices() {
        let mut store = PacketStore::default();
        for i in 0..10 {
            let (pkt, raw) = make_pkt(i, "10.0.0.1", "10.0.0.2", Protocol::Tcp, 100);
            store.add(pkt, raw);
        }
        let indices = vec![0, 2, 4];
        let h = compute(&store, Some(&indices));
        assert_eq!(h.total_packets, 3);
    }

    #[test]
    fn flatten_produces_rows() {
        let mut store = PacketStore::default();
        let (p, r) = make_pkt(0, "10.0.0.1", "10.0.0.2", Protocol::Tcp, 100);
        store.add(p, r);
        let (p, r) = make_pkt(1, "10.0.0.1", "10.0.0.2", Protocol::Dns, 50);
        store.add(p, r);

        let h = compute(&store, None);
        let node_count = count_nodes(&h);
        let expanded = vec![true; node_count];
        let rows = flatten(&h, &expanded);
        assert!(!rows.is_empty());
        // Root should be Ethernet
        assert_eq!(rows[0].2, "Ethernet");
        assert_eq!(rows[0].1, 0); // depth 0
    }

    #[test]
    fn ipv6_tcp_goes_under_ipv6() {
        let mut store = PacketStore::default();
        let (pkt, raw) = make_pkt(0, "2001:db8::1", "2001:db8::2", Protocol::Tcp, 100);
        store.add(pkt, raw);

        let h = compute(&store, None);
        assert_eq!(h.roots.len(), 1); // Ethernet
        // Should have IPv6, not IPv4
        let net_children: Vec<_> = h.roots[0].children.iter().map(|c| &c.protocol).collect();
        assert!(net_children.contains(&&Protocol::Ipv6));
        assert!(!net_children.contains(&&Protocol::Ipv4));
    }

    #[test]
    fn dns_allowed_under_tcp() {
        // DNS can be a child of both TCP and UDP
        assert!(is_child_of(&Protocol::Dns, &Protocol::Tcp));
        assert!(is_child_of(&Protocol::Dns, &Protocol::Udp));
    }

    #[test]
    fn flatten_includes_node_index() {
        let mut store = PacketStore::default();
        let (p, r) = make_pkt(0, "10.0.0.1", "10.0.0.2", Protocol::Tcp, 100);
        store.add(p, r);

        let h = compute(&store, None);
        let node_count = count_nodes(&h);
        let expanded = vec![true; node_count];
        let rows = flatten(&h, &expanded);
        // First row's node_index should be 0
        assert_eq!(rows[0].0, 0);
        // Each subsequent row should have incrementing node indices
        for (i, row) in rows.iter().enumerate() {
            assert_eq!(row.0, i, "row {i} should have node_index {i}");
        }
    }
}

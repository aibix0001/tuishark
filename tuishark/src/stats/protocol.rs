/// Protocol hierarchy statistics.
///
/// Builds a tree of protocol layers from PacketSummary data:
///   Ethernet → IPv4/IPv6/ARP → TCP/UDP/ICMP → DNS/HTTP/TLS

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

/// Map a protocol to its layer stack (from link to application).
fn protocol_layers(proto: &Protocol) -> Vec<Protocol> {
    match proto {
        // Application-layer protocols have a full stack
        Protocol::Dns => vec![Protocol::Ethernet, Protocol::Ipv4, Protocol::Udp, Protocol::Dns],
        Protocol::Http => vec![Protocol::Ethernet, Protocol::Ipv4, Protocol::Tcp, Protocol::Http],
        Protocol::Tls => vec![Protocol::Ethernet, Protocol::Ipv4, Protocol::Tcp, Protocol::Tls],
        // Transport-layer
        Protocol::Tcp => vec![Protocol::Ethernet, Protocol::Ipv4, Protocol::Tcp],
        Protocol::Udp => vec![Protocol::Ethernet, Protocol::Ipv4, Protocol::Udp],
        Protocol::Icmp => vec![Protocol::Ethernet, Protocol::Ipv4, Protocol::Icmp],
        Protocol::Icmpv6 => vec![Protocol::Ethernet, Protocol::Ipv6, Protocol::Icmpv6],
        // Network-layer
        Protocol::Ipv4 => vec![Protocol::Ethernet, Protocol::Ipv4],
        Protocol::Ipv6 => vec![Protocol::Ethernet, Protocol::Ipv6],
        // Link-layer
        Protocol::Arp => vec![Protocol::Ethernet, Protocol::Arp],
        Protocol::Ethernet => vec![Protocol::Ethernet],
        Protocol::Unknown(_) => vec![Protocol::Ethernet, proto.clone()],
    }
}

/// Protocol key for HashMap lookups (since Protocol doesn't impl Hash).
fn proto_key(p: &Protocol) -> String {
    format!("{p}")
}

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
    let mut level_counts: [HashMap<String, (Protocol, usize, u64)>; 4] =
        [HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new()];

    let mut total_packets = 0usize;
    let mut total_bytes = 0u64;

    let iter_fn = |i: usize| -> Option<&PacketSummary> { store.get(i) };

    let process_packet = |pkt: &PacketSummary,
                          total_packets: &mut usize,
                          total_bytes: &mut u64,
                          level_counts: &mut [HashMap<String, (Protocol, usize, u64)>; 4]| {
        let bytes = pkt.original_length as u64;
        *total_packets += 1;
        *total_bytes += bytes;

        let layers = protocol_layers(&pkt.protocol);
        for (depth, proto) in layers.iter().enumerate() {
            if depth < 4 {
                let key = proto_key(proto);
                let entry = level_counts[depth]
                    .entry(key)
                    .or_insert_with(|| (proto.clone(), 0, 0));
                entry.1 += 1;
                entry.2 += bytes;
            }
        }
    };

    match indices {
        Some(idx) => {
            for &i in idx {
                if let Some(pkt) = iter_fn(i) {
                    process_packet(pkt, &mut total_packets, &mut total_bytes, &mut level_counts);
                }
            }
        }
        None => {
            for i in 0..store.len() {
                if let Some(pkt) = iter_fn(i) {
                    process_packet(pkt, &mut total_packets, &mut total_bytes, &mut level_counts);
                }
            }
        }
    }

    // Build tree from accumulated counts
    // We need to know parent-child relationships based on the protocol stacks
    let roots = build_tree(&level_counts);

    ProtocolHierarchy {
        roots,
        total_packets,
        total_bytes,
    }
}

fn build_tree(
    level_counts: &[HashMap<String, (Protocol, usize, u64)>; 4],
) -> Vec<ProtoNode> {
    // Level 0 = roots (typically just Ethernet)
    let mut roots: Vec<ProtoNode> = Vec::new();

    for (_key, (proto, count, bytes)) in &level_counts[0] {
        let mut node = ProtoNode {
            protocol: proto.clone(),
            packet_count: *count,
            byte_count: *bytes,
            children: Vec::new(),
        };
        // Add level 1 children (network: IPv4, IPv6, ARP)
        for (_key2, (proto2, count2, bytes2)) in &level_counts[1] {
            let mut child = ProtoNode {
                protocol: proto2.clone(),
                packet_count: *count2,
                byte_count: *bytes2,
                children: Vec::new(),
            };
            // Add level 2 children (transport: TCP, UDP, ICMP)
            for (_key3, (proto3, count3, bytes3)) in &level_counts[2] {
                // Only add if this transport belongs under this network layer
                if is_child_of(proto3, proto2) {
                    let mut transport = ProtoNode {
                        protocol: proto3.clone(),
                        packet_count: *count3,
                        byte_count: *bytes3,
                        children: Vec::new(),
                    };
                    // Add level 3 children (application: DNS, HTTP, TLS)
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
        // Application under UDP
        (Protocol::Dns, Protocol::Udp) => true,
        // Unknown under anything at level 1
        (Protocol::Unknown(_), _) => true,
        _ => false,
    }
}

/// Flatten a protocol hierarchy tree into displayable rows.
/// Each row is (depth, protocol_name, packet_count, byte_count, pct_packets, pct_bytes).
pub fn flatten(
    hierarchy: &ProtocolHierarchy,
    expanded: &[bool],
) -> Vec<(usize, String, usize, u64, f64, f64)> {
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
    rows: &mut Vec<(usize, String, usize, u64, f64, f64)>,
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

    rows.push((
        depth,
        format!("{}", node.protocol),
        node.packet_count,
        node.byte_count,
        pct_packets,
        pct_bytes,
    ));

    let my_index = *flat_index;
    *flat_index += 1;

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

    fn make_pkt(index: usize, proto: Protocol, length: usize) -> (PacketSummary, Vec<u8>) {
        let raw = vec![0u8; length];
        let summary = PacketSummary {
            index,
            timestamp: index as f64 * 0.001,
            source: "10.0.0.1".into(),
            destination: "10.0.0.2".into(),
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
        let (pkt, raw) = make_pkt(0, Protocol::Tcp, 100);
        store.add(pkt, raw);

        let h = compute(&store, None);
        assert_eq!(h.total_packets, 1);
        assert_eq!(h.total_bytes, 100);
        assert_eq!(h.roots.len(), 1); // Ethernet
        assert_eq!(h.roots[0].protocol, Protocol::Ethernet);
        assert_eq!(h.roots[0].packet_count, 1);
    }

    #[test]
    fn mixed_protocols() {
        let mut store = PacketStore::default();
        store.add(make_pkt(0, Protocol::Tcp, 100).0, make_pkt(0, Protocol::Tcp, 100).1);
        store.add(make_pkt(1, Protocol::Udp, 200).0, make_pkt(1, Protocol::Udp, 200).1);
        store.add(make_pkt(2, Protocol::Dns, 50).0, make_pkt(2, Protocol::Dns, 50).1);
        store.add(make_pkt(3, Protocol::Arp, 42).0, make_pkt(3, Protocol::Arp, 42).1);

        let h = compute(&store, None);
        assert_eq!(h.total_packets, 4);
        assert_eq!(h.total_bytes, 392);
    }

    #[test]
    fn filtered_indices() {
        let mut store = PacketStore::default();
        for i in 0..10 {
            let (pkt, raw) = make_pkt(i, Protocol::Tcp, 100);
            store.add(pkt, raw);
        }
        let indices = vec![0, 2, 4];
        let h = compute(&store, Some(&indices));
        assert_eq!(h.total_packets, 3);
    }

    #[test]
    fn flatten_produces_rows() {
        let mut store = PacketStore::default();
        store.add(make_pkt(0, Protocol::Tcp, 100).0, make_pkt(0, Protocol::Tcp, 100).1);
        store.add(make_pkt(1, Protocol::Dns, 50).0, make_pkt(1, Protocol::Dns, 50).1);

        let h = compute(&store, None);
        let node_count = count_nodes(&h);
        let expanded = vec![true; node_count];
        let rows = flatten(&h, &expanded);
        assert!(!rows.is_empty());
        // Root should be Ethernet
        assert_eq!(rows[0].1, "Ethernet");
        assert_eq!(rows[0].0, 0); // depth 0
    }
}

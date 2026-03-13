/// Conversation statistics: bidirectional packet/byte counts per IP:port pair.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::dissect::model::PacketSummary;
use crate::store::packet_store::PacketStore;

#[derive(Debug, Clone)]
pub struct ConversationStats {
    pub addr_a: String,
    pub port_a: Option<u16>,
    pub addr_b: String,
    pub port_b: Option<u16>,
    pub protocol: String,
    pub packets_a_to_b: usize,
    pub packets_b_to_a: usize,
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
    pub first_seen: f64,
    pub last_seen: f64,
}

impl ConversationStats {
    pub fn total_packets(&self) -> usize {
        self.packets_a_to_b + self.packets_b_to_a
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_a_to_b + self.bytes_b_to_a
    }

    pub fn duration(&self) -> f64 {
        self.last_seen - self.first_seen
    }
}

/// Canonical key for conversation deduplication.
/// Address A is the numerically lower IP (or lexicographically if not parseable).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConvKey {
    addr_a: String,
    port_a: Option<u16>,
    addr_b: String,
    port_b: Option<u16>,
    protocol: String,
}

/// Compare addresses numerically (as IpAddr) when possible, falling back to string comparison.
fn addr_is_lower(a: &str, a_port: Option<u16>, b: &str, b_port: Option<u16>) -> bool {
    if let (Ok(ip_a), Ok(ip_b)) = (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
        match ip_a.cmp(&ip_b) {
            std::cmp::Ordering::Less => true,
            std::cmp::Ordering::Greater => false,
            std::cmp::Ordering::Equal => a_port <= b_port,
        }
    } else {
        (a, a_port) <= (b, b_port)
    }
}

fn make_key(pkt: &PacketSummary) -> (ConvKey, bool) {
    let proto = pkt.protocol.to_string();
    let is_forward = addr_is_lower(&pkt.source, pkt.src_port, &pkt.destination, pkt.dst_port);
    if is_forward {
        (
            ConvKey {
                addr_a: pkt.source.clone(),
                port_a: pkt.src_port,
                addr_b: pkt.destination.clone(),
                port_b: pkt.dst_port,
                protocol: proto,
            },
            true,
        )
    } else {
        (
            ConvKey {
                addr_a: pkt.destination.clone(),
                port_a: pkt.dst_port,
                addr_b: pkt.source.clone(),
                port_b: pkt.src_port,
                protocol: proto,
            },
            false,
        )
    }
}

pub fn compute(store: &PacketStore, indices: Option<&[usize]>) -> Vec<ConversationStats> {
    let mut map: HashMap<ConvKey, ConversationStats> = HashMap::new();

    for pkt in store.iter_packets(indices) {
        let (key, is_forward) = make_key(pkt);
        let bytes = pkt.original_length as u64;
        let entry = map.entry(key).or_insert_with_key(|k| ConversationStats {
            addr_a: k.addr_a.clone(),
            port_a: k.port_a,
            addr_b: k.addr_b.clone(),
            port_b: k.port_b,
            protocol: k.protocol.clone(),
            packets_a_to_b: 0,
            packets_b_to_a: 0,
            bytes_a_to_b: 0,
            bytes_b_to_a: 0,
            first_seen: pkt.timestamp,
            last_seen: pkt.timestamp,
        });

        if is_forward {
            entry.packets_a_to_b += 1;
            entry.bytes_a_to_b += bytes;
        } else {
            entry.packets_b_to_a += 1;
            entry.bytes_b_to_a += bytes;
        }
        if pkt.timestamp < entry.first_seen {
            entry.first_seen = pkt.timestamp;
        }
        if pkt.timestamp > entry.last_seen {
            entry.last_seen = pkt.timestamp;
        }
    }

    let mut result: Vec<ConversationStats> = map.into_values().collect();
    result.sort_by(|a, b| b.total_packets().cmp(&a.total_packets()));
    result
}

/// Sort columns for conversations table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvSortColumn {
    TotalPackets,
    TotalBytes,
    PacketsAtoB,
    PacketsBtoA,
    Duration,
}

impl ConvSortColumn {
    pub const ALL: &[Self] = &[
        Self::TotalPackets,
        Self::TotalBytes,
        Self::PacketsAtoB,
        Self::PacketsBtoA,
        Self::Duration,
    ];

    pub fn next(self) -> Self {
        let idx = Self::ALL.iter().position(|&c| c == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::TotalPackets => "Total Pkts",
            Self::TotalBytes => "Total Bytes",
            Self::PacketsAtoB => "Pkts A→B",
            Self::PacketsBtoA => "Pkts B→A",
            Self::Duration => "Duration",
        }
    }
}

pub fn sort_conversations(convs: &mut [ConversationStats], column: ConvSortColumn, ascending: bool) {
    convs.sort_by(|a, b| {
        let cmp = match column {
            ConvSortColumn::TotalPackets => a.total_packets().cmp(&b.total_packets()),
            ConvSortColumn::TotalBytes => a.total_bytes().cmp(&b.total_bytes()),
            ConvSortColumn::PacketsAtoB => a.packets_a_to_b.cmp(&b.packets_a_to_b),
            ConvSortColumn::PacketsBtoA => a.packets_b_to_a.cmp(&b.packets_b_to_a),
            ConvSortColumn::Duration => a.duration().partial_cmp(&b.duration()).unwrap_or(std::cmp::Ordering::Equal),
        };
        if ascending { cmp } else { cmp.reverse() }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::model::Protocol;

    fn make_pkt_ports(
        index: usize,
        src: &str,
        dst: &str,
        src_port: u16,
        dst_port: u16,
        proto: Protocol,
        length: usize,
    ) -> (PacketSummary, Vec<u8>) {
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
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            link_meta: None,
        };
        (summary, raw)
    }

    fn make_pkt(index: usize, src: &str, dst: &str, proto: Protocol, length: usize) -> (PacketSummary, Vec<u8>) {
        make_pkt_ports(index, src, dst, 12345, 80, proto, length)
    }

    #[test]
    fn empty_store() {
        let store = PacketStore::default();
        let convs = compute(&store, None);
        assert!(convs.is_empty());
    }

    #[test]
    fn single_conversation() {
        let mut store = PacketStore::default();
        let (pkt, raw) = make_pkt_ports(0, "10.0.0.1", "10.0.0.2", 12345, 80, Protocol::Tcp, 100);
        store.add(pkt, raw);
        let (pkt, raw) = make_pkt_ports(1, "10.0.0.2", "10.0.0.1", 80, 12345, Protocol::Tcp, 200);
        store.add(pkt, raw);

        let convs = compute(&store, None);
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].total_packets(), 2);
        assert_eq!(convs[0].total_bytes(), 300);
        assert_eq!(convs[0].packets_a_to_b, 1);
        assert_eq!(convs[0].packets_b_to_a, 1);
    }

    #[test]
    fn multiple_conversations() {
        let mut store = PacketStore::default();
        let (p, r) = make_pkt(0, "10.0.0.1", "10.0.0.2", Protocol::Tcp, 100);
        store.add(p, r);
        let (p, r) = make_pkt(1, "10.0.0.3", "10.0.0.4", Protocol::Udp, 200);
        store.add(p, r);

        let convs = compute(&store, None);
        assert_eq!(convs.len(), 2);
    }

    #[test]
    fn filtered_computation() {
        let mut store = PacketStore::default();
        for i in 0..5 {
            let (pkt, raw) = make_pkt(i, "10.0.0.1", "10.0.0.2", Protocol::Tcp, 100);
            store.add(pkt, raw);
        }
        let indices = vec![0, 2];
        let convs = compute(&store, Some(&indices));
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].total_packets(), 2);
    }

    #[test]
    fn sort_by_column() {
        let mut store = PacketStore::default();
        let (p, r) = make_pkt(0, "10.0.0.1", "10.0.0.2", Protocol::Tcp, 100);
        store.add(p, r);
        let (p, r) = make_pkt(1, "10.0.0.1", "10.0.0.2", Protocol::Tcp, 100);
        store.add(p, r);
        let (p, r) = make_pkt(2, "10.0.0.3", "10.0.0.4", Protocol::Udp, 500);
        store.add(p, r);

        let mut convs = compute(&store, None);
        sort_conversations(&mut convs, ConvSortColumn::TotalBytes, false);
        assert!(convs[0].total_bytes() >= convs[1].total_bytes());

        sort_conversations(&mut convs, ConvSortColumn::TotalBytes, true);
        assert!(convs[0].total_bytes() <= convs[1].total_bytes());
    }

    #[test]
    fn numeric_ip_ordering() {
        // 9.0.0.1 is numerically less than 10.0.0.1, despite lexicographic ordering
        assert!(addr_is_lower("9.0.0.1", None, "10.0.0.1", None));
        assert!(!addr_is_lower("10.0.0.1", None, "9.0.0.1", None));
    }
}

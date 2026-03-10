/// Endpoint statistics: per-IP address TX/RX counts.

use std::collections::HashMap;

use crate::dissect::model::PacketSummary;
use crate::store::packet_store::PacketStore;

#[derive(Debug, Clone)]
pub struct EndpointStats {
    pub address: String,
    pub tx_packets: usize,
    pub rx_packets: usize,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub first_seen: f64,
    pub last_seen: f64,
}

impl EndpointStats {
    pub fn total_packets(&self) -> usize {
        self.tx_packets + self.rx_packets
    }

    pub fn total_bytes(&self) -> u64 {
        self.tx_bytes + self.rx_bytes
    }
}

pub fn compute(store: &PacketStore, indices: Option<&[usize]>) -> Vec<EndpointStats> {
    let mut map: HashMap<String, EndpointStats> = HashMap::new();

    let mut process = |pkt: &PacketSummary| {
        let bytes = pkt.original_length as u64;

        // Source endpoint → TX
        let src = map.entry(pkt.source.clone()).or_insert_with(|| EndpointStats {
            address: pkt.source.clone(),
            tx_packets: 0,
            rx_packets: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            first_seen: pkt.timestamp,
            last_seen: pkt.timestamp,
        });
        src.tx_packets += 1;
        src.tx_bytes += bytes;
        if pkt.timestamp < src.first_seen {
            src.first_seen = pkt.timestamp;
        }
        if pkt.timestamp > src.last_seen {
            src.last_seen = pkt.timestamp;
        }

        // Destination endpoint → RX
        let dst = map.entry(pkt.destination.clone()).or_insert_with(|| EndpointStats {
            address: pkt.destination.clone(),
            tx_packets: 0,
            rx_packets: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            first_seen: pkt.timestamp,
            last_seen: pkt.timestamp,
        });
        dst.rx_packets += 1;
        dst.rx_bytes += bytes;
        if pkt.timestamp < dst.first_seen {
            dst.first_seen = pkt.timestamp;
        }
        if pkt.timestamp > dst.last_seen {
            dst.last_seen = pkt.timestamp;
        }
    };

    match indices {
        Some(idx) => {
            for &i in idx {
                if let Some(pkt) = store.get(i) {
                    process(pkt);
                }
            }
        }
        None => {
            for i in 0..store.len() {
                if let Some(pkt) = store.get(i) {
                    process(pkt);
                }
            }
        }
    }

    let mut result: Vec<EndpointStats> = map.into_values().collect();
    result.sort_by(|a, b| b.total_packets().cmp(&a.total_packets()));
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointSortColumn {
    TotalPackets,
    TotalBytes,
    TxPackets,
    RxPackets,
    TxBytes,
    RxBytes,
}

impl EndpointSortColumn {
    pub const ALL: &[Self] = &[
        Self::TotalPackets,
        Self::TotalBytes,
        Self::TxPackets,
        Self::RxPackets,
        Self::TxBytes,
        Self::RxBytes,
    ];

    pub fn next(self) -> Self {
        let idx = Self::ALL.iter().position(|&c| c == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::TotalPackets => "Total Pkts",
            Self::TotalBytes => "Total Bytes",
            Self::TxPackets => "Tx Pkts",
            Self::RxPackets => "Rx Pkts",
            Self::TxBytes => "Tx Bytes",
            Self::RxBytes => "Rx Bytes",
        }
    }
}

pub fn sort_endpoints(eps: &mut [EndpointStats], column: EndpointSortColumn, ascending: bool) {
    eps.sort_by(|a, b| {
        let cmp = match column {
            EndpointSortColumn::TotalPackets => a.total_packets().cmp(&b.total_packets()),
            EndpointSortColumn::TotalBytes => a.total_bytes().cmp(&b.total_bytes()),
            EndpointSortColumn::TxPackets => a.tx_packets.cmp(&b.tx_packets),
            EndpointSortColumn::RxPackets => a.rx_packets.cmp(&b.rx_packets),
            EndpointSortColumn::TxBytes => a.tx_bytes.cmp(&b.tx_bytes),
            EndpointSortColumn::RxBytes => a.rx_bytes.cmp(&b.rx_bytes),
        };
        if ascending { cmp } else { cmp.reverse() }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::model::Protocol;

    fn make_pkt(index: usize, src: &str, dst: &str, length: usize) -> (PacketSummary, Vec<u8>) {
        let raw = vec![0u8; length];
        let summary = PacketSummary {
            index,
            timestamp: index as f64 * 0.001,
            source: src.into(),
            destination: dst.into(),
            protocol: Protocol::Tcp,
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
        let eps = compute(&store, None);
        assert!(eps.is_empty());
    }

    #[test]
    fn single_packet_two_endpoints() {
        let mut store = PacketStore::default();
        let (pkt, raw) = make_pkt(0, "10.0.0.1", "10.0.0.2", 100);
        store.add(pkt, raw);

        let eps = compute(&store, None);
        assert_eq!(eps.len(), 2);

        let src_ep = eps.iter().find(|e| e.address == "10.0.0.1").unwrap();
        assert_eq!(src_ep.tx_packets, 1);
        assert_eq!(src_ep.rx_packets, 0);

        let dst_ep = eps.iter().find(|e| e.address == "10.0.0.2").unwrap();
        assert_eq!(dst_ep.tx_packets, 0);
        assert_eq!(dst_ep.rx_packets, 1);
    }

    #[test]
    fn bidirectional_traffic() {
        let mut store = PacketStore::default();
        store.add(make_pkt(0, "10.0.0.1", "10.0.0.2", 100).0,
                  make_pkt(0, "10.0.0.1", "10.0.0.2", 100).1);
        store.add(make_pkt(1, "10.0.0.2", "10.0.0.1", 200).0,
                  make_pkt(1, "10.0.0.2", "10.0.0.1", 200).1);

        let eps = compute(&store, None);
        let ep1 = eps.iter().find(|e| e.address == "10.0.0.1").unwrap();
        assert_eq!(ep1.tx_packets, 1);
        assert_eq!(ep1.rx_packets, 1);
        assert_eq!(ep1.tx_bytes, 100);
        assert_eq!(ep1.rx_bytes, 200);
    }

    #[test]
    fn sort_by_column() {
        let mut store = PacketStore::default();
        store.add(make_pkt(0, "10.0.0.1", "10.0.0.2", 100).0,
                  make_pkt(0, "10.0.0.1", "10.0.0.2", 100).1);
        store.add(make_pkt(1, "10.0.0.1", "10.0.0.2", 100).0,
                  make_pkt(1, "10.0.0.1", "10.0.0.2", 100).1);
        store.add(make_pkt(2, "10.0.0.3", "10.0.0.4", 500).0,
                  make_pkt(2, "10.0.0.3", "10.0.0.4", 500).1);

        let mut eps = compute(&store, None);
        sort_endpoints(&mut eps, EndpointSortColumn::TxBytes, false);
        assert!(eps[0].tx_bytes >= eps[1].tx_bytes);
    }
}

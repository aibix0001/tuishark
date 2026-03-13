/// I/O graph: packet/byte rate over time, bucketed into intervals.

use crate::store::packet_store::PacketStore;

#[derive(Debug, Clone)]
pub struct IoGraphData {
    pub buckets_packets: Vec<u64>,
    pub buckets_bytes: Vec<u64>,
    pub bucket_width_secs: f64,
    pub start_time: f64,
    pub end_time: f64,
    pub max_packets: u64,
    pub max_bytes: u64,
}

pub fn compute(store: &PacketStore, indices: Option<&[usize]>, num_buckets: usize) -> IoGraphData {
    let num_buckets = num_buckets.max(1);

    // First pass: collect timestamps and lengths, find min/max
    let mut entries: Vec<(f64, u64)> = Vec::new();
    let mut min_ts = f64::MAX;
    let mut max_ts = f64::MIN;

    for pkt in store.iter_packets(indices) {
        let ts = pkt.timestamp;
        let bytes = pkt.original_length as u64;
        if ts < min_ts {
            min_ts = ts;
        }
        if ts > max_ts {
            max_ts = ts;
        }
        entries.push((ts, bytes));
    }

    if entries.is_empty() {
        return IoGraphData {
            buckets_packets: vec![0; num_buckets],
            buckets_bytes: vec![0; num_buckets],
            bucket_width_secs: 1.0,
            start_time: 0.0,
            end_time: 0.0,
            max_packets: 0,
            max_bytes: 0,
        };
    }

    let mut buckets_packets = vec![0u64; num_buckets];
    let mut buckets_bytes = vec![0u64; num_buckets];

    if min_ts >= max_ts {
        // Single timestamp: everything in first bucket
        for &(_ts, bytes) in &entries {
            buckets_packets[0] += 1;
            buckets_bytes[0] += bytes;
        }
        let max_packets = buckets_packets[0];
        let max_bytes = buckets_bytes[0];
        return IoGraphData {
            buckets_packets,
            buckets_bytes,
            bucket_width_secs: 1.0,
            start_time: min_ts,
            end_time: max_ts,
            max_packets,
            max_bytes,
        };
    }

    let duration = max_ts - min_ts;
    let bucket_width = duration / num_buckets as f64;

    // Second pass: fill buckets from collected entries
    for &(ts, bytes) in &entries {
        let bucket = ((ts - min_ts) / bucket_width) as usize;
        let bucket = bucket.min(num_buckets - 1); // clamp last packet
        buckets_packets[bucket] += 1;
        buckets_bytes[bucket] += bytes;
    }

    let max_packets = buckets_packets.iter().copied().max().unwrap_or(0);
    let max_bytes = buckets_bytes.iter().copied().max().unwrap_or(0);

    IoGraphData {
        buckets_packets,
        buckets_bytes,
        bucket_width_secs: bucket_width,
        start_time: min_ts,
        end_time: max_ts,
        max_packets,
        max_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::model::{PacketSummary, Protocol};

    fn make_pkt(index: usize, timestamp: f64, length: usize) -> (PacketSummary, Vec<u8>) {
        let raw = vec![0u8; length];
        let summary = PacketSummary {
            index,
            timestamp,
            source: "10.0.0.1".into(),
            destination: "10.0.0.2".into(),
            protocol: Protocol::Tcp,
            length,
            original_length: length,
            info: "test".into(),
            src_port: Some(12345),
            dst_port: Some(80),
            link_meta: None,
        };
        (summary, raw)
    }

    #[test]
    fn empty_store() {
        let store = PacketStore::default();
        let data = compute(&store, None, 10);
        assert_eq!(data.max_packets, 0);
        assert_eq!(data.buckets_packets.len(), 10);
    }

    #[test]
    fn single_packet() {
        let mut store = PacketStore::default();
        let (p, r) = make_pkt(0, 1.0, 100);
        store.add(p, r);

        let data = compute(&store, None, 10);
        assert_eq!(data.max_packets, 1);
    }

    #[test]
    fn even_distribution() {
        let mut store = PacketStore::default();
        for i in 0..100 {
            let ts = i as f64 * 0.1;
            let (p, r) = make_pkt(i, ts, 100);
            store.add(p, r);
        }

        let data = compute(&store, None, 10);
        assert_eq!(data.buckets_packets.len(), 10);
        let total: u64 = data.buckets_packets.iter().sum();
        assert_eq!(total, 100);
    }

    #[test]
    fn filtered_indices() {
        let mut store = PacketStore::default();
        for i in 0..100 {
            let ts = i as f64 * 0.1;
            let (p, r) = make_pkt(i, ts, 100);
            store.add(p, r);
        }

        let indices: Vec<usize> = (0..50).collect();
        let data = compute(&store, Some(&indices), 10);
        let total: u64 = data.buckets_packets.iter().sum();
        assert_eq!(total, 50);
    }

    #[test]
    fn respects_num_buckets() {
        let mut store = PacketStore::default();
        for i in 0..20 {
            let (p, r) = make_pkt(i, i as f64, 100);
            store.add(p, r);
        }

        let data5 = compute(&store, None, 5);
        assert_eq!(data5.buckets_packets.len(), 5);

        let data20 = compute(&store, None, 20);
        assert_eq!(data20.buckets_packets.len(), 20);
    }
}

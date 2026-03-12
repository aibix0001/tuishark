use std::collections::HashMap;
use std::time::Instant;

use super::model::FlowKey;
use super::path_model::{PacketPath, PathEvent, PathHop};

/// Groups PathEvents by (skb_ptr, flow_hash) into PacketPaths,
/// and matches completed paths to captured packets by 5-tuple + timestamp.
pub struct PathAggregator {
    /// In-progress paths keyed by skb_ptr.
    /// Each skb_ptr may have multiple events as the packet traverses functions.
    pending: HashMap<u64, PendingPath>,
    /// Completed paths ready to be matched to packets.
    completed: Vec<PacketPath>,
    /// Timestamp of last expiry sweep.
    last_expiry: Instant,
}

struct PendingPath {
    events: Vec<PathEvent>,
    last_update: Instant,
}

impl PathAggregator {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            completed: Vec::new(),
            last_expiry: Instant::now(),
        }
    }

    /// Ingest a batch of PathEvents from the perf buffer.
    pub fn ingest(&mut self, events: &[PathEvent]) {
        let now = Instant::now();

        for event in events {
            let entry = self.pending
                .entry(event.skb_ptr)
                .or_insert_with(|| PendingPath {
                    events: Vec::with_capacity(8),
                    last_update: now,
                });

            // Validate 5-tuple consistency: if this event's 5-tuple differs from
            // existing events, the skb_ptr was reused for a different packet.
            // Start a new pending path in that case.
            if !entry.events.is_empty() {
                let first = &entry.events[0];
                if first.src_addr != event.src_addr
                    || first.dst_addr != event.dst_addr
                    || first.protocol != event.protocol
                {
                    // skb_ptr reuse detected — finalize old path, start new one
                    let old = std::mem::replace(entry, PendingPath {
                        events: Vec::with_capacity(8),
                        last_update: now,
                    });
                    if let Some(path) = Self::build_path(old.events) {
                        self.completed.push(path);
                    }
                }
            }

            entry.events.push(*event);
            entry.last_update = now;
        }

        // Run expiry check periodically (every 20ms)
        if now.duration_since(self.last_expiry).as_millis() >= 20 {
            self.expire_paths(now);
            self.last_expiry = now;
        }
    }

    /// Expire pending paths that haven't received new events for >50ms.
    /// These are considered complete (the packet has finished traversing).
    /// Most kernel paths complete in microseconds; 50ms is generous enough for
    /// slow paths (netfilter, qdisc delays) while keeping latency low.
    fn expire_paths(&mut self, now: Instant) {
        let mut expired_keys = Vec::new();

        for (&skb_ptr, pending) in &self.pending {
            if now.duration_since(pending.last_update).as_millis() >= 50 {
                expired_keys.push(skb_ptr);
            }
        }

        for key in expired_keys {
            if let Some(pending) = self.pending.remove(&key) {
                if let Some(path) = Self::build_path(pending.events) {
                    self.completed.push(path);
                }
            }
        }

        // Cap pending map size to prevent unbounded growth.
        // Finalize oldest entries rather than silently dropping them.
        if self.pending.len() > 10_000 {
            let mut entries: Vec<_> = self.pending.drain().collect();
            entries.sort_by_key(|(_, p)| p.last_update);
            // Finalize the oldest 5000 entries
            for (_, pending) in entries.drain(..5000) {
                if let Some(path) = Self::build_path(pending.events) {
                    self.completed.push(path);
                }
            }
            // Re-insert the newest entries
            for (k, v) in entries {
                self.pending.insert(k, v);
            }
        }

        // Also cap completed list
        if self.completed.len() > 10_000 {
            self.completed.drain(..5000);
        }
    }

    /// Build a PacketPath from a set of events for one skb_ptr.
    fn build_path(mut events: Vec<PathEvent>) -> Option<PacketPath> {
        if events.is_empty() {
            return None;
        }

        // Sort by timestamp
        events.sort_by_key(|e| e.timestamp_ns);

        let first = &events[0];
        let first_ts = first.timestamp_ns;

        let hops: Vec<PathHop> = events
            .iter()
            .map(|e| PathHop {
                func_id: e.func_id,
                timestamp_ns: e.timestamp_ns,
                delta_ns: e.timestamp_ns.saturating_sub(first_ts),
            })
            .collect();

        let last_ts = events.last().unwrap().timestamp_ns;

        Some(PacketPath {
            hops,
            first_seen_ns: first_ts,
            last_seen_ns: last_ts,
            src_addr: first.src_addr,
            dst_addr: first.dst_addr,
            src_port: first.src_port,
            dst_port: first.dst_port,
            protocol: first.protocol,
        })
    }

    /// Drain completed paths. Returns paths ready to be matched to packets.
    pub fn drain_completed(&mut self) -> Vec<PacketPath> {
        std::mem::take(&mut self.completed)
    }

    /// Try to extract a pending path matching a given flow key.
    ///
    /// When a packet is received, its path events may already be in the pending map
    /// but not yet expired. This method finds the best-matching pending path (by 5-tuple)
    /// and returns it immediately without waiting for expiry.
    ///
    /// This solves the timing gap where packets are printed before their paths expire.
    pub fn try_extract_pending(&mut self, flow_key: &FlowKey) -> Option<PacketPath> {
        let fwd = (flow_key.src_addr, flow_key.dst_addr, flow_key.src_port, flow_key.dst_port, flow_key.protocol);
        let rev = (flow_key.dst_addr, flow_key.src_addr, flow_key.dst_port, flow_key.src_port, flow_key.protocol);

        // Find the best matching pending path (most hops = most complete traversal)
        let mut best_key: Option<u64> = None;
        let mut best_hops = 0usize;

        for (&skb_ptr, pending) in &self.pending {
            if pending.events.is_empty() {
                continue;
            }
            let first = &pending.events[0];
            let evt_tuple = (first.src_addr, first.dst_addr, first.src_port, first.dst_port, first.protocol);
            if evt_tuple == fwd || evt_tuple == rev {
                if pending.events.len() > best_hops {
                    best_hops = pending.events.len();
                    best_key = Some(skb_ptr);
                }
            }
        }

        if let Some(skb_ptr) = best_key {
            let pending = self.pending.remove(&skb_ptr)?;
            Self::build_path(pending.events)
        } else {
            None
        }
    }

    /// Force-flush all pending paths (e.g., when stopping tracing).
    pub fn flush(&mut self) {
        let all_pending: Vec<_> = self.pending.drain().collect();
        for (_, pending) in all_pending {
            if let Some(path) = Self::build_path(pending.events) {
                self.completed.push(path);
            }
        }
    }

    /// Match completed paths to captured packets by 5-tuple.
    ///
    /// Uses a HashMap for O(n+m) lookup instead of O(n*m) nested loops.
    /// For each path, finds the most recent matching packet (last in the list).
    pub fn match_to_packets(
        paths: &[PacketPath],
        packet_flow_keys: &[(usize, FlowKey)],
    ) -> Vec<(usize, PacketPath)> {
        if paths.is_empty() || packet_flow_keys.is_empty() {
            return Vec::new();
        }

        // Build a lookup: FlowKey -> most recent packet index.
        // Since packet_flow_keys is ordered by time (newest last), last write wins.
        let mut fwd_map: HashMap<(u32, u32, u16, u16, u8), usize> = HashMap::new();
        let mut rev_map: HashMap<(u32, u32, u16, u16, u8), usize> = HashMap::new();
        for &(pkt_idx, ref fk) in packet_flow_keys {
            let key = (fk.src_addr, fk.dst_addr, fk.src_port, fk.dst_port, fk.protocol);
            let rev = (fk.dst_addr, fk.src_addr, fk.dst_port, fk.src_port, fk.protocol);
            fwd_map.insert(key, pkt_idx);
            rev_map.insert(rev, pkt_idx);
        }

        let mut matches = Vec::new();
        for path in paths {
            let key = (path.src_addr, path.dst_addr, path.src_port, path.dst_port, path.protocol);
            if let Some(&pkt_idx) = fwd_map.get(&key).or_else(|| rev_map.get(&key)) {
                matches.push((pkt_idx, path.clone()));
            }
        }

        matches
    }
}

impl Default for PathAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(skb_ptr: u64, func_id: u16, ts: u64) -> PathEvent {
        PathEvent {
            skb_ptr,
            timestamp_ns: ts,
            src_addr: 0xC0A80101, // 192.168.1.1
            dst_addr: 0x0A000001, // 10.0.0.1
            func_id,
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            _pad: [0; 1],
        }
    }

    #[test]
    fn build_path_sorts_by_timestamp() {
        let events = vec![
            make_event(0x1000, 8, 3000),  // tcp_v4_rcv
            make_event(0x1000, 0, 1000),  // netif_receive_skb
            make_event(0x1000, 2, 2000),  // ip_rcv
        ];

        let path = PathAggregator::build_path(events).unwrap();
        assert_eq!(path.hops.len(), 3);
        assert_eq!(path.hops[0].func_id, 0);
        assert_eq!(path.hops[1].func_id, 2);
        assert_eq!(path.hops[2].func_id, 8);
        assert_eq!(path.hops[0].delta_ns, 0);
        assert_eq!(path.hops[1].delta_ns, 1000);
        assert_eq!(path.hops[2].delta_ns, 2000);
        assert_eq!(path.total_ns(), 2000);
    }

    #[test]
    fn build_path_empty() {
        assert!(PathAggregator::build_path(vec![]).is_none());
    }

    #[test]
    fn match_forward_flow() {
        let path = PacketPath {
            hops: vec![],
            first_seen_ns: 0,
            last_seen_ns: 0,
            src_addr: 0xC0A80101,
            dst_addr: 0x0A000001,
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
        };

        let flow_key = FlowKey {
            src_addr: 0xC0A80101,
            dst_addr: 0x0A000001,
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            _pad: [0; 3],
        };

        let matches = PathAggregator::match_to_packets(&[path], &[(42, flow_key)]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, 42);
    }

    #[test]
    fn match_reverse_flow() {
        let path = PacketPath {
            hops: vec![],
            first_seen_ns: 0,
            last_seen_ns: 0,
            src_addr: 0x0A000001,
            dst_addr: 0xC0A80101,
            src_port: 80,
            dst_port: 12345,
            protocol: 6,
        };

        let flow_key = FlowKey {
            src_addr: 0xC0A80101,
            dst_addr: 0x0A000001,
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            _pad: [0; 3],
        };

        let matches = PathAggregator::match_to_packets(&[path], &[(7, flow_key)]);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn skb_ptr_reuse_detection() {
        let mut agg = PathAggregator::new();

        // First packet through skb_ptr 0x1000
        let events1 = vec![
            PathEvent {
                skb_ptr: 0x1000, timestamp_ns: 1000,
                src_addr: 0xC0A80101, dst_addr: 0x0A000001,
                func_id: 0, src_port: 100, dst_port: 80,
                protocol: 6, _pad: [0; 1],
            },
        ];
        agg.ingest(&events1);

        // Second packet reuses skb_ptr 0x1000 with different 5-tuple
        let events2 = vec![
            PathEvent {
                skb_ptr: 0x1000, timestamp_ns: 2000,
                src_addr: 0xDEADBEEF, dst_addr: 0xCAFEBABE,
                func_id: 2, src_port: 200, dst_port: 443,
                protocol: 6, _pad: [0; 1],
            },
        ];
        agg.ingest(&events2);

        // The first path should have been completed when reuse was detected
        let completed = agg.drain_completed();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].src_addr, 0xC0A80101);
    }
}

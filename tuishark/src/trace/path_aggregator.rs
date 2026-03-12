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
            entry.events.push(*event);
            entry.last_update = now;
        }

        // Run expiry check periodically (every 200ms)
        if now.duration_since(self.last_expiry).as_millis() >= 200 {
            self.expire_paths(now);
            self.last_expiry = now;
        }
    }

    /// Expire pending paths that haven't received new events for >100ms.
    /// These are considered complete (the packet has finished traversing).
    fn expire_paths(&mut self, now: Instant) {
        let mut expired_keys = Vec::new();

        for (&skb_ptr, pending) in &self.pending {
            if now.duration_since(pending.last_update).as_millis() >= 100 {
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

        // Also cap pending map size to prevent unbounded growth
        if self.pending.len() > 10_000 {
            // Remove oldest entries
            let mut entries: Vec<_> = self.pending.drain().collect();
            entries.sort_by_key(|(_, p)| p.last_update);
            // Keep newest 5000
            for (k, v) in entries.into_iter().skip(5000) {
                self.pending.insert(k, v);
            }
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
    /// Returns a Vec of (packet_index, PacketPath) pairs.
    /// Matching is done by comparing the path's 5-tuple against the packet's FlowKey.
    pub fn match_to_packets(
        paths: &[PacketPath],
        packet_flow_keys: &[(usize, FlowKey)],
    ) -> Vec<(usize, PacketPath)> {
        let mut matches = Vec::new();

        for path in paths {
            // Find packets with matching 5-tuple (forward or reverse)
            for &(pkt_idx, ref fk) in packet_flow_keys {
                let fwd = path.src_addr == fk.src_addr
                    && path.dst_addr == fk.dst_addr
                    && path.src_port == fk.src_port
                    && path.dst_port == fk.dst_port
                    && path.protocol == fk.protocol;

                let rev = path.src_addr == fk.dst_addr
                    && path.dst_addr == fk.src_addr
                    && path.src_port == fk.dst_port
                    && path.dst_port == fk.src_port
                    && path.protocol == fk.protocol;

                if fwd || rev {
                    matches.push((pkt_idx, path.clone()));
                    break; // One path → one packet (first match wins)
                }
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
            func_id,
            src_addr: 0xC0A80101, // 192.168.1.1
            dst_addr: 0x0A000001, // 10.0.0.1
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            _pad: [0; 5],
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
}

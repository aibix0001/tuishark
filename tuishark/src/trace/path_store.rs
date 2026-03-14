use std::collections::HashMap;

use super::path_model::PacketPath;

/// Stores per-packet kernel path data.
/// Maps packet store index → PacketPath (analogous to TraceStore for ProcessInfo).
#[derive(Default)]
pub struct PathStore {
    entries: HashMap<usize, PacketPath>,
}

impl PathStore {
    pub fn insert(&mut self, packet_index: usize, path: PacketPath) {
        self.entries.insert(packet_index, path);
    }

    pub fn get(&self, packet_index: usize) -> Option<&PacketPath> {
        self.entries.get(&packet_index)
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::path_model::PathHop;

    fn make_path() -> PacketPath {
        PacketPath {
            hops: vec![
                PathHop { func_id: 0, timestamp_ns: 1000, delta_ns: 0 },
                PathHop { func_id: 2, timestamp_ns: 2200, delta_ns: 1200 },
            ],
            first_seen_ns: 1000,
            last_seen_ns: 2200,
            src_addr: 0,
            dst_addr: 0,
            src_port: 0,
            dst_port: 0,
            protocol: 6,
        }
    }

    #[test]
    fn insert_and_get() {
        let mut store = PathStore::default();
        store.insert(0, make_path());
        store.insert(5, make_path());

        assert_eq!(store.len(), 2);
        assert!(!store.is_empty());
        assert!(store.get(0).is_some());
        assert_eq!(store.get(0).unwrap().hops.len(), 2);
        assert!(store.get(1).is_none());
        assert!(store.get(5).is_some());
    }

    #[test]
    fn clear_resets() {
        let mut store = PathStore::default();
        store.insert(0, make_path());
        assert_eq!(store.len(), 1);
        store.clear();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
        assert!(store.get(0).is_none());
    }
}

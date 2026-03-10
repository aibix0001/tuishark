use std::collections::HashMap;

use super::model::ProcessInfo;

/// Stores per-packet process information from eBPF tracing.
/// Maps packet store index → ProcessInfo.
pub struct TraceStore {
    entries: HashMap<usize, ProcessInfo>,
}

impl Default for TraceStore {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

impl TraceStore {
    pub fn insert(&mut self, packet_index: usize, info: ProcessInfo) {
        self.entries.insert(packet_index, info);
    }

    pub fn get(&self, packet_index: usize) -> Option<&ProcessInfo> {
        self.entries.get(&packet_index)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_info(pid: u32, name: &str) -> ProcessInfo {
        let mut comm = [0u8; 16];
        let bytes = name.as_bytes();
        comm[..bytes.len().min(16)].copy_from_slice(&bytes[..bytes.len().min(16)]);
        ProcessInfo {
            pid,
            uid: 1000,
            comm,
        }
    }

    #[test]
    fn insert_and_get() {
        let mut store = TraceStore::default();
        store.insert(0, make_info(1234, "curl"));
        store.insert(1, make_info(5678, "wget"));

        assert_eq!(store.len(), 2);
        assert_eq!(store.get(0).unwrap().pid, 1234);
        assert_eq!(store.get(1).unwrap().comm_str(), "wget");
        assert!(store.get(2).is_none());
    }

    #[test]
    fn clear_resets() {
        let mut store = TraceStore::default();
        store.insert(0, make_info(1, "test"));
        assert_eq!(store.len(), 1);
        store.clear();
        assert_eq!(store.len(), 0);
        assert!(store.get(0).is_none());
    }
}

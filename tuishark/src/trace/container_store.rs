use std::collections::HashMap;

use super::model::ContainerInfo;

/// Stores per-packet container context from eBPF tracing.
/// Maps packet store index → ContainerInfo.
#[derive(Default)]
pub struct ContainerStore {
    entries: HashMap<usize, ContainerInfo>,
}

impl ContainerStore {
    pub fn insert(&mut self, packet_index: usize, info: ContainerInfo) {
        self.entries.insert(packet_index, info);
    }

    pub fn get(&self, packet_index: usize) -> Option<&ContainerInfo> {
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

    fn make_info(ifindex: u32, name: &str, state: u8) -> ContainerInfo {
        let mut dev_name = [0u8; 16];
        let bytes = name.as_bytes();
        dev_name[..bytes.len().min(16)].copy_from_slice(&bytes[..bytes.len().min(16)]);
        ContainerInfo {
            cgroup_id: 1234,
            netns_inum: 4026531840,
            ifindex,
            dev_name,
            tcp_state: state,
            _pad: [0; 7],
        }
    }

    #[test]
    fn insert_and_get() {
        let mut store = ContainerStore::default();
        store.insert(0, make_info(2, "eth0", 1));
        store.insert(1, make_info(5, "docker0", 0));

        assert_eq!(store.len(), 2);
        assert!(!store.is_empty());
        assert_eq!(store.get(0).unwrap().ifindex, 2);
        assert_eq!(store.get(0).unwrap().dev_name_str(), "eth0");
        assert_eq!(store.get(1).unwrap().dev_name_str(), "docker0");
        assert!(store.get(2).is_none());
    }

    #[test]
    fn clear_resets() {
        let mut store = ContainerStore::default();
        store.insert(0, make_info(1, "lo", 0));
        assert_eq!(store.len(), 1);
        store.clear();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
        assert!(store.get(0).is_none());
    }
}

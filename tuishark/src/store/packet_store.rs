use crate::dissect::model::PacketSummary;

#[derive(Default)]
pub struct PacketStore {
    packets: Vec<PacketSummary>,
    raw_data: Vec<Vec<u8>>,
}

impl PacketStore {
    pub fn add(&mut self, packet: PacketSummary, raw: Vec<u8>) {
        self.packets.push(packet);
        self.raw_data.push(raw);
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&PacketSummary> {
        self.packets.get(index)
    }

    pub fn get_raw(&self, index: usize) -> Option<&[u8]> {
        self.raw_data.get(index).map(|v| v.as_slice())
    }

    pub fn get_range(&self, offset: usize, count: usize) -> &[PacketSummary] {
        let start = offset.min(self.packets.len());
        let end = (offset + count).min(self.packets.len());
        &self.packets[start..end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::model::Protocol;

    fn make_summary(index: usize) -> (PacketSummary, Vec<u8>) {
        let raw = vec![0u8; 64];
        let summary = PacketSummary {
            index,
            timestamp: index as f64 * 0.001,
            source: "10.0.0.1".into(),
            destination: "10.0.0.2".into(),
            protocol: Protocol::Tcp,
            length: 64,
            info: "test".into(),
        };
        (summary, raw)
    }

    #[test]
    fn empty_store() {
        let store = PacketStore::default();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert!(store.get(0).is_none());
        assert!(store.get_raw(0).is_none());
    }

    #[test]
    fn add_and_get() {
        let mut store = PacketStore::default();
        let (pkt, raw) = make_summary(0);
        store.add(pkt, raw);
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
        assert_eq!(store.get(0).unwrap().index, 0);
        assert_eq!(store.get_raw(0).unwrap().len(), 64);
    }

    #[test]
    fn get_range_bounds() {
        let mut store = PacketStore::default();
        for i in 0..10 {
            let (pkt, raw) = make_summary(i);
            store.add(pkt, raw);
        }

        // Normal range
        let range = store.get_range(2, 3);
        assert_eq!(range.len(), 3);
        assert_eq!(range[0].index, 2);

        // Offset beyond length
        let range = store.get_range(20, 5);
        assert_eq!(range.len(), 0);

        // Partial range at end
        let range = store.get_range(8, 5);
        assert_eq!(range.len(), 2);

        // Zero count
        let range = store.get_range(0, 0);
        assert_eq!(range.len(), 0);
    }
}

use crate::dissect::model::{LinkType, PacketSummary};

pub struct PacketStore {
    packets: Vec<PacketSummary>,
    raw_data: Vec<Vec<u8>>,
    first_absolute_ts: Option<f64>,
    modified_since_save: bool,
    link_type: LinkType,
}

impl Default for PacketStore {
    fn default() -> Self {
        Self {
            packets: Vec::new(),
            raw_data: Vec::new(),
            first_absolute_ts: None,
            modified_since_save: false,
            link_type: LinkType::Ethernet,
        }
    }
}

impl PacketStore {
    pub fn add(&mut self, packet: PacketSummary, raw: Vec<u8>) {
        self.packets.push(packet);
        self.raw_data.push(raw);
        self.modified_since_save = true;
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

    pub fn set_first_absolute_ts(&mut self, ts: f64) {
        if self.first_absolute_ts.is_none() {
            self.first_absolute_ts = Some(ts);
        }
    }

    pub fn first_absolute_ts(&self) -> Option<f64> {
        self.first_absolute_ts
    }

    pub fn is_modified(&self) -> bool {
        self.modified_since_save && !self.packets.is_empty()
    }

    pub fn mark_saved(&mut self) {
        self.modified_since_save = false;
    }

    /// Iterate over packets, optionally filtered by indices.
    /// When `indices` is `None`, iterates over all packets.
    pub fn iter_packets<'a>(&'a self, indices: Option<&'a [usize]>) -> PacketIter<'a> {
        PacketIter {
            store: self,
            indices,
            pos: 0,
        }
    }

    pub fn set_link_type(&mut self, lt: LinkType) {
        self.link_type = lt;
    }

    pub fn link_type(&self) -> LinkType {
        self.link_type
    }

    pub fn clear(&mut self) {
        self.packets.clear();
        self.raw_data.clear();
        self.first_absolute_ts = None;
        self.modified_since_save = false;
        self.link_type = LinkType::Ethernet;
    }
}

pub struct PacketIter<'a> {
    store: &'a PacketStore,
    indices: Option<&'a [usize]>,
    pos: usize,
}

impl<'a> Iterator for PacketIter<'a> {
    type Item = &'a PacketSummary;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.indices {
                Some(idx) => {
                    let &i = idx.get(self.pos)?;
                    self.pos += 1;
                    if let Some(pkt) = self.store.get(i) {
                        return Some(pkt);
                    }
                }
                None => {
                    if self.pos >= self.store.len() {
                        return None;
                    }
                    let pkt = self.store.get(self.pos)?;
                    self.pos += 1;
                    return Some(pkt);
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = match self.indices {
            Some(idx) => idx.len().saturating_sub(self.pos),
            None => self.store.len().saturating_sub(self.pos),
        };
        (0, Some(remaining))
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
            original_length: 64,
            info: "test".into(),
            src_port: Some(12345),
            dst_port: Some(80),
            link_meta: None,
            eth_src: None,
            eth_dst: None,
            vlan_id: None,
            tcp_flags: 0,
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

    #[test]
    fn modified_tracking() {
        let mut store = PacketStore::default();
        assert!(!store.is_modified());

        let (pkt, raw) = make_summary(0);
        store.add(pkt, raw);
        assert!(store.is_modified());

        store.mark_saved();
        assert!(!store.is_modified());

        let (pkt, raw) = make_summary(1);
        store.add(pkt, raw);
        assert!(store.is_modified());
    }

    #[test]
    fn absolute_timestamp() {
        let mut store = PacketStore::default();
        assert!(store.first_absolute_ts().is_none());

        store.set_first_absolute_ts(1710000000.0);
        assert_eq!(store.first_absolute_ts(), Some(1710000000.0));

        // Should not overwrite once set
        store.set_first_absolute_ts(9999.0);
        assert_eq!(store.first_absolute_ts(), Some(1710000000.0));
    }

    #[test]
    fn clear_resets_everything() {
        let mut store = PacketStore::default();
        store.set_first_absolute_ts(1710000000.0);
        let (pkt, raw) = make_summary(0);
        store.add(pkt, raw);
        assert!(store.is_modified());

        store.clear();
        assert!(store.is_empty());
        assert!(!store.is_modified());
        assert!(store.first_absolute_ts().is_none());
    }
}

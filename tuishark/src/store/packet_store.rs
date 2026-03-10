use crate::dissect::model::PacketSummary;

pub struct PacketStore {
    packets: Vec<PacketSummary>,
}

impl PacketStore {
    pub fn new() -> Self {
        Self {
            packets: Vec::new(),
        }
    }

    pub fn add(&mut self, packet: PacketSummary) {
        self.packets.push(packet);
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

    pub fn get_range(&self, offset: usize, count: usize) -> &[PacketSummary] {
        let start = offset.min(self.packets.len());
        let end = (offset + count).min(self.packets.len());
        &self.packets[start..end]
    }
}

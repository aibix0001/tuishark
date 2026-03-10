use anyhow::Result;
use pcap::Capture;
use std::path::Path;

use crate::dissect::fast::parse_packet;
use crate::dissect::model::PacketSummary;

pub fn load_pcap(path: &Path) -> Result<Vec<PacketSummary>> {
    let mut cap = Capture::from_file(path)?;
    let mut packets = Vec::new();
    let mut index = 0;
    let mut first_ts: Option<f64> = None;

    while let Ok(packet) = cap.next_packet() {
        let ts = packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1_000_000.0;
        let relative_ts = match first_ts {
            Some(first) => ts - first,
            None => {
                first_ts = Some(ts);
                0.0
            }
        };

        let summary = parse_packet(index, relative_ts, packet.data);
        packets.push(summary);
        index += 1;
    }

    Ok(packets)
}

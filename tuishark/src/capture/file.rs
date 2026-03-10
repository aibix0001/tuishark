use anyhow::Result;
use pcap::Capture;
use std::path::Path;

use crate::dissect::fast::parse_packet;
use crate::dissect::model::PacketSummary;

pub fn load_pcap(path: &Path) -> Result<Vec<(PacketSummary, Vec<u8>)>> {
    let mut cap = Capture::from_file(path)?;
    let mut packets = Vec::new();
    let mut first_ts: Option<f64> = None;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                let ts = packet.header.ts.tv_sec as f64
                    + packet.header.ts.tv_usec as f64 / 1_000_000.0;
                let relative_ts = match first_ts {
                    Some(first) => ts - first,
                    None => {
                        first_ts = Some(ts);
                        0.0
                    }
                };

                let index = packets.len();
                let raw = packet.data.to_vec();
                let summary = parse_packet(index, relative_ts, &raw);
                packets.push((summary, raw));
            }
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => {
                // Log error but continue reading remaining packets
                eprintln!("Warning: packet read error: {e}");
                continue;
            }
        }
    }

    Ok(packets)
}

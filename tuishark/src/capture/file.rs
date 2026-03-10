use anyhow::{Context, Result};
use pcap::Capture;
use std::path::Path;

use crate::dissect::fast::parse_packet_with_wire_len;
use crate::dissect::model::PacketSummary;

/// Maximum consecutive read errors before bailing out (prevents infinite loop on corrupt files).
const MAX_CONSECUTIVE_ERRORS: usize = 100;

/// Load packets from a pcap/pcapng file.
/// Returns (packets, absolute_first_timestamp).
pub fn load_pcap(path: &Path) -> Result<(Vec<(PacketSummary, Vec<u8>)>, Option<f64>)> {
    let mut cap = Capture::from_file(path)
        .with_context(|| format!("failed to open pcap file: {}", path.display()))?;

    // Validate link type — only Ethernet supported
    let datalink = cap.get_datalink();
    if datalink != pcap::Linktype::ETHERNET {
        anyhow::bail!(
            "unsupported link type in '{}': {:?} (only Ethernet is supported)",
            path.display(),
            datalink
        );
    }

    let mut packets = Vec::new();
    let mut first_ts: Option<f64> = None;
    let mut consecutive_errors = 0usize;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                consecutive_errors = 0;
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
                let original_length = packet.header.len as usize;
                let raw = packet.data.to_vec();
                let summary = parse_packet_with_wire_len(index, relative_ts, &raw, original_length);
                packets.push((summary, raw));
            }
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => {
                consecutive_errors += 1;
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    anyhow::bail!(
                        "too many consecutive read errors ({MAX_CONSECUTIVE_ERRORS}), last: {e}"
                    );
                }
                continue;
            }
        }
    }

    Ok((packets, first_ts))
}

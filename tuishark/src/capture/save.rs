use anyhow::{Context, Result};
use pcap::Capture;
use std::path::Path;

use crate::store::packet_store::PacketStore;

/// Save all packets from the store to a pcap file.
/// Returns the number of packets written.
///
/// Note: `pcap::Savefile::write()` does not return a Result in the pcap crate.
/// Per-packet write failures (e.g., disk full) may only surface on `flush()`.
pub fn save_pcap(path: &Path, store: &PacketStore) -> Result<usize> {
    anyhow::ensure!(!store.is_empty(), "no packets to save");

    let base_ts = store
        .first_absolute_ts()
        .context("cannot save: no base timestamp available (capture may not have started)")?;

    let pcap_linktype = store.link_type().to_pcap();
    let cap = Capture::dead(pcap_linktype)
        .context("failed to create dead capture handle")?;
    let mut savefile = cap
        .savefile(path)
        .with_context(|| format!("failed to create pcap file: {}", path.display()))?;

    let mut count = 0;

    for i in 0..store.len() {
        let Some(summary) = store.get(i) else {
            continue;
        };
        let Some(raw) = store.get_raw(i) else {
            continue;
        };

        let absolute_ts = base_ts + summary.timestamp;
        // Use floor division to ensure tv_usec is always non-negative.
        let tv_sec = absolute_ts.floor() as i64;
        let frac = (absolute_ts - tv_sec as f64) * 1_000_000.0;
        // Clamp to valid pcap range [0, 999_999]
        let tv_usec = (frac.round() as i64).clamp(0, 999_999);

        let header = pcap::PacketHeader {
            ts: libc::timeval {
                tv_sec: tv_sec as libc::time_t,
                tv_usec: tv_usec as libc::suseconds_t,
            },
            caplen: raw.len() as u32,
            len: summary.original_length as u32,
        };

        let packet = pcap::Packet {
            header: &header,
            data: raw,
        };

        savefile.write(&packet);
        count += 1;
    }

    savefile.flush()?;
    Ok(count)
}

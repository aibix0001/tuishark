use anyhow::{Context, Result};
use pcap::{Capture, Linktype};
use std::path::Path;

use crate::store::packet_store::PacketStore;

/// Save all packets from the store to a pcap file.
/// Returns the number of packets written.
pub fn save_pcap(path: &Path, store: &PacketStore) -> Result<usize> {
    let cap = Capture::dead(Linktype::ETHERNET)
        .context("failed to create dead capture handle")?;
    let mut savefile = cap
        .savefile(path)
        .with_context(|| format!("failed to create pcap file: {}", path.display()))?;

    let base_ts = store.first_absolute_ts();
    let mut count = 0;

    for i in 0..store.len() {
        let Some(summary) = store.get(i) else {
            continue;
        };
        let Some(raw) = store.get_raw(i) else {
            continue;
        };

        let absolute_ts = base_ts + summary.timestamp;
        let tv_sec = absolute_ts as i64;
        let tv_usec = ((absolute_ts - tv_sec as f64) * 1_000_000.0) as i64;

        let header = pcap::PacketHeader {
            ts: libc::timeval {
                tv_sec: tv_sec as libc::time_t,
                tv_usec: tv_usec as libc::suseconds_t,
            },
            caplen: raw.len() as u32,
            len: raw.len() as u32,
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

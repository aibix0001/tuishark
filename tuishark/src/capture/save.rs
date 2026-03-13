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
        let tv_sec = absolute_ts.floor() as libc::time_t;
        let frac = (absolute_ts - tv_sec as f64) * 1_000_000.0;
        // Clamp to valid pcap range [0, 999_999].
        // Cast directly to suseconds_t for portability (i32 on some FreeBSD arches).
        let tv_usec = (frac.round() as libc::suseconds_t).clamp(0, 999_999);

        let header = pcap::PacketHeader {
            ts: libc::timeval { tv_sec, tv_usec },
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::model::LinkType;
    use crate::dissect::fast::parse_packet_with_wire_len;

    fn make_eth_tcp_packet() -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet header (14 bytes)
        pkt.extend_from_slice(&[0x00; 6]); // dst mac
        pkt.extend_from_slice(&[0x01; 6]); // src mac
        pkt.extend_from_slice(&[0x08, 0x00]); // IPv4
        // IPv4 header (20 bytes)
        pkt.push(0x45); // version + IHL
        pkt.push(0x00);
        pkt.extend_from_slice(&40u16.to_be_bytes()); // total length
        pkt.extend_from_slice(&[0x00, 0x01]); // id
        pkt.extend_from_slice(&[0x40, 0x00]); // flags
        pkt.push(64); // TTL
        pkt.push(6); // TCP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&[192, 168, 1, 10]); // src
        pkt.extend_from_slice(&[10, 0, 0, 1]); // dst
        // TCP header (20 bytes)
        pkt.extend_from_slice(&8080u16.to_be_bytes());
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(&1000u32.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.push(0x50);
        pkt.push(0x02); // SYN
        pkt.extend_from_slice(&65535u16.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt
    }

    #[test]
    fn save_empty_store_fails() {
        let store = PacketStore::default();
        let dir = std::env::temp_dir();
        let path = dir.join("tuishark-test-empty.pcap");
        assert!(save_pcap(&path, &store).is_err());
    }

    #[test]
    fn save_no_base_ts_fails() {
        let raw = make_eth_tcp_packet();
        let summary = parse_packet_with_wire_len(0, 0.0, &raw, raw.len(), LinkType::Ethernet);
        let mut store = PacketStore::default();
        store.add(summary, raw);
        // No set_first_absolute_ts — should fail
        let dir = std::env::temp_dir();
        let path = dir.join("tuishark-test-nots.pcap");
        assert!(save_pcap(&path, &store).is_err());
    }

    #[test]
    fn save_and_reload_roundtrip() {
        let raw = make_eth_tcp_packet();
        let wire_len = raw.len();
        let base_ts = 1710000000.123456_f64;
        let pkt_ts = 0.5_f64; // relative to base

        let summary = parse_packet_with_wire_len(0, pkt_ts, &raw, wire_len, LinkType::Ethernet);
        let mut store = PacketStore::default();
        store.set_first_absolute_ts(base_ts);
        store.add(summary, raw.clone());

        let dir = std::env::temp_dir();
        let path = dir.join(format!("tuishark-test-roundtrip-{}.pcap", std::process::id()));
        let count = save_pcap(&path, &store).expect("save should succeed");
        assert_eq!(count, 1);

        // Re-read the file with pcap crate
        let mut cap = Capture::from_file(&path).expect("should open saved pcap");
        let reloaded = cap.next_packet().expect("should have one packet");

        // Verify raw data preserved
        assert_eq!(reloaded.data, raw.as_slice());
        assert_eq!(reloaded.header.caplen, wire_len as u32);
        assert_eq!(reloaded.header.len, wire_len as u32);

        // Verify timestamp (base_ts + pkt_ts = 1710000000.623456)
        let expected_sec = (base_ts + pkt_ts).floor() as i64;
        let expected_usec = (((base_ts + pkt_ts) - expected_sec as f64) * 1_000_000.0).round() as i64;
        assert_eq!(reloaded.header.ts.tv_sec as i64, expected_sec);
        assert_eq!(reloaded.header.ts.tv_usec as i64, expected_usec);

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn save_multiple_packets_roundtrip() {
        let raw = make_eth_tcp_packet();
        let base_ts = 1710000000.0_f64;

        let mut store = PacketStore::default();
        store.set_first_absolute_ts(base_ts);
        for i in 0..5 {
            let ts = i as f64 * 0.1;
            let summary = parse_packet_with_wire_len(i, ts, &raw, raw.len(), LinkType::Ethernet);
            store.add(summary, raw.clone());
        }

        let dir = std::env::temp_dir();
        let path = dir.join(format!("tuishark-test-multi-{}.pcap", std::process::id()));
        let count = save_pcap(&path, &store).expect("save should succeed");
        assert_eq!(count, 5);

        // Verify all packets can be read back
        let mut cap = Capture::from_file(&path).expect("should open saved pcap");
        let mut loaded = 0;
        while cap.next_packet().is_ok() {
            loaded += 1;
        }
        assert_eq!(loaded, 5);

        let _ = std::fs::remove_file(&path);
    }
}

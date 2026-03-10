use std::io::Write;

use anyhow::Result;

use crate::dissect::model::PacketSummary;
use crate::store::packet_store::PacketStore;

/// Write packets as a human-readable fixed-width text table.
/// Single-pass: computes duration while writing rows.
pub fn export_text<W: Write>(
    writer: &mut W,
    store: &PacketStore,
    indices: Option<&[usize]>,
    file_path: Option<&str>,
    filtered: bool,
    first_absolute_ts: Option<f64>,
) -> Result<usize> {
    // Header metadata
    writeln!(writer, "TuiShark Packet Export")?;
    writeln!(writer, "=====================")?;
    if let Some(path) = file_path {
        writeln!(writer, "Source: {path}")?;
    }

    let total = store.len();
    let export_count = indices.map_or(total, |idx| idx.len());
    if filtered {
        writeln!(writer, "Packets: {export_count} of {total} (filtered)")?;
    } else {
        writeln!(writer, "Packets: {export_count}")?;
    }

    if let Some(ts) = first_absolute_ts {
        writeln!(writer, "Capture start: {}", super::csv::format_epoch_iso8601(ts))?;
    }

    writeln!(writer)?;

    // Column headers (45-char wide for IPv6 addresses)
    writeln!(
        writer,
        "{:>6}  {:>12}  {:<45}  {:<45}  {:<10}  {:>6}  {}",
        "No", "Time", "Source", "Destination", "Protocol", "Length", "Info"
    )?;
    writeln!(
        writer,
        "{:->6}  {:->12}  {:->45}  {:->45}  {:->10}  {:->6}  {:->30}",
        "", "", "", "", "", "", ""
    )?;

    let mut count = 0;
    let mut first_ts = None;
    let mut last_ts = 0.0_f64;

    for pkt in store.iter_packets(indices) {
        if first_ts.is_none() {
            first_ts = Some(pkt.timestamp);
        }
        last_ts = pkt.timestamp;
        write_text_row(writer, pkt)?;
        count += 1;
    }

    // Footer with duration
    if let Some(ft) = first_ts {
        let duration = last_ts - ft;
        writeln!(writer)?;
        writeln!(writer, "Duration: {duration:.3}s ({count} packets)")?;
    }

    writer.flush()?;
    Ok(count)
}

fn write_text_row<W: Write>(writer: &mut W, pkt: &PacketSummary) -> Result<()> {
    writeln!(
        writer,
        "{:>6}  {:>12.6}  {:<45}  {:<45}  {:<10}  {:>6}  {}",
        pkt.index + 1,
        pkt.timestamp,
        &pkt.source,
        &pkt.destination,
        pkt.protocol,
        pkt.original_length,
        pkt.info,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::model::Protocol;

    fn make_store(n: usize) -> PacketStore {
        let mut store = PacketStore::default();
        for i in 0..n {
            let pkt = PacketSummary {
                index: i,
                timestamp: i as f64 * 1.5,
                source: "192.168.1.100".into(),
                destination: "10.0.0.1".into(),
                protocol: Protocol::Tcp,
                length: 1500,
                original_length: 1500,
                info: format!("TCP segment #{i}"),
                src_port: Some(54321),
                dst_port: Some(443),
            };
            store.add(pkt, vec![0u8; 1500]);
        }
        store
    }

    #[test]
    fn text_has_header_and_rows() {
        let store = make_store(3);
        let mut buf = Vec::new();
        let count = export_text(&mut buf, &store, None, Some("test.pcap"), false, None).unwrap();
        assert_eq!(count, 3);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("TuiShark Packet Export"));
        assert!(output.contains("Source: test.pcap"));
        assert!(output.contains("Packets: 3"));
        assert!(output.contains("Duration:"));
        // Column headers
        assert!(output.contains("No"));
        assert!(output.contains("Protocol"));
        // Data rows
        assert!(output.contains("192.168.1.100"));
    }

    #[test]
    fn text_filtered_header() {
        let store = make_store(5);
        let indices = vec![1, 3];
        let mut buf = Vec::new();
        export_text(&mut buf, &store, Some(&indices), None, true, None).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("2 of 5 (filtered)"));
    }

    #[test]
    fn text_empty_store() {
        let store = PacketStore::default();
        let mut buf = Vec::new();
        let count = export_text(&mut buf, &store, None, None, false, None).unwrap();
        assert_eq!(count, 0);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Packets: 0"));
    }

    #[test]
    fn text_ipv6_addresses_not_truncated() {
        let mut store = PacketStore::default();
        let pkt = PacketSummary {
            index: 0,
            timestamp: 0.0,
            source: "2001:0db8:85a3:0000:0000:8a2e:0370:7334".into(),
            destination: "fe80::1".into(),
            protocol: Protocol::Tcp,
            length: 64,
            original_length: 64,
            info: "TCP SYN".into(),
            src_port: Some(443),
            dst_port: Some(80),
        };
        store.add(pkt, vec![0u8; 64]);
        let mut buf = Vec::new();
        export_text(&mut buf, &store, None, None, false, None).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // Full IPv6 address should be present (45-char column)
        assert!(output.contains("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
    }

    #[test]
    fn text_absolute_timestamp_in_header() {
        let store = make_store(1);
        let mut buf = Vec::new();
        let base_ts = 1773144000.0;
        export_text(&mut buf, &store, None, None, false, Some(base_ts)).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Capture start: 2026-03-10T12:00:00"));
    }
}

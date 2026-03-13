use std::borrow::Cow;
use std::io::Write;

use anyhow::Result;

use crate::dissect::model::PacketSummary;
use crate::store::packet_store::PacketStore;

/// Write packets as RFC 4180 CSV.
pub fn export_csv<W: Write>(
    writer: &mut W,
    store: &PacketStore,
    indices: Option<&[usize]>,
    first_absolute_ts: Option<f64>,
) -> Result<usize> {
    writeln!(
        writer,
        "\"No.\",\"Time\",\"Absolute Time\",\"Source\",\"Destination\",\"Protocol\",\"Length\",\"SrcPort\",\"DstPort\",\"Info\""
    )?;

    let mut count = 0;
    for pkt in store.iter_packets(indices) {
        write_csv_row(writer, pkt, first_absolute_ts)?;
        count += 1;
    }

    writer.flush()?;
    Ok(count)
}

fn write_csv_row<W: Write>(
    writer: &mut W,
    pkt: &PacketSummary,
    first_absolute_ts: Option<f64>,
) -> Result<()> {
    let abs_ts = first_absolute_ts.map(|base| base + pkt.timestamp);
    let abs_ts_str = match abs_ts {
        Some(ts) => format_epoch_iso8601(ts),
        None => String::new(),
    };
    let src_port = pkt
        .src_port
        .map(|p| p.to_string())
        .unwrap_or_default();
    let dst_port = pkt
        .dst_port
        .map(|p| p.to_string())
        .unwrap_or_default();

    writeln!(
        writer,
        "{},{:.6},{},{},{},{},{},{},{},{}",
        pkt.index + 1,
        pkt.timestamp,
        csv_escape(&abs_ts_str),
        csv_escape(&pkt.source),
        csv_escape(&pkt.destination),
        csv_escape(&pkt.protocol.to_string()),
        pkt.original_length,
        src_port,
        dst_port,
        csv_escape(&pkt.info),
    )?;
    Ok(())
}

/// RFC 4180: quote fields containing commas, quotes, or newlines.
/// Returns a borrowed reference when no escaping is needed (zero-alloc fast path).
fn csv_escape(s: &str) -> Cow<'_, str> {
    if s.contains('"') || s.contains(',') || s.contains('\n') || s.contains('\r') {
        Cow::Owned(format!("\"{}\"", s.replace('"', "\"\"")))
    } else {
        Cow::Borrowed(s)
    }
}

/// Format an epoch timestamp as ISO 8601 (UTC).
pub(crate) fn format_epoch_iso8601(epoch: f64) -> String {
    let secs = epoch.floor() as u64;
    let micros = ((epoch - epoch.floor()) * 1_000_000.0).round() as u64;
    let days = secs / 86400;
    let day_secs = secs % 86400;
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;
    let (year, month, day) = super::epoch_days_to_date(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}.{micros:06}Z")
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
                timestamp: i as f64 * 0.001,
                source: "10.0.0.1".into(),
                destination: "10.0.0.2".into(),
                protocol: Protocol::Tcp,
                length: 64,
                original_length: 64,
                info: format!("Seq={i}"),
                src_port: Some(12345),
                dst_port: Some(80),
                link_meta: None,
            };
            store.add(pkt, vec![0u8; 64]);
        }
        store
    }

    #[test]
    fn csv_header_and_rows() {
        let store = make_store(3);
        let mut buf = Vec::new();
        let count = export_csv(&mut buf, &store, None, None).unwrap();
        assert_eq!(count, 3);
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 4); // header + 3 rows
        assert!(lines[0].starts_with("\"No.\""));
        assert!(lines[1].starts_with("1,"));
        // Verify ports are present
        assert!(output.contains("12345"));
        assert!(output.contains(",80,"));
    }

    #[test]
    fn csv_filtered() {
        let store = make_store(5);
        let indices = vec![1, 3];
        let mut buf = Vec::new();
        let count = export_csv(&mut buf, &store, Some(&indices), None).unwrap();
        assert_eq!(count, 2);
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 3); // header + 2 rows
    }

    #[test]
    fn csv_escape_special_chars() {
        assert_eq!(csv_escape("hello"), Cow::Borrowed("hello"));
        assert_eq!(csv_escape("hello,world").as_ref(), "\"hello,world\"");
        assert_eq!(csv_escape("say \"hi\"").as_ref(), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_escape("line\nnew").as_ref(), "\"line\nnew\"");
    }

    #[test]
    fn csv_with_special_info() {
        let mut store = PacketStore::default();
        let pkt = PacketSummary {
            index: 0,
            timestamp: 0.0,
            source: "10.0.0.1".into(),
            destination: "10.0.0.2".into(),
            protocol: Protocol::Http,
            length: 100,
            original_length: 100,
            info: "GET /path?a=1,b=2 HTTP/1.1".into(),
            src_port: Some(8080),
            dst_port: Some(80),
            link_meta: None,
        };
        store.add(pkt, vec![0u8; 100]);
        let mut buf = Vec::new();
        export_csv(&mut buf, &store, None, None).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // Info field with comma should be quoted
        assert!(output.contains("\"GET /path?a=1,b=2 HTTP/1.1\""));
    }

    #[test]
    fn csv_absolute_timestamp() {
        let store = make_store(1);
        let mut buf = Vec::new();
        // Epoch for 2026-03-10 12:00:00 UTC
        let base_ts = 1773144000.0;
        export_csv(&mut buf, &store, None, Some(base_ts)).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("2026-03-10T12:00:00"));
    }

    #[test]
    fn csv_empty_store() {
        let store = PacketStore::default();
        let mut buf = Vec::new();
        let count = export_csv(&mut buf, &store, None, None).unwrap();
        assert_eq!(count, 0);
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 1); // header only
    }

    #[test]
    fn csv_no_port_packet() {
        let mut store = PacketStore::default();
        let pkt = PacketSummary {
            index: 0,
            timestamp: 0.0,
            source: "10.0.0.1".into(),
            destination: "10.0.0.2".into(),
            protocol: Protocol::Icmp,
            length: 64,
            original_length: 64,
            info: "Echo request".into(),
            src_port: None,
            dst_port: None,
            link_meta: None,
        };
        store.add(pkt, vec![0u8; 64]);
        let mut buf = Vec::new();
        export_csv(&mut buf, &store, None, None).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // Empty port fields
        assert!(output.contains(",,Echo request"));
    }
}

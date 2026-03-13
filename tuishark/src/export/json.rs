use std::io::Write;

use anyhow::Result;
use serde::Serialize;

use crate::dissect::model::PacketSummary;
use crate::store::packet_store::PacketStore;

#[derive(Serialize)]
struct ExportPacket {
    index: usize,
    timestamp: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    absolute_time: Option<String>,
    source: String,
    destination: String,
    protocol: String,
    length: usize,
    info: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    src_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dst_port: Option<u16>,
}

impl ExportPacket {
    fn from_summary(pkt: &PacketSummary, first_absolute_ts: Option<f64>) -> Self {
        let absolute_time = first_absolute_ts.map(|base| {
            let epoch = base + pkt.timestamp;
            super::csv::format_epoch_iso8601(epoch)
        });
        Self {
            index: pkt.index + 1,
            timestamp: pkt.timestamp,
            absolute_time,
            source: pkt.source.clone(),
            destination: pkt.destination.clone(),
            protocol: pkt.protocol.to_string(),
            length: pkt.original_length,
            info: pkt.info.clone(),
            src_port: pkt.src_port,
            dst_port: pkt.dst_port,
        }
    }
}

/// Write packets as a streaming JSON array (one packet at a time to avoid memory spikes).
pub fn export_json<W: Write>(
    writer: &mut W,
    store: &PacketStore,
    indices: Option<&[usize]>,
    first_absolute_ts: Option<f64>,
) -> Result<usize> {
    let mut count = 0;
    writeln!(writer, "[")?;

    for pkt in store.iter_packets(indices) {
        if count > 0 {
            writeln!(writer, ",")?;
        }
        let export_pkt = ExportPacket::from_summary(pkt, first_absolute_ts);
        serde_json::to_writer_pretty(&mut *writer, &export_pkt)?;
        count += 1;
    }

    if count > 0 {
        writeln!(writer)?;
    }
    writeln!(writer, "]")?;
    writer.flush()?;
    Ok(count)
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
    fn json_output_valid() {
        let store = make_store(3);
        let mut buf = Vec::new();
        let count = export_json(&mut buf, &store, None, None).unwrap();
        assert_eq!(count, 3);
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 3);
    }

    #[test]
    fn json_packet_fields() {
        let store = make_store(1);
        let mut buf = Vec::new();
        export_json(&mut buf, &store, None, None).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let pkt = &parsed[0];
        assert_eq!(pkt["index"], 1);
        assert_eq!(pkt["protocol"], "TCP");
        assert_eq!(pkt["source"], "10.0.0.1");
        assert_eq!(pkt["src_port"], 12345);
    }

    #[test]
    fn json_filtered() {
        let store = make_store(5);
        let indices = vec![0, 2, 4];
        let mut buf = Vec::new();
        let count = export_json(&mut buf, &store, Some(&indices), None).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn json_empty_store() {
        let store = PacketStore::default();
        let mut buf = Vec::new();
        let count = export_json(&mut buf, &store, None, None).unwrap();
        assert_eq!(count, 0);
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 0);
    }

    #[test]
    fn json_absolute_timestamp() {
        let store = make_store(1);
        let mut buf = Vec::new();
        let base_ts = 1773144000.0; // 2026-03-10 12:00:00 UTC
        export_json(&mut buf, &store, None, Some(base_ts)).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let abs = parsed[0]["absolute_time"].as_str().unwrap();
        assert!(abs.starts_with("2026-03-10T12:00:00"));
        assert!(abs.ends_with("Z"));
    }
}

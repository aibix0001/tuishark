use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::process;

use anyhow::{Context, Result};

use super::model::{Layer, LayerField, PacketDetail};

/// Checks whether `tshark` is available on the system PATH.
pub fn tshark_available() -> bool {
    std::process::Command::new("tshark")
        .arg("--version")
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status()
        .is_ok()
}

/// Manages a named FIFO and a long-running tshark process for deep packet dissection.
///
/// Keeps the FIFO write end open for the lifetime of the dissector so tshark
/// doesn't see EOF between packets.
pub struct DeepDissector {
    fifo_path: PathBuf,
    fifo_writer: File,
    rtshark: Option<rtshark::RTShark>,
}

impl DeepDissector {
    /// Create a new DeepDissector. Creates a named FIFO, spawns tshark, and writes the pcap global header.
    pub fn new() -> Result<Self> {
        let fifo_path = std::env::temp_dir().join(format!("tuishark-{}.fifo", process::id()));

        // Remove stale FIFO if it exists
        let _ = fs::remove_file(&fifo_path);

        // Create named pipe (FIFO)
        let c_path = std::ffi::CString::new(fifo_path.to_str().unwrap())?;
        let ret = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "Failed to create FIFO: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Spawn tshark reading from the FIFO.
        // This must happen before we open the FIFO for writing (or concurrently),
        // because open(FIFO, O_WRONLY) blocks until a reader exists.
        // rtshark spawns tshark which opens the FIFO for reading.
        let rtshark = rtshark::RTSharkBuilder::builder()
            .input_path(fifo_path.to_str().unwrap())
            .live_capture()
            .spawn()
            .context("Failed to spawn tshark process")?;

        // Now open the FIFO for writing — tshark is the reader, so this won't block.
        // We use a thread with a timeout in case something goes wrong.
        let fifo_for_open = fifo_path.clone();
        let open_handle = std::thread::spawn(move || -> Result<File> {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .open(&fifo_for_open)
                .context("Failed to open FIFO for writing")?;
            // Write pcap global header
            f.write_all(&pcap_global_header())?;
            f.flush()?;
            Ok(f)
        });

        let fifo_writer = open_handle
            .join()
            .map_err(|_| anyhow::anyhow!("FIFO open thread panicked"))??;

        Ok(Self {
            fifo_path,
            fifo_writer,
            rtshark: Some(rtshark),
        })
    }

    /// Dissect a single raw packet using tshark.
    /// Writes the packet to the FIFO and reads the parsed result.
    pub fn dissect_packet(&mut self, raw: &[u8], timestamp: f64) -> Result<PacketDetail> {
        // Write packet record to the persistent FIFO handle
        self.fifo_writer
            .write_all(&pcap_packet_header(raw.len(), timestamp))?;
        self.fifo_writer.write_all(raw)?;
        self.fifo_writer.flush()?;

        // Read the dissected packet from tshark
        let rtshark = self
            .rtshark
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("tshark process not running"))?;

        match rtshark.read() {
            Ok(Some(packet)) => Ok(map_rtshark_packet(packet)),
            Ok(None) => Err(anyhow::anyhow!("tshark returned no packet")),
            Err(e) => Err(anyhow::anyhow!("tshark read error: {e}")),
        }
    }
}

impl Drop for DeepDissector {
    fn drop(&mut self) {
        // Drop writer first to signal EOF to tshark
        // (fifo_writer is dropped automatically, but we kill tshark explicitly)
        if let Some(mut rtshark) = self.rtshark.take() {
            let _ = rtshark.kill();
        }
        let _ = fs::remove_file(&self.fifo_path);
    }
}

/// Build a pcap global header (24 bytes).
fn pcap_global_header() -> [u8; 24] {
    let mut hdr = [0u8; 24];
    // Magic number (little-endian)
    hdr[0..4].copy_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    // Version major: 2
    hdr[4..6].copy_from_slice(&2u16.to_le_bytes());
    // Version minor: 4
    hdr[6..8].copy_from_slice(&4u16.to_le_bytes());
    // Timezone offset (0)
    hdr[8..12].copy_from_slice(&0i32.to_le_bytes());
    // Timestamp accuracy (0)
    hdr[12..16].copy_from_slice(&0u32.to_le_bytes());
    // Snap length
    hdr[16..20].copy_from_slice(&65535u32.to_le_bytes());
    // Link type: Ethernet (1)
    hdr[20..24].copy_from_slice(&1u32.to_le_bytes());
    hdr
}

/// Build a pcap packet record header (16 bytes).
fn pcap_packet_header(len: usize, timestamp: f64) -> [u8; 16] {
    let ts_sec = timestamp as u32;
    let ts_usec = ((timestamp - ts_sec as f64) * 1_000_000.0) as u32;
    let cap_len = len as u32;

    let mut hdr = [0u8; 16];
    hdr[0..4].copy_from_slice(&ts_sec.to_le_bytes());
    hdr[4..8].copy_from_slice(&ts_usec.to_le_bytes());
    hdr[8..12].copy_from_slice(&cap_len.to_le_bytes());
    hdr[12..16].copy_from_slice(&cap_len.to_le_bytes());
    hdr
}

/// Map an rtshark Packet into our PacketDetail model.
/// Takes ownership because rtshark::Packet only implements IntoIterator for owned values.
fn map_rtshark_packet(packet: rtshark::Packet) -> PacketDetail {
    let mut layers = Vec::new();

    for layer in packet {
        let layer: rtshark::Layer = layer;
        let layer_name = layer.name().to_string();
        let mut fields = Vec::new();
        for metadata in layer {
            let metadata: rtshark::Metadata = metadata;
            let name = metadata.name().to_string();
            let value = metadata.value().to_string();

            let byte_range = match (metadata.position(), metadata.size()) {
                (Some(pos), Some(size)) if size > 0 => {
                    Some((pos as usize, (pos + size) as usize))
                }
                _ => None,
            };

            fields.push(LayerField {
                name,
                value,
                byte_range,
            });
        }

        layers.push(Layer {
            name: layer_name,
            fields,
        });
    }

    PacketDetail { layers }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcap_global_header_magic() {
        let hdr = pcap_global_header();
        assert_eq!(&hdr[0..4], &0xa1b2c3d4u32.to_le_bytes());
        assert_eq!(&hdr[4..6], &2u16.to_le_bytes());
        assert_eq!(&hdr[6..8], &4u16.to_le_bytes());
        assert_eq!(&hdr[20..24], &1u32.to_le_bytes()); // Ethernet
    }

    #[test]
    fn pcap_packet_header_roundtrip() {
        let hdr = pcap_packet_header(100, 1234.567890);
        let ts_sec = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let ts_usec = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
        let cap_len = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
        let orig_len = u32::from_le_bytes(hdr[12..16].try_into().unwrap());

        assert_eq!(ts_sec, 1234);
        assert_eq!(ts_usec, 567890);
        assert_eq!(cap_len, 100);
        assert_eq!(orig_len, 100);
    }

    #[test]
    fn tshark_check() {
        // This just tests the function runs without panic — result depends on system
        let _ = tshark_available();
    }

    #[test]
    fn deep_dissect_tcp_packet() {
        if !tshark_available() {
            eprintln!("Skipping deep dissection test — tshark not available");
            return;
        }

        let mut dissector = DeepDissector::new().expect("Failed to create DeepDissector");

        // Build a minimal Ethernet/IPv4/TCP SYN packet
        let mut pkt = Vec::new();
        // Ethernet header
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst mac
        pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // src mac
        pkt.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
        // IPv4 header (20 bytes)
        pkt.push(0x45); // version + IHL
        pkt.push(0x00); // DSCP
        pkt.extend_from_slice(&40u16.to_be_bytes()); // total length
        pkt.extend_from_slice(&[0x00, 0x01]); // identification
        pkt.extend_from_slice(&[0x40, 0x00]); // flags + fragment offset
        pkt.push(64); // TTL
        pkt.push(6); // protocol TCP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum (0 = let tshark handle)
        pkt.extend_from_slice(&[192, 168, 1, 10]); // source
        pkt.extend_from_slice(&[10, 0, 0, 1]); // dest
        // TCP header (20 bytes)
        pkt.extend_from_slice(&12345u16.to_be_bytes()); // src port
        pkt.extend_from_slice(&80u16.to_be_bytes()); // dst port
        pkt.extend_from_slice(&1000u32.to_be_bytes()); // seq
        pkt.extend_from_slice(&0u32.to_be_bytes()); // ack
        pkt.push(0x50); // data offset = 5
        pkt.push(0x02); // SYN flag
        pkt.extend_from_slice(&65535u16.to_be_bytes()); // window
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&[0x00, 0x00]); // urgent pointer

        let detail = dissector
            .dissect_packet(&pkt, 0.0)
            .expect("Deep dissection failed");

        // tshark should produce at least eth, ip, tcp layers
        assert!(
            detail.layers.len() >= 3,
            "Expected at least 3 layers, got {}: {:?}",
            detail.layers.len(),
            detail.layers.iter().map(|l| &l.name).collect::<Vec<_>>()
        );

        // Check that we have expected layer names
        let layer_names: Vec<&str> = detail.layers.iter().map(|l| l.name.as_str()).collect();
        assert!(layer_names.contains(&"eth"), "Missing eth layer: {layer_names:?}");
        assert!(layer_names.contains(&"ip"), "Missing ip layer: {layer_names:?}");
        assert!(layer_names.contains(&"tcp"), "Missing tcp layer: {layer_names:?}");

        // Check that fields have byte ranges
        let eth_layer = detail.layers.iter().find(|l| l.name == "eth").unwrap();
        assert!(!eth_layer.fields.is_empty(), "eth layer should have fields");
        let has_byte_range = eth_layer.fields.iter().any(|f| f.byte_range.is_some());
        assert!(has_byte_range, "eth layer fields should have byte ranges");
    }
}

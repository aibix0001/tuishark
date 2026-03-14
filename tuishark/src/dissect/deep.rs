use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicUsize, Ordering};
use anyhow::{Context, Result};

use super::model::{Layer, LayerField, PacketDetail};

/// Default pcap linktype for Ethernet (DLT_EN10MB).
#[allow(dead_code)]
pub const LINKTYPE_ETHERNET: u32 = 1;

/// Default snap length matching tcpdump/Wireshark convention.
const SNAPLEN: u32 = 262144;

/// Checks whether `tshark` is available on the system PATH.
#[must_use]
pub fn tshark_available() -> bool {
    std::process::Command::new("tshark")
        .arg("--version")
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status()
        .is_ok()
}

/// Global request counter for correlating deep dissection requests with results.
/// Monotonically increasing; used to discard stale results.
static REQUEST_SEQ: AtomicUsize = AtomicUsize::new(0);

/// Get the next unique request sequence number.
pub fn next_request_seq() -> usize {
    REQUEST_SEQ.fetch_add(1, Ordering::Relaxed)
}

/// Manages a named FIFO and a long-running tshark process for deep packet dissection.
///
/// Keeps the FIFO write end open for the lifetime of the dissector so tshark
/// doesn't see EOF between packets.
pub struct DeepDissector {
    fifo_path: PathBuf,
    fifo_writer: Option<File>,
    rtshark: Option<rtshark::RTShark>,
    frame_counter: usize,
    #[allow(dead_code)] // stored for future non-Ethernet linktype support
    linktype: u32,
}

impl DeepDissector {
    /// Create a new DeepDissector with the given pcap linktype.
    /// Use `LINKTYPE_ETHERNET` (1) for standard Ethernet captures.
    pub fn new(linktype: u32) -> Result<Self> {
        let fifo_path = std::env::temp_dir().join(format!("tuishark-{}.fifo", process::id()));

        // Remove stale FIFO if it exists
        let _ = fs::remove_file(&fifo_path);

        // Create named pipe (FIFO)
        let fifo_str = fifo_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("FIFO path is not valid UTF-8: {:?}", fifo_path))?;
        let c_path = std::ffi::CString::new(fifo_str)?;
        // SAFETY: `c_path` is a valid null-terminated C string (guaranteed by CString::new
        // which rejects interior null bytes). Mode 0o600 is a valid permission mask.
        let ret = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "Failed to create FIFO: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Spawn tshark reading from the FIFO.
        // This must happen before we open the FIFO for writing,
        // because open(FIFO, O_WRONLY) blocks until a reader exists.
        let fifo_str_owned = fifo_str.to_string();
        let rtshark = rtshark::RTSharkBuilder::builder()
            .input_path(&fifo_str_owned)
            .live_capture()
            .spawn()
            .context("Failed to spawn tshark process")?;

        // Open the FIFO for writing with a timeout.
        // If tshark fails to start and never opens the read end, open() blocks forever.
        // We use a thread + channel with recv_timeout to prevent a permanent hang.
        let fifo_for_open = fifo_path.clone();
        let lt = linktype;
        let (open_tx, open_rx) = std::sync::mpsc::channel::<Result<File>>();
        std::thread::spawn(move || {
            let result = (|| -> Result<File> {
                let mut f = fs::OpenOptions::new()
                    .write(true)
                    .open(&fifo_for_open)
                    .context("Failed to open FIFO for writing")?;
                f.write_all(&pcap_global_header(lt))?;
                f.flush()?;
                Ok(f)
            })();
            let _ = open_tx.send(result);
        });

        let fifo_writer = open_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| anyhow::anyhow!("Timeout opening FIFO — tshark may have failed to start"))??;

        // Verify tshark is actually running by giving it a moment
        std::thread::sleep(std::time::Duration::from_millis(50));

        Ok(Self {
            fifo_path,
            fifo_writer: Some(fifo_writer),
            rtshark: Some(rtshark),
            frame_counter: 0,
            linktype,
        })
    }

    /// Create a new DeepDissector with the default Ethernet linktype.
    #[allow(dead_code)]
    pub fn new_ethernet() -> Result<Self> {
        Self::new(LINKTYPE_ETHERNET)
    }

    /// Dissect a single raw packet using tshark.
    /// Writes the packet to the FIFO and reads the parsed result.
    pub fn dissect_packet(&mut self, raw: &[u8], timestamp: f64) -> Result<PacketDetail> {
        let writer = self
            .fifo_writer
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("FIFO writer not available"))?;

        // Write packet record to the persistent FIFO handle
        writer.write_all(&pcap_packet_header(raw.len(), timestamp)?)?;
        writer.write_all(raw)?;
        writer.flush()?;

        self.frame_counter += 1;

        // Read the dissected packet from tshark
        let rtshark = self
            .rtshark
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("tshark process not running"))?;

        match rtshark.read() {
            Ok(Some(packet)) => Ok(map_rtshark_packet(packet)),
            Ok(None) => Err(anyhow::anyhow!(
                "tshark returned no packet (frame {})",
                self.frame_counter
            )),
            Err(e) => Err(anyhow::anyhow!(
                "tshark read error on frame {}: {e}",
                self.frame_counter
            )),
        }
    }
}

impl Drop for DeepDissector {
    fn drop(&mut self) {
        // Drop writer first to signal EOF to tshark
        drop(self.fifo_writer.take());
        // Then kill tshark
        if let Some(mut rtshark) = self.rtshark.take() {
            let _ = rtshark.kill();
        }
        let _ = fs::remove_file(&self.fifo_path);
    }
}

/// Build a pcap global header (24 bytes) with the given linktype.
fn pcap_global_header(linktype: u32) -> [u8; 24] {
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
    // Snap length (262144 — tcpdump/Wireshark default)
    hdr[16..20].copy_from_slice(&SNAPLEN.to_le_bytes());
    // Link type
    hdr[20..24].copy_from_slice(&linktype.to_le_bytes());
    hdr
}

/// Build a pcap packet record header (16 bytes).
/// Returns an error if the timestamp is negative or the length exceeds u32.
fn pcap_packet_header(len: usize, timestamp: f64) -> Result<[u8; 16]> {
    if timestamp < 0.0 {
        anyhow::bail!("negative timestamp ({timestamp}) cannot be encoded in pcap format");
    }
    let ts_sec = if timestamp > u32::MAX as f64 {
        u32::MAX // saturate rather than wrap
    } else {
        timestamp as u32
    };
    let ts_usec = ((timestamp - ts_sec as f64) * 1_000_000.0).max(0.0) as u32;
    let cap_len = u32::try_from(len).context("packet length exceeds u32")?;

    let mut hdr = [0u8; 16];
    hdr[0..4].copy_from_slice(&ts_sec.to_le_bytes());
    hdr[4..8].copy_from_slice(&ts_usec.to_le_bytes());
    hdr[8..12].copy_from_slice(&cap_len.to_le_bytes());
    hdr[12..16].copy_from_slice(&cap_len.to_le_bytes());
    Ok(hdr)
}

/// Map an rtshark Packet into our PacketDetail model.
/// Takes ownership because rtshark::Packet only implements IntoIterator for owned values.
fn map_rtshark_packet(packet: rtshark::Packet) -> PacketDetail {
    let mut layers = Vec::new();

    for layer in packet {
        let raw_name = layer.name().to_string();
        let mut fields = Vec::new();
        for metadata in layer {
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

        let layer_name = build_descriptive_layer_name(&raw_name, &fields);

        layers.push(Layer {
            name: layer_name,
            fields,
        });
    }

    PacketDetail { layers }
}

/// Build a descriptive layer name from tshark fields, matching the style
/// used by fast dissection (e.g. "IPv4, Src: 1.2.3.4, Dst: 5.6.7.8").
fn build_descriptive_layer_name(raw_name: &str, fields: &[LayerField]) -> String {
    /// Look up a field value by its tshark field name.
    fn field_val<'a>(fields: &'a [LayerField], name: &str) -> Option<&'a str> {
        fields
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.value.as_str())
    }

    match raw_name {
        "eth" => {
            if let (Some(src), Some(dst)) =
                (field_val(fields, "eth.src"), field_val(fields, "eth.dst"))
            {
                format!("Ethernet II, Src: {src}, Dst: {dst}")
            } else {
                "Ethernet II".into()
            }
        }
        "ip" => {
            if let (Some(src), Some(dst)) =
                (field_val(fields, "ip.src"), field_val(fields, "ip.dst"))
            {
                format!("IPv4, Src: {src}, Dst: {dst}")
            } else {
                "IPv4".into()
            }
        }
        "ipv6" => {
            if let (Some(src), Some(dst)) =
                (field_val(fields, "ipv6.src"), field_val(fields, "ipv6.dst"))
            {
                format!("IPv6, Src: {src}, Dst: {dst}")
            } else {
                "IPv6".into()
            }
        }
        "tcp" => {
            if let (Some(src), Some(dst)) = (
                field_val(fields, "tcp.srcport"),
                field_val(fields, "tcp.dstport"),
            ) {
                format!("TCP, Src Port: {src}, Dst Port: {dst}")
            } else {
                "TCP".into()
            }
        }
        "udp" => {
            if let (Some(src), Some(dst)) = (
                field_val(fields, "udp.srcport"),
                field_val(fields, "udp.dstport"),
            ) {
                format!("UDP, Src Port: {src}, Dst Port: {dst}")
            } else {
                "UDP".into()
            }
        }
        "arp" => "ARP".into(),
        "icmp" => "ICMPv4".into(),
        "icmpv6" => "ICMPv6".into(),
        "dns" => "DNS".into(),
        "http" => "HTTP".into(),
        "tls" | "ssl" => "TLS".into(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcap_global_header_ethernet() {
        let hdr = pcap_global_header(LINKTYPE_ETHERNET);
        assert_eq!(&hdr[0..4], &0xa1b2c3d4u32.to_le_bytes());
        assert_eq!(&hdr[4..6], &2u16.to_le_bytes());
        assert_eq!(&hdr[6..8], &4u16.to_le_bytes());
        assert_eq!(&hdr[16..20], &SNAPLEN.to_le_bytes());
        assert_eq!(&hdr[20..24], &1u32.to_le_bytes()); // Ethernet
    }

    #[test]
    fn pcap_packet_header_roundtrip() {
        let hdr = pcap_packet_header(100, 1234.567890).unwrap();
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
    fn pcap_packet_header_negative_timestamp_rejected() {
        assert!(pcap_packet_header(100, -1.0).is_err());
    }

    #[test]
    fn pcap_packet_header_large_timestamp_saturates() {
        let hdr = pcap_packet_header(100, 5_000_000_000.0).unwrap();
        let ts_sec = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        assert_eq!(ts_sec, u32::MAX);
    }

    fn make_field(name: &str, value: &str) -> LayerField {
        LayerField {
            name: name.into(),
            value: value.into(),
            byte_range: None,
        }
    }

    #[test]
    fn descriptive_name_ipv4_with_fields() {
        let fields = vec![
            make_field("ip.src", "10.0.0.1"),
            make_field("ip.dst", "10.0.0.2"),
        ];
        assert_eq!(
            build_descriptive_layer_name("ip", &fields),
            "IPv4, Src: 10.0.0.1, Dst: 10.0.0.2"
        );
    }

    #[test]
    fn descriptive_name_ipv4_missing_fields() {
        assert_eq!(build_descriptive_layer_name("ip", &[]), "IPv4");
    }

    #[test]
    fn descriptive_name_tcp_with_fields() {
        let fields = vec![
            make_field("tcp.srcport", "443"),
            make_field("tcp.dstport", "12345"),
        ];
        assert_eq!(
            build_descriptive_layer_name("tcp", &fields),
            "TCP, Src Port: 443, Dst Port: 12345"
        );
    }

    #[test]
    fn descriptive_name_udp_missing_fields() {
        assert_eq!(build_descriptive_layer_name("udp", &[]), "UDP");
    }

    #[test]
    fn descriptive_name_eth_with_fields() {
        let fields = vec![
            make_field("eth.src", "aa:bb:cc:dd:ee:ff"),
            make_field("eth.dst", "11:22:33:44:55:66"),
        ];
        assert_eq!(
            build_descriptive_layer_name("eth", &fields),
            "Ethernet II, Src: aa:bb:cc:dd:ee:ff, Dst: 11:22:33:44:55:66"
        );
    }

    #[test]
    fn descriptive_name_static_protocols() {
        assert_eq!(build_descriptive_layer_name("arp", &[]), "ARP");
        assert_eq!(build_descriptive_layer_name("icmp", &[]), "ICMPv4");
        assert_eq!(build_descriptive_layer_name("icmpv6", &[]), "ICMPv6");
        assert_eq!(build_descriptive_layer_name("dns", &[]), "DNS");
        assert_eq!(build_descriptive_layer_name("http", &[]), "HTTP");
        assert_eq!(build_descriptive_layer_name("tls", &[]), "TLS");
        assert_eq!(build_descriptive_layer_name("ssl", &[]), "TLS");
    }

    #[test]
    fn descriptive_name_unknown_protocol() {
        assert_eq!(build_descriptive_layer_name("stp", &[]), "stp");
    }

    #[test]
    fn tshark_check() {
        let _ = tshark_available();
    }

    #[test]
    fn request_seq_increments() {
        let a = next_request_seq();
        let b = next_request_seq();
        assert!(b > a);
    }

    #[test]
    fn deep_dissect_tcp_packet() {
        if !tshark_available() {
            eprintln!("Skipping deep dissection test — tshark not available");
            return;
        }

        let mut dissector = DeepDissector::new_ethernet().expect("Failed to create DeepDissector");

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
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
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

        let layer_names: Vec<&str> = detail.layers.iter().map(|l| l.name.as_str()).collect();
        assert!(
            layer_names.iter().any(|n| n.starts_with("Ethernet II")),
            "Missing Ethernet layer: {layer_names:?}"
        );
        assert!(
            layer_names.iter().any(|n| n.starts_with("IPv4")),
            "Missing IPv4 layer: {layer_names:?}"
        );
        assert!(
            layer_names.iter().any(|n| n.starts_with("TCP")),
            "Missing TCP layer: {layer_names:?}"
        );

        let eth_layer = detail.layers.iter().find(|l| l.name.starts_with("Ethernet II")).unwrap();
        assert!(!eth_layer.fields.is_empty(), "eth layer should have fields");
        let has_byte_range = eth_layer.fields.iter().any(|f| f.byte_range.is_some());
        assert!(has_byte_range, "eth layer fields should have byte ranges");
    }
}

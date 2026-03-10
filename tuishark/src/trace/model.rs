/// Shared types used by both the eBPF map and the userspace lookup.

/// 5-tuple flow key used as the BPF map key.
/// Matches the C-compatible layout in the eBPF program.
///
/// # Safety
/// This type is `#[repr(C)]` with only primitive fields, making it safe for Pod.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct FlowKey {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3],
}

impl FlowKey {
    /// Create a FlowKey from parsed packet fields.
    /// Returns None if the packet doesn't have enough info (e.g., ARP, non-IP).
    pub fn from_packet(
        source: &str,
        destination: &str,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        protocol: u8,
    ) -> Option<Self> {
        let src_addr = parse_ipv4(source)?;
        let dst_addr = parse_ipv4(destination)?;
        Some(Self {
            src_addr,
            dst_addr,
            src_port: src_port.unwrap_or(0),
            dst_port: dst_port.unwrap_or(0),
            protocol,
            _pad: [0; 3],
        })
    }

    /// Create the reverse flow key (swap src/dst).
    pub fn reverse(&self) -> Self {
        Self {
            src_addr: self.dst_addr,
            dst_addr: self.src_addr,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
            _pad: [0; 3],
        }
    }
}

/// Process information from the eBPF map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ProcessInfo {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
}

impl ProcessInfo {
    /// Get the process name as a string (strips null bytes).
    pub fn comm_str(&self) -> &str {
        let len = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        std::str::from_utf8(&self.comm[..len]).unwrap_or("<invalid>")
    }
}

// SAFETY: FlowKey and ProcessInfo are #[repr(C)] structs with only primitive fields (u32, u16, u8,
// [u8; N]). They contain no pointers, references, padding-sensitive types, or interior mutability.
// They are valid for any bit pattern and can be safely read from/written to BPF maps.
#[cfg(feature = "trace")]
unsafe impl aya::Pod for FlowKey {}
#[cfg(feature = "trace")]
unsafe impl aya::Pod for ProcessInfo {}

/// Trace state for status display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceState {
    /// Tracing disabled (--trace not passed or feature not compiled).
    Disabled,
    /// Tracing requested but eBPF failed to load.
    Unavailable,
    /// eBPF loaded and actively tracing.
    Active,
    /// Not applicable (file mode).
    FileMode,
}

/// Parse an IPv4 address string into a u32 in network byte order.
fn parse_ipv4(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let a: u8 = parts[0].parse().ok()?;
    let b: u8 = parts[1].parse().ok()?;
    let c: u8 = parts[2].parse().ok()?;
    let d: u8 = parts[3].parse().ok()?;
    Some(u32::from_be_bytes([a, b, c, d]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_valid() {
        assert_eq!(parse_ipv4("192.168.1.1"), Some(0xC0A80101));
        assert_eq!(parse_ipv4("10.0.0.1"), Some(0x0A000001));
        assert_eq!(parse_ipv4("0.0.0.0"), Some(0));
        assert_eq!(parse_ipv4("255.255.255.255"), Some(0xFFFFFFFF));
    }

    #[test]
    fn parse_ipv4_invalid() {
        assert_eq!(parse_ipv4("not-an-ip"), None);
        assert_eq!(parse_ipv4("192.168.1"), None);
        assert_eq!(parse_ipv4(""), None);
        assert_eq!(parse_ipv4("::1"), None);
    }

    #[test]
    fn flow_key_from_packet() {
        let key = FlowKey::from_packet(
            "192.168.1.1",
            "10.0.0.1",
            Some(12345),
            Some(80),
            6, // TCP
        );
        assert!(key.is_some());
        let key = key.unwrap();
        assert_eq!(key.src_addr, 0xC0A80101);
        assert_eq!(key.dst_addr, 0x0A000001);
        assert_eq!(key.src_port, 12345);
        assert_eq!(key.dst_port, 80);
        assert_eq!(key.protocol, 6);
    }

    #[test]
    fn flow_key_from_non_ip() {
        // ARP packets have no IP addresses
        let key = FlowKey::from_packet("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", None, None, 0);
        assert!(key.is_none());
    }

    #[test]
    fn flow_key_reverse() {
        let key = FlowKey::from_packet("192.168.1.1", "10.0.0.1", Some(12345), Some(80), 6)
            .unwrap();
        let rev = key.reverse();
        assert_eq!(rev.src_addr, key.dst_addr);
        assert_eq!(rev.dst_addr, key.src_addr);
        assert_eq!(rev.src_port, key.dst_port);
        assert_eq!(rev.dst_port, key.src_port);
    }

    #[test]
    fn process_info_comm_str() {
        let mut info = ProcessInfo {
            pid: 1234,
            uid: 1000,
            comm: [0u8; 16],
        };
        info.comm[..4].copy_from_slice(b"curl");
        assert_eq!(info.comm_str(), "curl");
    }

    #[test]
    fn process_info_full_comm() {
        let info = ProcessInfo {
            pid: 1,
            uid: 0,
            comm: *b"systemd-resolve\0",
        };
        assert_eq!(info.comm_str(), "systemd-resolve");
    }
}

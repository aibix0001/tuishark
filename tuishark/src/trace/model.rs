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

/// Container context from eBPF — network namespace, device, TCP state, cgroup.
/// Must match the eBPF-side ContainerInfo layout exactly.
///
/// Fields ordered to avoid implicit padding: u64 first, then u32s, then byte arrays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ContainerInfo {
    pub cgroup_id: u64,
    pub netns_inum: u32,
    pub ifindex: u32,
    pub dev_name: [u8; 16],
    pub tcp_state: u8,
    pub _pad: [u8; 7],
}

// Compile-time size assertion: 8+4+4+16+1+7 = 40 bytes.
const _: () = assert!(std::mem::size_of::<ContainerInfo>() == 40);

impl ContainerInfo {
    /// Get the device name as a string (strips null bytes).
    pub fn dev_name_str(&self) -> &str {
        let len = self.dev_name.iter().position(|&b| b == 0).unwrap_or(16);
        std::str::from_utf8(&self.dev_name[..len]).unwrap_or("<invalid>")
    }

    /// Get TCP state as a human-readable string.
    pub fn tcp_state_str(&self) -> &'static str {
        match self.tcp_state {
            1 => "ESTABLISHED",
            2 => "SYN_SENT",
            3 => "SYN_RECV",
            4 => "FIN_WAIT1",
            5 => "FIN_WAIT2",
            6 => "TIME_WAIT",
            7 => "CLOSE",
            8 => "CLOSE_WAIT",
            9 => "LAST_ACK",
            10 => "LISTEN",
            11 => "CLOSING",
            12 => "NEW_SYN_RECV",
            0 => "N/A",
            _ => "UNKNOWN",
        }
    }
}

// SAFETY: ContainerInfo is #[repr(C)] with only primitive fields (u32, [u8; 16], u8, [u8; 3], u64).
// No pointers, references, or interior mutability. Valid for any bit pattern.
#[cfg(feature = "trace")]
unsafe impl aya::Pod for ContainerInfo {}

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

/// Parse an IPv4 address string into a u32 matching the kernel's `__be32` memory layout.
///
/// The kernel stores IP addresses as `__be32` (big-endian). When the eBPF program reads this
/// via `bpf_probe_read_kernel` into a native `u32`, the raw memory bytes are interpreted in
/// the platform's native byte order. We must produce the same representation here so that
/// the BPF map lookup key matches.
fn parse_ipv4(s: &str) -> Option<u32> {
    let mut octets = s.splitn(5, '.');
    let a: u8 = octets.next()?.parse().ok()?;
    let b: u8 = octets.next()?.parse().ok()?;
    let c: u8 = octets.next()?.parse().ok()?;
    let d: u8 = octets.next()?.parse().ok()?;
    // Reject if there are extra segments (e.g., "1.2.3.4.5")
    if octets.next().is_some() {
        return None;
    }
    // Use native byte order to match how eBPF reads __be32 from kernel memory
    Some(u32::from_ne_bytes([a, b, c, d]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_valid() {
        // Values use from_ne_bytes to match kernel __be32 read by eBPF
        assert_eq!(parse_ipv4("192.168.1.1"), Some(u32::from_ne_bytes([192, 168, 1, 1])));
        assert_eq!(parse_ipv4("10.0.0.1"), Some(u32::from_ne_bytes([10, 0, 0, 1])));
        assert_eq!(parse_ipv4("0.0.0.0"), Some(0));
        assert_eq!(parse_ipv4("255.255.255.255"), Some(u32::from_ne_bytes([255, 255, 255, 255])));
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
        assert_eq!(key.src_addr, u32::from_ne_bytes([192, 168, 1, 1]));
        assert_eq!(key.dst_addr, u32::from_ne_bytes([10, 0, 0, 1]));
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

    #[test]
    fn container_info_dev_name_str() {
        let mut info = ContainerInfo {
            cgroup_id: 0,
            netns_inum: 0,
            ifindex: 2,
            dev_name: [0u8; 16],
            tcp_state: 0,
            _pad: [0; 7],
        };
        info.dev_name[..4].copy_from_slice(b"eth0");
        assert_eq!(info.dev_name_str(), "eth0");
    }

    #[test]
    fn container_info_tcp_states() {
        let make = |state: u8| ContainerInfo {
            cgroup_id: 0, netns_inum: 0, ifindex: 0, dev_name: [0; 16],
            tcp_state: state, _pad: [0; 7],
        };
        assert_eq!(make(0).tcp_state_str(), "N/A");
        assert_eq!(make(1).tcp_state_str(), "ESTABLISHED");
        assert_eq!(make(2).tcp_state_str(), "SYN_SENT");
        assert_eq!(make(3).tcp_state_str(), "SYN_RECV");
        assert_eq!(make(4).tcp_state_str(), "FIN_WAIT1");
        assert_eq!(make(5).tcp_state_str(), "FIN_WAIT2");
        assert_eq!(make(6).tcp_state_str(), "TIME_WAIT");
        assert_eq!(make(7).tcp_state_str(), "CLOSE");
        assert_eq!(make(8).tcp_state_str(), "CLOSE_WAIT");
        assert_eq!(make(9).tcp_state_str(), "LAST_ACK");
        assert_eq!(make(10).tcp_state_str(), "LISTEN");
        assert_eq!(make(11).tcp_state_str(), "CLOSING");
        assert_eq!(make(12).tcp_state_str(), "NEW_SYN_RECV");
        assert_eq!(make(255).tcp_state_str(), "UNKNOWN");
    }
}

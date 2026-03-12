/// Data types for kernel packet path tracing.
///
/// These types mirror the eBPF-side structures used for PathEvent emission
/// and provide the userspace aggregation types (PacketPath, PathHop).

/// Static function name table — func_id indexes into this array.
/// Order matches the func_id assignments in the eBPF program.
pub const FUNC_NAMES: &[&str] = &[
    // Ingress (0-5)
    "netif_receive_skb",           // 0
    "__netif_receive_skb_core",    // 1
    "ip_rcv",                      // 2
    "ip_rcv_finish",               // 3
    "ip_local_deliver",            // 4
    "ip_local_deliver_finish",     // 5
    // Netfilter (6-7)
    "nf_hook_slow",                // 6
    "nf_conntrack_in",             // 7
    // TCP rx (8-10)
    "tcp_v4_rcv",                  // 8
    "tcp_rcv_established",         // 9
    "tcp_data_queue",              // 10
    // UDP rx (11-12)
    "udp_rcv",                     // 11
    "udp_queue_rcv_skb",           // 12
    // Socket (13-14) — reserved, not currently probed
    // (sock_sendmsg/sock_recvmsg take struct socket *, not sk_buff *)
    "sock_sendmsg",                // 13 (reserved)
    "sock_recvmsg",                // 14 (reserved)
    // TCP tx (15-16)
    "tcp_sendmsg",                 // 15
    "tcp_write_xmit",             // 16
    // UDP tx (17)
    "udp_sendmsg",                 // 17
    // IP out (18-19)
    "ip_output",                   // 18
    "ip_finish_output",            // 19
    // Forward (20-21)
    "ip_forward",                  // 20
    "ip_forward_finish",           // 21
    // Egress (22-23)
    "dev_queue_xmit",              // 22
    "dev_hard_start_xmit",         // 23
];

/// Subsystem classification for color coding in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subsystem {
    Ingress,
    Netfilter,
    Transport,
    Socket,
    IpOut,
    Forward,
    Egress,
}

impl Subsystem {
    pub fn from_func_id(id: u16) -> Self {
        match id {
            0..=5 => Subsystem::Ingress,
            6..=7 => Subsystem::Netfilter,
            8..=12 => Subsystem::Transport,
            13..=14 => Subsystem::Socket,
            15..=17 => Subsystem::Transport,
            18..=19 => Subsystem::IpOut,
            20..=21 => Subsystem::Forward,
            22..=23 => Subsystem::Egress,
            _ => Subsystem::Ingress,
        }
    }
}

/// eBPF PathEvent — must match the kernel-side layout exactly.
///
/// Fields ordered to avoid implicit padding: u64s first, then u32s, then u16s, then u8.
/// Emitted by each path-tracing kprobe via PerfEventArray.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PathEvent {
    pub skb_ptr: u64,
    pub timestamp_ns: u64,
    pub src_addr: u32,
    pub dst_addr: u32,
    pub func_id: u16,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 1],
}

// Compile-time size assertion to catch layout mismatches between eBPF and userspace.
// Compile-time size assertion: 8+8+4+4+2+2+2+1+1 = 32 bytes (no implicit padding).
const _: () = assert!(std::mem::size_of::<PathEvent>() == 32);

// SAFETY: PathEvent is #[repr(C)] with only primitive fields (u64, u32, u16, u8, [u8; 1]).
// No pointers, references, or interior mutability. Valid for any bit pattern.
#[cfg(feature = "trace")]
unsafe impl aya::Pod for PathEvent {}

/// eBPF TraceFilter — written by userspace, read by BPF to filter events.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TraceFilter {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub active: u8,
    pub _pad: [u8; 2],
}

// SAFETY: TraceFilter is #[repr(C)] with only primitive fields (u32, u16, u8, [u8; 2]).
// No pointers, references, or interior mutability. Valid for any bit pattern.
#[cfg(feature = "trace")]
unsafe impl aya::Pod for TraceFilter {}

impl Default for TraceFilter {
    fn default() -> Self {
        Self {
            src_addr: 0,
            dst_addr: 0,
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            active: 0,
            _pad: [0; 2],
        }
    }
}

/// A single hop in the kernel path.
#[derive(Debug, Clone)]
pub struct PathHop {
    pub func_id: u16,
    pub timestamp_ns: u64,
    pub delta_ns: u64,
}

impl PathHop {
    /// Get the function name from the static table.
    pub fn func_name(&self) -> &'static str {
        FUNC_NAMES
            .get(self.func_id as usize)
            .copied()
            .unwrap_or("unknown")
    }

    /// Get the subsystem for color coding.
    pub fn subsystem(&self) -> Subsystem {
        Subsystem::from_func_id(self.func_id)
    }
}

/// A complete kernel path for one packet (one sk_buff traversal).
#[derive(Debug, Clone)]
pub struct PacketPath {
    pub hops: Vec<PathHop>,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl PacketPath {
    /// Total traversal time in nanoseconds.
    pub fn total_ns(&self) -> u64 {
        self.last_seen_ns.saturating_sub(self.first_seen_ns)
    }

    /// Format total time as a human-readable string.
    pub fn total_time_str(&self) -> String {
        format_ns(self.total_ns())
    }
}

/// Format nanoseconds as a human-readable duration string.
pub fn format_ns(ns: u64) -> String {
    if ns < 1_000 {
        format!("{ns} ns")
    } else if ns < 1_000_000 {
        format!("{:.1} us", ns as f64 / 1_000.0)
    } else {
        format!("{:.1} ms", ns as f64 / 1_000_000.0)
    }
}

/// Path tracing state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathTraceState {
    /// Path tracing not active.
    Inactive,
    /// Path tracing active (all flows or filtered).
    Active,
    /// Path tracing active with filter on a specific flow.
    Filtered,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn func_name_lookup() {
        let hop = PathHop { func_id: 0, timestamp_ns: 0, delta_ns: 0 };
        assert_eq!(hop.func_name(), "netif_receive_skb");

        let hop = PathHop { func_id: 8, timestamp_ns: 0, delta_ns: 0 };
        assert_eq!(hop.func_name(), "tcp_v4_rcv");

        let hop = PathHop { func_id: 22, timestamp_ns: 0, delta_ns: 0 };
        assert_eq!(hop.func_name(), "dev_queue_xmit");
    }

    #[test]
    fn func_name_out_of_range() {
        let hop = PathHop { func_id: 255, timestamp_ns: 0, delta_ns: 0 };
        assert_eq!(hop.func_name(), "unknown");
    }

    #[test]
    fn subsystem_classification() {
        assert_eq!(Subsystem::from_func_id(0), Subsystem::Ingress);
        assert_eq!(Subsystem::from_func_id(6), Subsystem::Netfilter);
        assert_eq!(Subsystem::from_func_id(8), Subsystem::Transport);
        assert_eq!(Subsystem::from_func_id(13), Subsystem::Socket);
        assert_eq!(Subsystem::from_func_id(18), Subsystem::IpOut);
        assert_eq!(Subsystem::from_func_id(20), Subsystem::Forward);
        assert_eq!(Subsystem::from_func_id(22), Subsystem::Egress);
    }

    #[test]
    fn format_ns_units() {
        assert_eq!(format_ns(500), "500 ns");
        assert_eq!(format_ns(1_200), "1.2 us");
        assert_eq!(format_ns(42_300), "42.3 us");
        assert_eq!(format_ns(1_500_000), "1.5 ms");
    }

    #[test]
    fn packet_path_total() {
        let path = PacketPath {
            hops: vec![],
            first_seen_ns: 1000,
            last_seen_ns: 43300,
            src_addr: 0,
            dst_addr: 0,
            src_port: 0,
            dst_port: 0,
            protocol: 0,
        };
        assert_eq!(path.total_ns(), 42300);
        assert_eq!(path.total_time_str(), "42.3 us");
    }
}

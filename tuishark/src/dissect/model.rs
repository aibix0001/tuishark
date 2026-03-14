use std::fmt;

/// Link-layer type for a capture session (maps to pcap DLT values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,   // DLT_EN10MB (1)
    RawIp,      // DLT_RAW (101) — IPv4 or IPv6
    Null,       // DLT_NULL (0) — BSD loopback
    LinuxSll,   // DLT_LINUX_SLL (113)
    Pflog,      // DLT_PFLOG (117)
    Enc,        // DLT_ENC (109)
}

impl LinkType {
    /// Try to convert a pcap Linktype to our LinkType enum.
    pub fn from_pcap(lt: pcap::Linktype) -> Option<Self> {
        match lt.0 {
            1 => Some(LinkType::Ethernet),
            101 | 228 | 229 => Some(LinkType::RawIp), // DLT_RAW, DLT_IPV4, DLT_IPV6
            0 => Some(LinkType::Null),
            113 => Some(LinkType::LinuxSll),
            117 => Some(LinkType::Pflog),
            109 => Some(LinkType::Enc),
            _ => None,
        }
    }

    /// Convert back to pcap Linktype for saving.
    pub fn to_pcap(self) -> pcap::Linktype {
        match self {
            LinkType::Ethernet => pcap::Linktype(1),
            LinkType::RawIp => pcap::Linktype(101),
            LinkType::Null => pcap::Linktype(0),
            LinkType::LinuxSll => pcap::Linktype(113),
            LinkType::Pflog => pcap::Linktype(117),
            LinkType::Enc => pcap::Linktype(109),
        }
    }

    /// Fixed byte length of the link-layer header.
    /// Returns `None` for variable-length headers (Pflog) — callers must parse
    /// the header directly to determine the actual length.
    pub fn header_len(self) -> Option<usize> {
        match self {
            LinkType::Ethernet => Some(14),
            LinkType::RawIp => Some(0),
            LinkType::Null => Some(4),
            LinkType::LinuxSll => Some(16),
            LinkType::Pflog => None, // variable — parsed from header byte 0
            LinkType::Enc => Some(12),
        }
    }
}

impl fmt::Display for LinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkType::Ethernet => write!(f, "Ethernet"),
            LinkType::RawIp => write!(f, "Raw IP"),
            LinkType::Null => write!(f, "BSD Loopback"),
            LinkType::LinuxSll => write!(f, "Linux SLL"),
            LinkType::Pflog => write!(f, "pflog"),
            LinkType::Enc => write!(f, "enc"),
        }
    }
}

/// Metadata extracted from pflog link-layer headers.
#[derive(Debug, Clone)]
pub struct PflogMeta {
    pub action: PfAction,
    pub direction: PfDirection,
    pub ifname: String,
    pub rule_number: u32,
    pub reason: u8,
    pub header_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PfAction {
    Pass,
    Block,
    Scrub,
    NoScrub,
    Nat,
    NoNat,
    Binat,
    NoBinat,
    Rdr,
    NoRdr,
    Match,
    Unknown(u8),
}

impl fmt::Display for PfAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PfAction::Pass => write!(f, "pass"),
            PfAction::Block => write!(f, "block"),
            PfAction::Scrub => write!(f, "scrub"),
            PfAction::NoScrub => write!(f, "no-scrub"),
            PfAction::Nat => write!(f, "nat"),
            PfAction::NoNat => write!(f, "no-nat"),
            PfAction::Binat => write!(f, "binat"),
            PfAction::NoBinat => write!(f, "no-binat"),
            PfAction::Rdr => write!(f, "rdr"),
            PfAction::NoRdr => write!(f, "no-rdr"),
            PfAction::Match => write!(f, "match"),
            PfAction::Unknown(v) => write!(f, "unknown({v})"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PfDirection {
    In,
    Out,
    Fwd,
    Unknown(u8),
}

impl fmt::Display for PfDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PfDirection::In => write!(f, "in"),
            PfDirection::Out => write!(f, "out"),
            PfDirection::Fwd => write!(f, "fwd"),
            PfDirection::Unknown(v) => write!(f, "unknown({v})"),
        }
    }
}

/// Decode pflog reason code to human-readable string.
pub fn pflog_reason_str(reason: u8) -> &'static str {
    match reason {
        0 => "match",
        1 => "bad-offset",
        2 => "fragment",
        3 => "short",
        4 => "normalize",
        5 => "memory",
        6 => "bad-timestamp",
        7 => "congestion",
        8 => "ip-option",
        9 => "proto-cksum",
        10 => "state-mismatch",
        11 => "state-insert",
        12 => "state-limit",
        13 => "src-limit",
        14 => "synproxy",
        _ => "unknown",
    }
}

/// Metadata extracted from enc (IPsec tunnel) link-layer headers.
#[derive(Debug, Clone)]
pub struct EncMeta {
    pub address_family: u32,
    pub spi: u32,
    pub flags: u32,
}

/// Link-layer metadata attached to a packet summary.
// TODO: wire into packet table columns and display filter engine (pf.action, pf.ifname, enc.spi)
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum LinkMeta {
    Pflog(PflogMeta),
    Enc(EncMeta),
}

#[derive(Debug, Clone)]
pub struct PacketSummary {
    pub index: usize,
    pub timestamp: f64,
    pub source: String,
    pub destination: String,
    pub protocol: Protocol,
    pub length: usize,
    /// Original wire length (may differ from `length` if packet was truncated by snaplen).
    pub original_length: usize,
    pub info: String,
    /// Source port (TCP/UDP only, None for other protocols).
    pub src_port: Option<u16>,
    /// Destination port (TCP/UDP only, None for other protocols).
    pub dst_port: Option<u16>,
    /// Link-layer metadata (pflog/enc only).
    // TODO: surface in packet table and display filters
    #[allow(dead_code)]
    pub link_meta: Option<LinkMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Arp,
    Dns,
    Http,
    Tls,
    Ipv4,
    Ipv6,
    Ethernet,
    Pflog,
    Enc,
    Unknown(String),
}

impl Protocol {
    /// Case-insensitive match against a protocol name string.
    pub fn matches_str(&self, s: &str) -> bool {
        let s_lower = s.to_ascii_lowercase();
        match self {
            Protocol::Tcp => s_lower == "tcp",
            Protocol::Udp => s_lower == "udp",
            Protocol::Icmp => s_lower == "icmp",
            Protocol::Icmpv6 => s_lower == "icmpv6",
            Protocol::Arp => s_lower == "arp",
            Protocol::Dns => s_lower == "dns",
            Protocol::Http => s_lower == "http",
            Protocol::Tls => s_lower == "tls" || s_lower == "https",
            Protocol::Ipv4 => s_lower == "ipv4" || s_lower == "ip",
            Protocol::Ipv6 => s_lower == "ipv6",
            Protocol::Ethernet => s_lower == "ethernet" || s_lower == "eth",
            Protocol::Pflog => s_lower == "pflog" || s_lower == "pf",
            Protocol::Enc => s_lower == "enc" || s_lower == "ipsec",
            Protocol::Unknown(name) => name.to_ascii_lowercase() == s_lower,
        }
    }

    /// Case-insensitive substring check without heap allocation.
    /// `needle` must already be lowercased.
    pub fn contains_lower(&self, needle: &str) -> bool {
        let name = match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
            Protocol::Icmpv6 => "icmpv6",
            Protocol::Arp => "arp",
            Protocol::Dns => "dns",
            Protocol::Http => "http",
            Protocol::Tls => "tls",
            Protocol::Ipv4 => "ipv4",
            Protocol::Ipv6 => "ipv6",
            Protocol::Ethernet => "ethernet",
            Protocol::Pflog => "pflog",
            Protocol::Enc => "enc",
            Protocol::Unknown(s) => {
                // Unknown names may have mixed case
                return s.to_ascii_lowercase().contains(needle);
            }
        };
        name.contains(needle)
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Icmpv6 => write!(f, "ICMPv6"),
            Protocol::Arp => write!(f, "ARP"),
            Protocol::Dns => write!(f, "DNS"),
            Protocol::Http => write!(f, "HTTP"),
            Protocol::Tls => write!(f, "TLS"),
            Protocol::Ipv4 => write!(f, "IPv4"),
            Protocol::Ipv6 => write!(f, "IPv6"),
            Protocol::Ethernet => write!(f, "Ethernet"),
            Protocol::Pflog => write!(f, "pflog"),
            Protocol::Enc => write!(f, "enc"),
            Protocol::Unknown(s) => write!(f, "{s}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LayerField {
    pub name: String,
    pub value: String,
    pub byte_range: Option<(usize, usize)>,
}

#[derive(Debug, Clone, Default)]
pub struct Layer {
    pub name: String,
    pub fields: Vec<LayerField>,
}

#[derive(Debug, Clone, Default)]
pub struct PacketDetail {
    pub layers: Vec<Layer>,
}

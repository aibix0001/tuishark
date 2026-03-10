use std::fmt;

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

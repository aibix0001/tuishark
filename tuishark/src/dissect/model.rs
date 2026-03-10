use std::fmt;

#[derive(Debug, Clone)]
pub struct PacketSummary {
    pub index: usize,
    pub timestamp: f64,
    pub source: String,
    pub destination: String,
    pub protocol: Protocol,
    pub length: usize,
    pub info: String,
}

#[derive(Debug, Clone)]
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

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
#[derive(Debug, Clone, PartialEq)]
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

impl PfAction {
    /// Zero-allocation string representation for hot-path filter evaluation.
    /// Returns `None` for `Unknown` variants (caller must fall back to `to_string()`).
    pub fn as_str(&self) -> Option<&'static str> {
        match self {
            PfAction::Pass => Some("pass"),
            PfAction::Block => Some("block"),
            PfAction::Scrub => Some("scrub"),
            PfAction::NoScrub => Some("no-scrub"),
            PfAction::Nat => Some("nat"),
            PfAction::NoNat => Some("no-nat"),
            PfAction::Binat => Some("binat"),
            PfAction::NoBinat => Some("no-binat"),
            PfAction::Rdr => Some("rdr"),
            PfAction::NoRdr => Some("no-rdr"),
            PfAction::Match => Some("match"),
            PfAction::Unknown(_) => None,
        }
    }
}

impl fmt::Display for PfAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Some(s) => write!(f, "{s}"),
            None => {
                let PfAction::Unknown(v) = self else { unreachable!() };
                write!(f, "unknown({v})")
            }
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

impl PfDirection {
    /// Zero-allocation string representation for hot-path filter evaluation.
    pub fn as_str(&self) -> Option<&'static str> {
        match self {
            PfDirection::In => Some("in"),
            PfDirection::Out => Some("out"),
            PfDirection::Fwd => Some("fwd"),
            PfDirection::Unknown(_) => None,
        }
    }
}

impl fmt::Display for PfDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Some(s) => write!(f, "{s}"),
            None => {
                let PfDirection::Unknown(v) = self else { unreachable!() };
                write!(f, "unknown({v})")
            }
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
#[derive(Debug, Clone, PartialEq)]
pub struct EncMeta {
    pub address_family: u32,
    pub spi: u32,
    pub flags: u32,
}

/// Decode enc flags to human-readable string.
pub fn enc_flags_str(flags: u32) -> &'static str {
    match (flags & 1 != 0, flags & 2 != 0) {
        (true, true) => "auth+conf",
        (true, false) => "auth",
        (false, true) => "conf",
        (false, false) => "none",
    }
}

/// Link-layer metadata attached to a packet summary.
#[derive(Debug, Clone, PartialEq)]
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
    pub link_meta: Option<LinkMeta>,
    /// Source MAC address (Ethernet only).
    pub eth_src: Option<String>,
    /// Destination MAC address (Ethernet only).
    pub eth_dst: Option<String>,
    /// VLAN ID (802.1Q tag, if present).
    pub vlan_id: Option<u16>,
    /// TCP flags bitmask (FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20).
    pub tcp_flags: u8,
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
    Ssh,
    Smtp,
    Ftp,
    Telnet,
    Rdp,
    Bgp,
    Ldap,
    Dhcp,
    Ntp,
    Snmp,
    Syslog,
    Tftp,
    Mdns,
    Radius,
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
            Protocol::Ssh => s_lower == "ssh",
            Protocol::Smtp => s_lower == "smtp",
            Protocol::Ftp => s_lower == "ftp",
            Protocol::Telnet => s_lower == "telnet",
            Protocol::Rdp => s_lower == "rdp",
            Protocol::Bgp => s_lower == "bgp",
            Protocol::Ldap => s_lower == "ldap",
            Protocol::Dhcp => s_lower == "dhcp",
            Protocol::Ntp => s_lower == "ntp",
            Protocol::Snmp => s_lower == "snmp",
            Protocol::Syslog => s_lower == "syslog",
            Protocol::Tftp => s_lower == "tftp",
            Protocol::Mdns => s_lower == "mdns",
            Protocol::Radius => s_lower == "radius",
            Protocol::Ipv4 => s_lower == "ipv4" || s_lower == "ip",
            Protocol::Ipv6 => s_lower == "ipv6",
            Protocol::Ethernet => s_lower == "ethernet" || s_lower == "eth",
            Protocol::Pflog => s_lower == "pflog" || s_lower == "pf",
            Protocol::Enc => s_lower == "enc" || s_lower == "ipsec",
            Protocol::Unknown(name) => name.to_ascii_lowercase() == s_lower,
        }
    }

    pub fn is_known_name(s: &str) -> bool {
        matches!(
            s.to_ascii_lowercase().as_str(),
            "tcp" | "udp" | "icmp" | "icmpv6" | "arp" | "dns" | "http"
                | "tls" | "https" | "ssh" | "smtp" | "ftp" | "telnet"
                | "rdp" | "bgp" | "ldap" | "dhcp" | "ntp" | "snmp"
                | "syslog" | "tftp" | "mdns" | "radius"
                | "ipv4" | "ip" | "ipv6" | "ethernet" | "eth"
                | "pflog" | "pf" | "enc" | "ipsec"
        )
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
            Protocol::Ssh => "ssh",
            Protocol::Smtp => "smtp",
            Protocol::Ftp => "ftp",
            Protocol::Telnet => "telnet",
            Protocol::Rdp => "rdp",
            Protocol::Bgp => "bgp",
            Protocol::Ldap => "ldap",
            Protocol::Dhcp => "dhcp",
            Protocol::Ntp => "ntp",
            Protocol::Snmp => "snmp",
            Protocol::Syslog => "syslog",
            Protocol::Tftp => "tftp",
            Protocol::Mdns => "mdns",
            Protocol::Radius => "radius",
            Protocol::Ipv4 => "ipv4",
            Protocol::Ipv6 => "ipv6",
            Protocol::Ethernet => "ethernet",
            Protocol::Pflog => "pflog",
            Protocol::Enc => "enc",
            Protocol::Unknown(s) => {
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
            Protocol::Ssh => write!(f, "SSH"),
            Protocol::Smtp => write!(f, "SMTP"),
            Protocol::Ftp => write!(f, "FTP"),
            Protocol::Telnet => write!(f, "Telnet"),
            Protocol::Rdp => write!(f, "RDP"),
            Protocol::Bgp => write!(f, "BGP"),
            Protocol::Ldap => write!(f, "LDAP"),
            Protocol::Dhcp => write!(f, "DHCP"),
            Protocol::Ntp => write!(f, "NTP"),
            Protocol::Snmp => write!(f, "SNMP"),
            Protocol::Syslog => write!(f, "Syslog"),
            Protocol::Tftp => write!(f, "TFTP"),
            Protocol::Mdns => write!(f, "mDNS"),
            Protocol::Radius => write!(f, "RADIUS"),
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

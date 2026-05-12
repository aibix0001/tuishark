/// Filter expression AST.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// Field comparison: `ip.src == 192.168.1.1`
    Compare {
        field: Field,
        op: CompareOp,
        value: Value,
    },
    /// String containment: `info contains "SYN"`
    /// The value is stored pre-lowercased for O(1) case-insensitive matching.
    Contains {
        field: Field,
        value: String,
    },
    /// Bare protocol match: `tcp` desugars to `proto == tcp`
    ProtoMatch(String),
    /// Bare boolean field check: `tcp.flags.syn` (true if non-zero)
    BareField(Field),
    /// Boolean AND
    And(Box<Expr>, Box<Expr>),
    /// Boolean OR
    Or(Box<Expr>, Box<Expr>),
    /// Boolean NOT
    Not(Box<Expr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    IpSrc,
    IpDst,
    IpAddr, // matches either src or dst
    PortSrc,
    PortDst,
    Port,   // matches either src or dst
    Proto,
    Len,
    Info,
    // Ethernet (MAC) fields
    EthSrc,
    EthDst,
    EthAddr, // matches either src or dst MAC
    // VLAN
    VlanId,
    // TCP flags (value: 0 or 1)
    TcpFlagSyn,
    TcpFlagAck,
    TcpFlagFin,
    TcpFlagRst,
    TcpFlagPsh,
    TcpFlagUrg,
    // pflog link-layer fields
    PfAction,
    PfDirection,
    PfIfname,
    PfRule,
    PfReason,
    // enc (IPsec) link-layer fields
    EncSpi,
    EncFlags,
}

impl Field {
    pub fn is_boolean(&self) -> bool {
        matches!(
            self,
            Field::TcpFlagSyn
                | Field::TcpFlagAck
                | Field::TcpFlagFin
                | Field::TcpFlagRst
                | Field::TcpFlagPsh
                | Field::TcpFlagUrg
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Int(u64),
    Cidr {
        addr: std::net::IpAddr,
        prefix_len: u8,
    },
}

impl Eq for Value {}

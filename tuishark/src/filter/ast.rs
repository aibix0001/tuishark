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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Int(u64),
}

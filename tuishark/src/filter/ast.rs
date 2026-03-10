/// Filter expression AST.

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// Field comparison: `ip.src == 192.168.1.1`
    Compare {
        field: Field,
        op: CompareOp,
        value: Value,
    },
    /// String containment: `info contains "SYN"`
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

#[derive(Debug, Clone, PartialEq)]
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
}

#[derive(Debug, Clone, PartialEq)]
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
}

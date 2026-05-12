/// Tokenizer and recursive descent parser for filter expressions.
///
/// Grammar:
///   expr     = or_expr
///   or_expr  = and_expr (("or" | "||") and_expr)*
///   and_expr = not_expr (("and" | "&&") not_expr)*
///   not_expr = ("not" | "!") not_expr | primary
///   primary  = "(" expr ")" | comparison | contains | bare_proto | bare_field
///   comparison = field compare_op value
///   contains   = field "contains" quoted_string
///   bare_proto = protocol_name  (desugars to proto == name)
///   bare_field = boolean_field   (desugars to field != 0)
///   field    = "ip.src" | "ip.dst" | "ip.addr" | "port.src" | "port.dst" | "port" | "proto" | "len" | "info"
///            | "eth.src" | "eth.dst" | "eth.addr" | "vlan.id"
///            | "tcp.flags.syn" | "tcp.flags.ack" | "tcp.flags.fin" | "tcp.flags.rst" | "tcp.flags.psh" | "tcp.flags.urg"
///            | "tcp.srcport" | "tcp.dstport" | "udp.srcport" | "udp.dstport" | "frame.len"
///            | "pf.action" | "pf.direction" | "pf.dir" | "pf.ifname" | "pf.interface" | "pf.rule" | "pf.reason"
///            | "enc.spi" | "enc.flags"
///   value    = integer | string | cidr
///   compare_op = "==" | "!=" | ">" | "<" | ">=" | "<="

use super::ast::{CompareOp, Expr, Field, Value};
use crate::dissect::model::Protocol;

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Field(Field),
    Op(CompareOp),
    Contains,
    And,
    Or,
    Not,
    LParen,
    RParen,
    Str(String),
    Int(u64),
}

pub fn parse(input: &str) -> Result<Expr, String> {
    let tokens = tokenize(input)?;
    if tokens.is_empty() {
        return Err("empty filter expression".into());
    }
    let mut pos = 0;
    let expr = parse_or(&tokens, &mut pos)?;
    if pos < tokens.len() {
        return Err(format!("unexpected token at position {pos}"));
    }
    Ok(expr)
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        // Skip whitespace
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }

        // Parentheses
        if chars[i] == '(' {
            tokens.push(Token::LParen);
            i += 1;
            continue;
        }
        if chars[i] == ')' {
            tokens.push(Token::RParen);
            i += 1;
            continue;
        }

        // Two-char operators
        if i + 1 < chars.len() {
            match (chars[i], chars[i + 1]) {
                ('=', '=') => { tokens.push(Token::Op(CompareOp::Eq)); i += 2; continue; }
                ('!', '=') => { tokens.push(Token::Op(CompareOp::Ne)); i += 2; continue; }
                ('>', '=') => { tokens.push(Token::Op(CompareOp::Ge)); i += 2; continue; }
                ('<', '=') => { tokens.push(Token::Op(CompareOp::Le)); i += 2; continue; }
                ('&', '&') => { tokens.push(Token::And); i += 2; continue; }
                ('|', '|') => { tokens.push(Token::Or); i += 2; continue; }
                _ => {}
            }
        }

        // Single-char operators
        match chars[i] {
            '>' => { tokens.push(Token::Op(CompareOp::Gt)); i += 1; continue; }
            '<' => { tokens.push(Token::Op(CompareOp::Lt)); i += 1; continue; }
            '!' => { tokens.push(Token::Not); i += 1; continue; }
            _ => {}
        }

        // Quoted string
        if chars[i] == '"' {
            i += 1;
            let start = i;
            while i < chars.len() && chars[i] != '"' {
                i += 1;
            }
            if i >= chars.len() {
                return Err("unterminated string".into());
            }
            let s: String = chars[start..i].iter().collect();
            tokens.push(Token::Str(s));
            i += 1; // skip closing quote
            continue;
        }

        // Word or number (includes ':', '/' for IPv6 and CIDR notation)
        if chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '.' || chars[i] == ':' || chars[i] == '/' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '.' || chars[i] == ':' || chars[i] == '/') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            let lower = word.to_ascii_lowercase();

            // Try as keyword/field
            match lower.as_str() {
                "and" => tokens.push(Token::And),
                "or" => tokens.push(Token::Or),
                "not" => tokens.push(Token::Not),
                "contains" => tokens.push(Token::Contains),
                "ip.src" => tokens.push(Token::Field(Field::IpSrc)),
                "ip.dst" => tokens.push(Token::Field(Field::IpDst)),
                "ip.addr" => tokens.push(Token::Field(Field::IpAddr)),
                "port.src" | "tcp.srcport" | "udp.srcport" => tokens.push(Token::Field(Field::PortSrc)),
                "port.dst" | "tcp.dstport" | "udp.dstport" => tokens.push(Token::Field(Field::PortDst)),
                "port" => tokens.push(Token::Field(Field::Port)),
                "proto" => tokens.push(Token::Field(Field::Proto)),
                "len" | "frame.len" => tokens.push(Token::Field(Field::Len)),
                "info" => tokens.push(Token::Field(Field::Info)),
                "eth.src" => tokens.push(Token::Field(Field::EthSrc)),
                "eth.dst" => tokens.push(Token::Field(Field::EthDst)),
                "eth.addr" => tokens.push(Token::Field(Field::EthAddr)),
                "vlan.id" => tokens.push(Token::Field(Field::VlanId)),
                "tcp.flags.syn" => tokens.push(Token::Field(Field::TcpFlagSyn)),
                "tcp.flags.ack" => tokens.push(Token::Field(Field::TcpFlagAck)),
                "tcp.flags.fin" => tokens.push(Token::Field(Field::TcpFlagFin)),
                "tcp.flags.rst" => tokens.push(Token::Field(Field::TcpFlagRst)),
                "tcp.flags.psh" => tokens.push(Token::Field(Field::TcpFlagPsh)),
                "tcp.flags.urg" => tokens.push(Token::Field(Field::TcpFlagUrg)),
                "pf.action" => tokens.push(Token::Field(Field::PfAction)),
                "pf.direction" | "pf.dir" => tokens.push(Token::Field(Field::PfDirection)),
                "pf.ifname" | "pf.interface" => tokens.push(Token::Field(Field::PfIfname)),
                "pf.rule" => tokens.push(Token::Field(Field::PfRule)),
                "pf.reason" => tokens.push(Token::Field(Field::PfReason)),
                "enc.spi" => tokens.push(Token::Field(Field::EncSpi)),
                "enc.flags" => tokens.push(Token::Field(Field::EncFlags)),
                _ => {
                    // Try as integer (decimal or hex 0x prefix)
                    if let Ok(n) = word.parse::<u64>() {
                        tokens.push(Token::Int(n));
                    } else if let Some(hex) = lower.strip_prefix("0x") {
                        if let Ok(n) = u64::from_str_radix(hex, 16) {
                            tokens.push(Token::Int(n));
                        } else {
                            tokens.push(Token::Str(word));
                        }
                    } else {
                        // Unquoted string value (e.g., protocol name, IP address, CIDR)
                        tokens.push(Token::Str(word));
                    }
                }
            }
            continue;
        }

        return Err(format!("unexpected character: '{}'", chars[i]));
    }

    Ok(tokens)
}

fn parse_or(tokens: &[Token], pos: &mut usize) -> Result<Expr, String> {
    let mut left = parse_and(tokens, pos)?;
    while *pos < tokens.len() && tokens[*pos] == Token::Or {
        *pos += 1;
        let right = parse_and(tokens, pos)?;
        left = Expr::Or(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_and(tokens: &[Token], pos: &mut usize) -> Result<Expr, String> {
    let mut left = parse_not(tokens, pos)?;
    while *pos < tokens.len() && tokens[*pos] == Token::And {
        *pos += 1;
        let right = parse_not(tokens, pos)?;
        left = Expr::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_not(tokens: &[Token], pos: &mut usize) -> Result<Expr, String> {
    if *pos < tokens.len() && tokens[*pos] == Token::Not {
        *pos += 1;
        let expr = parse_not(tokens, pos)?;
        return Ok(Expr::Not(Box::new(expr)));
    }
    parse_primary(tokens, pos)
}

fn parse_primary(tokens: &[Token], pos: &mut usize) -> Result<Expr, String> {
    if *pos >= tokens.len() {
        return Err("unexpected end of expression".into());
    }

    // Parenthesized expression
    if tokens[*pos] == Token::LParen {
        *pos += 1;
        let expr = parse_or(tokens, pos)?;
        if *pos >= tokens.len() || tokens[*pos] != Token::RParen {
            return Err("missing closing parenthesis".into());
        }
        *pos += 1;
        return Ok(expr);
    }

    // Bare protocol name: `tcp` → ProtoMatch("tcp")
    if let Token::Str(s) = &tokens[*pos] {
        if Protocol::is_known_name(s) {
            let next_is_operator = *pos + 1 < tokens.len()
                && matches!(
                    &tokens[*pos + 1],
                    Token::Op(_) | Token::Contains
                );
            if !next_is_operator {
                let name = s.to_ascii_lowercase();
                *pos += 1;
                return Ok(Expr::ProtoMatch(name));
            }
        }
    }

    // Field-based expressions
    let field = match &tokens[*pos] {
        Token::Field(f) => f.clone(),
        other => return Err(format!("expected field name, got {other:?}")),
    };
    *pos += 1;

    // Bare boolean field: `tcp.flags.syn` with no operator following
    if field.is_boolean() {
        let has_operator = *pos < tokens.len()
            && matches!(
                &tokens[*pos],
                Token::Op(_) | Token::Contains
            );
        if !has_operator {
            return Ok(Expr::BareField(field));
        }
    }

    if *pos >= tokens.len() {
        return Err("expected operator after field".into());
    }

    // Contains
    if tokens[*pos] == Token::Contains {
        *pos += 1;
        if *pos >= tokens.len() {
            return Err("expected value after 'contains'".into());
        }
        let value = match &tokens[*pos] {
            Token::Str(s) => s.to_ascii_lowercase(),
            Token::Int(n) => n.to_string(),
            other => return Err(format!("expected string after 'contains', got {other:?}")),
        };
        *pos += 1;
        return Ok(Expr::Contains { field, value });
    }

    // Comparison
    let op = match &tokens[*pos] {
        Token::Op(op) => op.clone(),
        other => return Err(format!("expected operator, got {other:?}")),
    };
    *pos += 1;

    if *pos >= tokens.len() {
        return Err("expected value after operator".into());
    }

    let value = match &tokens[*pos] {
        Token::Str(s) => parse_value_str(s),
        Token::Int(n) => Value::Int(*n),
        other => return Err(format!("expected value, got {other:?}")),
    };
    *pos += 1;

    Ok(Expr::Compare { field, op, value })
}

fn parse_value_str(s: &str) -> Value {
    if let Some((addr_str, prefix_str)) = s.rsplit_once('/') {
        if let Ok(prefix_len) = prefix_str.parse::<u8>() {
            if let Ok(addr) = addr_str.parse::<std::net::IpAddr>() {
                let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
                if prefix_len <= max_prefix {
                    return Value::Cidr { addr, prefix_len };
                }
            }
        }
    }
    Value::Str(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_eq() {
        let expr = parse("proto == tcp").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::Proto,
                op: CompareOp::Eq,
                value: Value::Str("tcp".into()),
            }
        );
    }

    #[test]
    fn parse_ip_addr() {
        let expr = parse("ip.src == 192.168.1.1").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::IpSrc,
                op: CompareOp::Eq,
                value: Value::Str("192.168.1.1".into()),
            }
        );
    }

    #[test]
    fn parse_port_int() {
        let expr = parse("port == 443").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::Port,
                op: CompareOp::Eq,
                value: Value::Int(443),
            }
        );
    }

    #[test]
    fn parse_and_or() {
        let expr = parse("proto == tcp and port == 80").unwrap();
        assert!(matches!(expr, Expr::And(_, _)));
    }

    #[test]
    fn parse_not() {
        let expr = parse("not proto == arp").unwrap();
        assert!(matches!(expr, Expr::Not(_)));
    }

    #[test]
    fn parse_contains() {
        let expr = parse("info contains \"SYN\"").unwrap();
        assert_eq!(
            expr,
            Expr::Contains {
                field: Field::Info,
                value: "syn".into(), // pre-lowercased at parse time
            }
        );
    }

    #[test]
    fn parse_parens() {
        let expr = parse("(proto == tcp or proto == udp) and port == 80").unwrap();
        assert!(matches!(expr, Expr::And(_, _)));
    }

    #[test]
    fn parse_operator_aliases() {
        let expr = parse("proto == tcp && port == 80").unwrap();
        assert!(matches!(expr, Expr::And(_, _)));

        let expr = parse("proto == tcp || proto == udp").unwrap();
        assert!(matches!(expr, Expr::Or(_, _)));

        let expr = parse("!proto == arp").unwrap();
        assert!(matches!(expr, Expr::Not(_)));
    }

    #[test]
    fn parse_len_comparison() {
        let expr = parse("len > 1000").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::Len,
                op: CompareOp::Gt,
                value: Value::Int(1000),
            }
        );
    }

    #[test]
    fn parse_empty_error() {
        assert!(parse("").is_err());
    }

    #[test]
    fn parse_unterminated_string() {
        assert!(parse("info contains \"hello").is_err());
    }

    #[test]
    fn parse_missing_value() {
        assert!(parse("proto ==").is_err());
    }

    #[test]
    fn parse_missing_paren() {
        assert!(parse("(proto == tcp").is_err());
    }

    #[test]
    fn parse_pf_action() {
        let expr = parse("pf.action == block").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::PfAction,
                op: CompareOp::Eq,
                value: Value::Str("block".into()),
            }
        );
    }

    #[test]
    fn parse_pf_direction_alias() {
        let expr = parse("pf.dir == in").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::PfDirection,
                op: CompareOp::Eq,
                value: Value::Str("in".into()),
            }
        );
    }

    #[test]
    fn parse_pf_ifname_alias() {
        let expr = parse("pf.interface == em0").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::PfIfname,
                op: CompareOp::Eq,
                value: Value::Str("em0".into()),
            }
        );
    }

    #[test]
    fn parse_enc_spi() {
        let expr = parse("enc.spi == 12345").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::EncSpi,
                op: CompareOp::Eq,
                value: Value::Int(12345),
            }
        );
    }

    #[test]
    fn parse_hex_literal() {
        let expr = parse("enc.spi == 0x12345678").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::EncSpi,
                op: CompareOp::Eq,
                value: Value::Int(0x12345678),
            }
        );
    }

    #[test]
    fn parse_hex_literal_uppercase() {
        let expr = parse("enc.spi == 0xFF").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::EncSpi,
                op: CompareOp::Eq,
                value: Value::Int(255),
            }
        );
    }

    #[test]
    fn parse_pf_reason() {
        let expr = parse("pf.reason == match").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::PfReason,
                op: CompareOp::Eq,
                value: Value::Str("match".into()),
            }
        );
    }

    // --- Bare protocol ---

    #[test]
    fn parse_bare_proto() {
        let expr = parse("tcp").unwrap();
        assert_eq!(expr, Expr::ProtoMatch("tcp".into()));
    }

    #[test]
    fn parse_bare_proto_and() {
        let expr = parse("tcp and port == 80").unwrap();
        assert!(matches!(expr, Expr::And(_, _)));
    }

    #[test]
    fn parse_bare_proto_or() {
        let expr = parse("tcp or udp").unwrap();
        assert!(matches!(expr, Expr::Or(_, _)));
    }

    #[test]
    fn parse_bare_proto_not() {
        let expr = parse("not arp").unwrap();
        assert!(matches!(expr, Expr::Not(_)));
    }

    // --- CIDR ---

    #[test]
    fn parse_cidr_v4() {
        let expr = parse("ip.src == 192.168.0.0/16").unwrap();
        assert!(matches!(
            expr,
            Expr::Compare {
                value: Value::Cidr { prefix_len: 16, .. },
                ..
            }
        ));
    }

    #[test]
    fn parse_cidr_v6() {
        let expr = parse("ip.src == 2001:db8::/32").unwrap();
        assert!(matches!(
            expr,
            Expr::Compare {
                value: Value::Cidr { prefix_len: 32, .. },
                ..
            }
        ));
    }

    #[test]
    fn parse_cidr_invalid_prefix() {
        let expr = parse("ip.src == 10.0.0.0/33").unwrap();
        assert!(matches!(
            expr,
            Expr::Compare {
                value: Value::Str(_),
                ..
            }
        ));
    }

    #[test]
    fn parse_cidr_zero() {
        let expr = parse("ip.src == 0.0.0.0/0").unwrap();
        assert!(matches!(
            expr,
            Expr::Compare {
                value: Value::Cidr { prefix_len: 0, .. },
                ..
            }
        ));
    }

    // --- Wireshark field aliases ---

    #[test]
    fn parse_tcp_srcport() {
        let expr = parse("tcp.srcport == 80").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::PortSrc,
                op: CompareOp::Eq,
                value: Value::Int(80),
            }
        );
    }

    #[test]
    fn parse_udp_dstport() {
        let expr = parse("udp.dstport == 53").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::PortDst,
                op: CompareOp::Eq,
                value: Value::Int(53),
            }
        );
    }

    #[test]
    fn parse_frame_len() {
        let expr = parse("frame.len > 1000").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::Len,
                op: CompareOp::Gt,
                value: Value::Int(1000),
            }
        );
    }

    // --- MAC address fields ---

    #[test]
    fn parse_eth_src() {
        let expr = parse("eth.src == aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::EthSrc,
                op: CompareOp::Eq,
                value: Value::Str("aa:bb:cc:dd:ee:ff".into()),
            }
        );
    }

    #[test]
    fn parse_eth_addr() {
        let expr = parse("eth.addr == 00:11:22:33:44:55").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::EthAddr,
                op: CompareOp::Eq,
                value: Value::Str("00:11:22:33:44:55".into()),
            }
        );
    }

    // --- VLAN ---

    #[test]
    fn parse_vlan_id() {
        let expr = parse("vlan.id == 100").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::VlanId,
                op: CompareOp::Eq,
                value: Value::Int(100),
            }
        );
    }

    // --- TCP flags ---

    #[test]
    fn parse_tcp_flags_bare() {
        let expr = parse("tcp.flags.syn").unwrap();
        assert_eq!(expr, Expr::BareField(Field::TcpFlagSyn));
    }

    #[test]
    fn parse_tcp_flags_compare() {
        let expr = parse("tcp.flags.rst == 1").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::TcpFlagRst,
                op: CompareOp::Eq,
                value: Value::Int(1),
            }
        );
    }

    #[test]
    fn parse_tcp_flags_bare_and() {
        let expr = parse("tcp.flags.syn and tcp.flags.ack").unwrap();
        assert!(matches!(expr, Expr::And(_, _)));
    }

    // --- IPv6 tokenization ---

    #[test]
    fn parse_ipv6_address() {
        let expr = parse("ip.src == 2001:db8::1").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::IpSrc,
                op: CompareOp::Eq,
                value: Value::Str("2001:db8::1".into()),
            }
        );
    }

    #[test]
    fn parse_ipv6_full() {
        let expr = parse("ip.dst == fe80::1").unwrap();
        assert_eq!(
            expr,
            Expr::Compare {
                field: Field::IpDst,
                op: CompareOp::Eq,
                value: Value::Str("fe80::1".into()),
            }
        );
    }
}

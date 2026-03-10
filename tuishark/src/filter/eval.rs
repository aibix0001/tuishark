/// Evaluate a filter expression against a PacketSummary.

use crate::dissect::model::PacketSummary;
use super::ast::{CompareOp, Expr, Field, Value};

#[must_use]
pub fn matches(expr: &Expr, pkt: &PacketSummary) -> bool {
    match expr {
        Expr::Compare { field, op, value } => eval_compare(field, op, value, pkt),
        Expr::Contains { field, value } => eval_contains(field, value, pkt),
        Expr::And(left, right) => matches(left, pkt) && matches(right, pkt),
        Expr::Or(left, right) => matches(left, pkt) || matches(right, pkt),
        Expr::Not(inner) => !matches(inner, pkt),
    }
}

fn eval_compare(field: &Field, op: &CompareOp, value: &Value, pkt: &PacketSummary) -> bool {
    match field {
        Field::IpSrc => cmp_str(&pkt.source, op, value),
        Field::IpDst => cmp_str(&pkt.destination, op, value),
        Field::IpAddr => cmp_str(&pkt.source, op, value) || cmp_str(&pkt.destination, op, value),
        Field::PortSrc => cmp_port(pkt.src_port, op, value),
        Field::PortDst => cmp_port(pkt.dst_port, op, value),
        Field::Port => cmp_port(pkt.src_port, op, value) || cmp_port(pkt.dst_port, op, value),
        Field::Proto => cmp_proto(pkt, op, value),
        Field::Len => cmp_int(pkt.original_length as u64, op, value),
        Field::Info => cmp_str(&pkt.info, op, value),
    }
}

/// Evaluate `contains` — needle is already lowercased at parse time.
fn eval_contains(field: &Field, needle: &str, pkt: &PacketSummary) -> bool {
    match field {
        Field::IpSrc => str_contains_lower(&pkt.source, needle),
        Field::IpDst => str_contains_lower(&pkt.destination, needle),
        Field::IpAddr => {
            str_contains_lower(&pkt.source, needle)
                || str_contains_lower(&pkt.destination, needle)
        }
        Field::Info => str_contains_lower(&pkt.info, needle),
        Field::Proto => pkt.protocol.contains_lower(needle),
        // contains doesn't make sense for numeric fields, but handle gracefully
        Field::PortSrc | Field::PortDst | Field::Port | Field::Len => false,
    }
}

/// Case-insensitive contains without heap allocation.
/// `needle` must already be lowercased.
fn str_contains_lower(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    let needle_bytes = needle.as_bytes();
    haystack
        .as_bytes()
        .windows(needle_bytes.len())
        .any(|window| {
            window
                .iter()
                .zip(needle_bytes)
                .all(|(h, n)| h.to_ascii_lowercase() == *n)
        })
}

fn cmp_str(field_val: &str, op: &CompareOp, value: &Value) -> bool {
    let cmp_val = match value {
        Value::Str(s) => s.as_str(),
        Value::Int(n) => {
            // Avoid recursion + allocation: compare inline
            let s = n.to_string();
            return cmp_str_inner(field_val, op, &s);
        }
    };
    cmp_str_inner(field_val, op, cmp_val)
}

/// All string comparisons are case-insensitive for consistency.
fn cmp_str_inner(field_val: &str, op: &CompareOp, cmp_val: &str) -> bool {
    match op {
        CompareOp::Eq => field_val.eq_ignore_ascii_case(cmp_val),
        CompareOp::Ne => !field_val.eq_ignore_ascii_case(cmp_val),
        CompareOp::Gt => {
            let a = field_val.to_ascii_lowercase();
            let b = cmp_val.to_ascii_lowercase();
            a > b
        }
        CompareOp::Lt => {
            let a = field_val.to_ascii_lowercase();
            let b = cmp_val.to_ascii_lowercase();
            a < b
        }
        CompareOp::Ge => {
            let a = field_val.to_ascii_lowercase();
            let b = cmp_val.to_ascii_lowercase();
            a >= b
        }
        CompareOp::Le => {
            let a = field_val.to_ascii_lowercase();
            let b = cmp_val.to_ascii_lowercase();
            a <= b
        }
    }
}

fn cmp_port(port: Option<u16>, op: &CompareOp, value: &Value) -> bool {
    let port_val = match port {
        Some(p) => p as u64,
        None => return false,
    };
    cmp_int(port_val, op, value)
}

fn cmp_int(field_val: u64, op: &CompareOp, value: &Value) -> bool {
    let cmp_val = match value {
        Value::Int(n) => *n,
        Value::Str(s) => match s.parse::<u64>() {
            Ok(n) => n,
            Err(_) => return false,
        },
    };
    match op {
        CompareOp::Eq => field_val == cmp_val,
        CompareOp::Ne => field_val != cmp_val,
        CompareOp::Gt => field_val > cmp_val,
        CompareOp::Lt => field_val < cmp_val,
        CompareOp::Ge => field_val >= cmp_val,
        CompareOp::Le => field_val <= cmp_val,
    }
}

fn cmp_proto(pkt: &PacketSummary, op: &CompareOp, value: &Value) -> bool {
    let proto_name = match value {
        Value::Str(s) => s.as_str(),
        Value::Int(_) => return false,
    };
    match op {
        CompareOp::Eq => pkt.protocol.matches_str(proto_name),
        CompareOp::Ne => !pkt.protocol.matches_str(proto_name),
        // Ordering doesn't make sense for protocols
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::model::Protocol;
    use crate::filter::parser;

    fn sample_pkt() -> PacketSummary {
        PacketSummary {
            index: 0,
            timestamp: 0.0,
            source: "192.168.1.10".into(),
            destination: "10.0.0.1".into(),
            protocol: Protocol::Tcp,
            length: 1500,
            original_length: 1500,
            info: "54321 → 443 [SYN] Seq=1000 Ack=0 Win=65535".into(),
            src_port: Some(54321),
            dst_port: Some(443),
        }
    }

    fn eval(expr_str: &str) -> bool {
        let expr = parser::parse(expr_str).unwrap();
        matches(&expr, &sample_pkt())
    }

    #[test]
    fn proto_eq() {
        assert!(eval("proto == tcp"));
        assert!(!eval("proto == udp"));
    }

    #[test]
    fn proto_ne() {
        assert!(eval("proto != udp"));
        assert!(!eval("proto != tcp"));
    }

    #[test]
    fn ip_src() {
        assert!(eval("ip.src == 192.168.1.10"));
        assert!(!eval("ip.src == 10.0.0.1"));
    }

    #[test]
    fn ip_dst() {
        assert!(eval("ip.dst == 10.0.0.1"));
    }

    #[test]
    fn ip_addr_either() {
        assert!(eval("ip.addr == 192.168.1.10"));
        assert!(eval("ip.addr == 10.0.0.1"));
        assert!(!eval("ip.addr == 8.8.8.8"));
    }

    #[test]
    fn port_eq() {
        assert!(eval("port == 443"));
        assert!(eval("port == 54321"));
        assert!(!eval("port == 80"));
    }

    #[test]
    fn port_src_dst() {
        assert!(eval("port.src == 54321"));
        assert!(!eval("port.src == 443"));
        assert!(eval("port.dst == 443"));
    }

    #[test]
    fn len_comparison() {
        assert!(eval("len >= 1500"));
        assert!(eval("len == 1500"));
        assert!(!eval("len > 1500"));
        assert!(eval("len > 1000"));
    }

    #[test]
    fn info_contains() {
        assert!(eval("info contains \"SYN\""));
        assert!(eval("info contains \"syn\"")); // case insensitive
        assert!(!eval("info contains \"FIN\""));
    }

    #[test]
    fn boolean_and() {
        assert!(eval("proto == tcp and port == 443"));
        assert!(!eval("proto == tcp and port == 80"));
    }

    #[test]
    fn boolean_or() {
        assert!(eval("proto == tcp or proto == udp"));
        assert!(!eval("proto == arp or proto == dns"));
    }

    #[test]
    fn boolean_not() {
        assert!(eval("not proto == udp"));
        assert!(!eval("not proto == tcp"));
    }

    #[test]
    fn complex_expr() {
        assert!(eval("(proto == tcp or proto == udp) and len > 1000"));
        assert!(!eval("(proto == tcp or proto == udp) and len > 2000"));
    }

    #[test]
    fn no_port_packet() {
        let pkt = PacketSummary {
            index: 0,
            timestamp: 0.0,
            source: "192.168.1.1".into(),
            destination: "192.168.1.2".into(),
            protocol: Protocol::Arp,
            length: 42,
            original_length: 42,
            info: "ARP".into(),
            src_port: None,
            dst_port: None,
        };
        let expr = parser::parse("port == 80").unwrap();
        assert!(!super::matches(&expr, &pkt));
    }

    #[test]
    fn zero_match_filter() {
        // Filter that matches nothing should not crash
        let pkt = sample_pkt();
        let expr = parser::parse("proto == arp").unwrap();
        assert!(!super::matches(&expr, &pkt));
    }

    #[test]
    fn contains_case_insensitive_no_alloc() {
        // Verify the pre-lowercased needle works
        assert!(str_contains_lower("Hello World", "hello"));
        assert!(str_contains_lower("ABCDEF", "cde"));
        assert!(!str_contains_lower("ABC", "abcd"));
        assert!(str_contains_lower("anything", ""));
    }

    #[test]
    fn ip_addr_contains() {
        let pkt = sample_pkt();
        let expr = parser::parse("ip.addr contains \"192.168\"").unwrap();
        assert!(super::matches(&expr, &pkt));
        let expr = parser::parse("ip.addr contains \"10.0\"").unwrap();
        assert!(super::matches(&expr, &pkt));
        let expr = parser::parse("ip.addr contains \"8.8.8\"").unwrap();
        assert!(!super::matches(&expr, &pkt));
    }

    #[test]
    fn len_uses_original_length() {
        // Verify len checks original_length (wire length), not captured length
        let mut pkt = sample_pkt();
        pkt.length = 96; // truncated capture
        pkt.original_length = 1500; // wire length
        let expr = parser::parse("len == 1500").unwrap();
        assert!(super::matches(&expr, &pkt));
        let expr = parser::parse("len == 96").unwrap();
        assert!(!super::matches(&expr, &pkt));
    }
}

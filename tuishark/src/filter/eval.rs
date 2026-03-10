/// Evaluate a filter expression against a PacketSummary.

use crate::dissect::model::PacketSummary;
use super::ast::{CompareOp, Expr, Field, Value};

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
        Field::Len => cmp_int(pkt.length as u64, op, value),
        Field::Info => cmp_str(&pkt.info, op, value),
    }
}

fn eval_contains(field: &Field, needle: &str, pkt: &PacketSummary) -> bool {
    let haystack = match field {
        Field::IpSrc => &pkt.source,
        Field::IpDst => &pkt.destination,
        Field::IpAddr => {
            return pkt.source.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
                || pkt.destination.to_ascii_lowercase().contains(&needle.to_ascii_lowercase());
        }
        Field::Info => &pkt.info,
        Field::Proto => {
            let proto_str = pkt.protocol.to_string();
            return proto_str.to_ascii_lowercase().contains(&needle.to_ascii_lowercase());
        }
        // contains doesn't make sense for numeric fields, but handle gracefully
        Field::PortSrc | Field::PortDst | Field::Port | Field::Len => return false,
    };
    haystack.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
}

fn cmp_str(field_val: &str, op: &CompareOp, value: &Value) -> bool {
    let cmp_val = match value {
        Value::Str(s) => s.as_str(),
        Value::Int(n) => {
            let s = n.to_string();
            return cmp_str(field_val, op, &Value::Str(s));
        }
    };
    match op {
        CompareOp::Eq => field_val.eq_ignore_ascii_case(cmp_val),
        CompareOp::Ne => !field_val.eq_ignore_ascii_case(cmp_val),
        CompareOp::Gt => field_val > cmp_val,
        CompareOp::Lt => field_val < cmp_val,
        CompareOp::Ge => field_val >= cmp_val,
        CompareOp::Le => field_val <= cmp_val,
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
}

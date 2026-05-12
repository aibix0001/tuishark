/// Evaluate a filter expression against a PacketSummary.

use std::net::IpAddr;
use crate::dissect::model::{self, LinkMeta, PacketSummary};
use super::ast::{CompareOp, Expr, Field, Value};

#[must_use]
pub fn matches(expr: &Expr, pkt: &PacketSummary) -> bool {
    match expr {
        Expr::Compare { field, op, value } => eval_compare(field, op, value, pkt),
        Expr::Contains { field, value } => eval_contains(field, value, pkt),
        Expr::ProtoMatch(name) => pkt.protocol.matches_str(name),
        Expr::BareField(field) => eval_bare_field(field, pkt),
        Expr::And(left, right) => matches(left, pkt) && matches(right, pkt),
        Expr::Or(left, right) => matches(left, pkt) || matches(right, pkt),
        Expr::Not(inner) => !matches(inner, pkt),
    }
}

fn eval_bare_field(field: &Field, pkt: &PacketSummary) -> bool {
    match field {
        Field::TcpFlagSyn => pkt.tcp_flags & 0x02 != 0,
        Field::TcpFlagAck => pkt.tcp_flags & 0x10 != 0,
        Field::TcpFlagFin => pkt.tcp_flags & 0x01 != 0,
        Field::TcpFlagRst => pkt.tcp_flags & 0x04 != 0,
        Field::TcpFlagPsh => pkt.tcp_flags & 0x08 != 0,
        Field::TcpFlagUrg => pkt.tcp_flags & 0x20 != 0,
        _ => false,
    }
}

fn eval_compare(field: &Field, op: &CompareOp, value: &Value, pkt: &PacketSummary) -> bool {
    match field {
        Field::IpSrc => cmp_ip(&pkt.source, op, value),
        Field::IpDst => cmp_ip(&pkt.destination, op, value),
        Field::IpAddr => cmp_ip(&pkt.source, op, value) || cmp_ip(&pkt.destination, op, value),
        Field::PortSrc => cmp_port(pkt.src_port, op, value),
        Field::PortDst => cmp_port(pkt.dst_port, op, value),
        Field::Port => cmp_port(pkt.src_port, op, value) || cmp_port(pkt.dst_port, op, value),
        Field::Proto => cmp_proto(pkt, op, value),
        Field::Len => cmp_int(pkt.original_length as u64, op, value),
        Field::Info => cmp_str(&pkt.info, op, value),
        Field::EthSrc => match &pkt.eth_src {
            Some(mac) => cmp_str(mac, op, value),
            None => false,
        },
        Field::EthDst => match &pkt.eth_dst {
            Some(mac) => cmp_str(mac, op, value),
            None => false,
        },
        Field::EthAddr => {
            pkt.eth_src.as_deref().is_some_and(|m| cmp_str(m, op, value))
                || pkt.eth_dst.as_deref().is_some_and(|m| cmp_str(m, op, value))
        },
        Field::VlanId => match pkt.vlan_id {
            Some(vid) => cmp_int(vid as u64, op, value),
            None => false,
        },
        Field::TcpFlagSyn => cmp_int(((pkt.tcp_flags >> 1) & 1) as u64, op, value),
        Field::TcpFlagAck => cmp_int(((pkt.tcp_flags >> 4) & 1) as u64, op, value),
        Field::TcpFlagFin => cmp_int((pkt.tcp_flags & 1) as u64, op, value),
        Field::TcpFlagRst => cmp_int(((pkt.tcp_flags >> 2) & 1) as u64, op, value),
        Field::TcpFlagPsh => cmp_int(((pkt.tcp_flags >> 3) & 1) as u64, op, value),
        Field::TcpFlagUrg => cmp_int(((pkt.tcp_flags >> 5) & 1) as u64, op, value),
        Field::PfAction => match &pkt.link_meta {
            Some(LinkMeta::Pflog(m)) => match m.action.as_str() {
                Some(s) => cmp_str(s, op, value),
                None => cmp_str(&m.action.to_string(), op, value),
            },
            _ => false,
        },
        Field::PfDirection => match &pkt.link_meta {
            Some(LinkMeta::Pflog(m)) => match m.direction.as_str() {
                Some(s) => cmp_str(s, op, value),
                None => cmp_str(&m.direction.to_string(), op, value),
            },
            _ => false,
        },
        Field::PfIfname => match &pkt.link_meta {
            Some(LinkMeta::Pflog(m)) => cmp_str(&m.ifname, op, value),
            _ => false,
        },
        Field::PfRule => match &pkt.link_meta {
            Some(LinkMeta::Pflog(m)) => cmp_int(m.rule_number as u64, op, value),
            _ => false,
        },
        Field::PfReason => match &pkt.link_meta {
            Some(LinkMeta::Pflog(m)) => cmp_str(model::pflog_reason_str(m.reason), op, value),
            _ => false,
        },
        Field::EncSpi => match &pkt.link_meta {
            Some(LinkMeta::Enc(m)) => cmp_int(m.spi as u64, op, value),
            _ => false,
        },
        Field::EncFlags => match &pkt.link_meta {
            Some(LinkMeta::Enc(m)) => match value {
                Value::Str(_) => cmp_str(model::enc_flags_str(m.flags), op, value),
                Value::Int(_) => cmp_int(m.flags as u64, op, value),
                Value::Cidr { .. } => false,
            },
            _ => false,
        },
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
        Field::EthSrc => pkt.eth_src.as_deref().is_some_and(|m| str_contains_lower(m, needle)),
        Field::EthDst => pkt.eth_dst.as_deref().is_some_and(|m| str_contains_lower(m, needle)),
        Field::EthAddr => {
            pkt.eth_src.as_deref().is_some_and(|m| str_contains_lower(m, needle))
                || pkt.eth_dst.as_deref().is_some_and(|m| str_contains_lower(m, needle))
        },
        Field::PfAction => match &pkt.link_meta {
            Some(LinkMeta::Pflog(m)) => match m.action.as_str() {
                Some(s) => str_contains_lower(s, needle),
                None => str_contains_lower(&m.action.to_string(), needle),
            },
            _ => false,
        },
        Field::PfDirection => match &pkt.link_meta {
            Some(LinkMeta::Pflog(m)) => match m.direction.as_str() {
                Some(s) => str_contains_lower(s, needle),
                None => str_contains_lower(&m.direction.to_string(), needle),
            },
            _ => false,
        },
        Field::PfIfname => match &pkt.link_meta {
            Some(LinkMeta::Pflog(m)) => str_contains_lower(&m.ifname, needle),
            _ => false,
        },
        Field::PfReason => match &pkt.link_meta {
            Some(LinkMeta::Pflog(m)) => str_contains_lower(model::pflog_reason_str(m.reason), needle),
            _ => false,
        },
        Field::EncFlags => match &pkt.link_meta {
            Some(LinkMeta::Enc(m)) => str_contains_lower(model::enc_flags_str(m.flags), needle),
            _ => false,
        },
        // contains doesn't make sense for numeric/boolean fields
        Field::PortSrc | Field::PortDst | Field::Port | Field::Len
        | Field::VlanId
        | Field::TcpFlagSyn | Field::TcpFlagAck | Field::TcpFlagFin
        | Field::TcpFlagRst | Field::TcpFlagPsh | Field::TcpFlagUrg
        | Field::PfRule | Field::EncSpi => false,
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

fn cmp_ip(field_val: &str, op: &CompareOp, value: &Value) -> bool {
    // CIDR matching
    if let Value::Cidr { addr, prefix_len } = value {
        let matches_cidr = match (field_val.parse::<IpAddr>(), addr) {
            (Ok(IpAddr::V4(ip)), IpAddr::V4(net)) => {
                let mask = match *prefix_len {
                    0 => 0u32,
                    p if p >= 32 => u32::MAX,
                    p => !0u32 << (32 - p),
                };
                (u32::from(ip) & mask) == (u32::from(*net) & mask)
            }
            (Ok(IpAddr::V6(ip)), IpAddr::V6(net)) => {
                let mask = match *prefix_len {
                    0 => 0u128,
                    p if p >= 128 => u128::MAX,
                    p => !0u128 << (128 - p),
                };
                (u128::from(ip) & mask) == (u128::from(*net) & mask)
            }
            _ => false,
        };
        return match op {
            CompareOp::Eq => matches_cidr,
            CompareOp::Ne => !matches_cidr,
            _ => false,
        };
    }
    // Numeric IP comparison for ordering operators
    if matches!(op, CompareOp::Gt | CompareOp::Lt | CompareOp::Ge | CompareOp::Le) {
        if let Value::Str(s) = value {
            if let (Ok(a), Ok(b)) = (field_val.parse::<IpAddr>(), s.parse::<IpAddr>()) {
                return match op {
                    CompareOp::Gt => a > b,
                    CompareOp::Lt => a < b,
                    CompareOp::Ge => a >= b,
                    CompareOp::Le => a <= b,
                    _ => unreachable!(),
                };
            }
        }
    }
    cmp_str(field_val, op, value)
}

fn cmp_str(field_val: &str, op: &CompareOp, value: &Value) -> bool {
    let cmp_val = match value {
        Value::Str(s) => s.as_str(),
        Value::Int(n) => {
            let s = n.to_string();
            return cmp_str_inner(field_val, op, &s);
        }
        Value::Cidr { .. } => return false,
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
        Value::Cidr { .. } => return false,
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
        Value::Int(_) | Value::Cidr { .. } => return false,
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
    use crate::dissect::model::{EncMeta, PfAction, PfDirection, PflogMeta, Protocol};
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
            link_meta: None,
            eth_src: Some("aa:bb:cc:dd:ee:ff".into()),
            eth_dst: Some("11:22:33:44:55:66".into()),
            vlan_id: Some(100),
            tcp_flags: 0x02, // SYN
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
            link_meta: None,
            eth_src: None,
            eth_dst: None,
            vlan_id: None,
            tcp_flags: 0,
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

    fn pflog_pkt() -> PacketSummary {
        PacketSummary {
            index: 0,
            timestamp: 0.0,
            source: "192.168.1.10".into(),
            destination: "10.0.0.1".into(),
            protocol: Protocol::Pflog,
            length: 100,
            original_length: 100,
            info: "block in on em0".into(),
            src_port: None,
            dst_port: None,
            link_meta: Some(LinkMeta::Pflog(PflogMeta {
                action: PfAction::Block,
                direction: PfDirection::In,
                ifname: "em0".into(),
                rule_number: 42,
                reason: 0,
                header_len: 100,
            })),
            eth_src: None,
            eth_dst: None,
            vlan_id: None,
            tcp_flags: 0,
        }
    }

    fn enc_pkt() -> PacketSummary {
        PacketSummary {
            index: 0,
            timestamp: 0.0,
            source: "10.0.0.1".into(),
            destination: "10.0.0.2".into(),
            protocol: Protocol::Enc,
            length: 200,
            original_length: 200,
            info: "IPsec tunnel".into(),
            src_port: None,
            dst_port: None,
            link_meta: Some(LinkMeta::Enc(EncMeta {
                address_family: 2,
                spi: 0x12345678,
                flags: 3,
            })),
            eth_src: None,
            eth_dst: None,
            vlan_id: None,
            tcp_flags: 0,
        }
    }

    #[test]
    fn pflog_action_filter() {
        let expr = parser::parse("pf.action == block").unwrap();
        assert!(matches(&expr, &pflog_pkt()));
        let expr = parser::parse("pf.action == pass").unwrap();
        assert!(!matches(&expr, &pflog_pkt()));
    }

    #[test]
    fn pflog_ifname_filter() {
        let expr = parser::parse("pf.ifname == em0").unwrap();
        assert!(matches(&expr, &pflog_pkt()));
        let expr = parser::parse("pf.ifname == em1").unwrap();
        assert!(!matches(&expr, &pflog_pkt()));
    }

    #[test]
    fn pflog_rule_filter() {
        let expr = parser::parse("pf.rule == 42").unwrap();
        assert!(matches(&expr, &pflog_pkt()));
        let expr = parser::parse("pf.rule == 99").unwrap();
        assert!(!matches(&expr, &pflog_pkt()));
    }

    #[test]
    fn enc_spi_filter() {
        let expr = parser::parse("enc.spi == 305419896").unwrap(); // 0x12345678
        assert!(matches(&expr, &enc_pkt()));
        let expr = parser::parse("enc.spi == 0").unwrap();
        assert!(!matches(&expr, &enc_pkt()));
    }

    #[test]
    fn enc_flags_filter() {
        // Raw integer comparison still works
        let expr = parser::parse("enc.flags == 3").unwrap();
        assert!(matches(&expr, &enc_pkt()));
    }

    #[test]
    fn enc_flags_string_filter() {
        // Decoded string comparison: display shows "auth+conf", filter should match
        let expr = parser::parse("enc.flags == \"auth+conf\"").unwrap();
        assert!(matches(&expr, &enc_pkt()));
        let expr = parser::parse("enc.flags == auth").unwrap();
        assert!(!matches(&expr, &enc_pkt())); // flags=3 is auth+conf, not just auth
    }

    #[test]
    fn enc_flags_contains_filter() {
        let expr = parser::parse("enc.flags contains \"auth\"").unwrap();
        assert!(matches(&expr, &enc_pkt()));
        let expr = parser::parse("enc.flags contains \"conf\"").unwrap();
        assert!(matches(&expr, &enc_pkt()));
        let expr = parser::parse("enc.flags contains \"none\"").unwrap();
        assert!(!matches(&expr, &enc_pkt()));
    }

    #[test]
    fn pf_filter_no_meta() {
        // pf.* filters return false on non-pflog packets
        let pkt = sample_pkt();
        let expr = parser::parse("pf.action == block").unwrap();
        assert!(!matches(&expr, &pkt));
        let expr = parser::parse("pf.ifname == em0").unwrap();
        assert!(!matches(&expr, &pkt));
        let expr = parser::parse("enc.spi == 12345").unwrap();
        assert!(!matches(&expr, &pkt));
    }

    #[test]
    fn pflog_reason_filter() {
        let expr = parser::parse("pf.reason == match").unwrap();
        assert!(matches(&expr, &pflog_pkt())); // reason=0 → "match"
        let expr = parser::parse("pf.reason == \"bad-offset\"").unwrap();
        assert!(!matches(&expr, &pflog_pkt()));
    }

    #[test]
    fn enc_spi_hex_filter() {
        // Users write hex — verify it works after hex literal parsing
        let expr = parser::parse("enc.spi == 0x12345678").unwrap();
        assert!(matches(&expr, &enc_pkt()));
    }

    #[test]
    fn pflog_contains_filter() {
        let expr = parser::parse("pf.action contains \"blo\"").unwrap();
        assert!(matches(&expr, &pflog_pkt()));
        let expr = parser::parse("pf.ifname contains \"em\"").unwrap();
        assert!(matches(&expr, &pflog_pkt()));
        let expr = parser::parse("pf.direction contains \"in\"").unwrap();
        assert!(matches(&expr, &pflog_pkt()));
    }

    #[test]
    fn len_uses_original_length() {
        let mut pkt = sample_pkt();
        pkt.length = 96;
        pkt.original_length = 1500;
        let expr = parser::parse("len == 1500").unwrap();
        assert!(super::matches(&expr, &pkt));
        let expr = parser::parse("len == 96").unwrap();
        assert!(!super::matches(&expr, &pkt));
    }

    // --- CIDR subnet matching ---

    #[test]
    fn cidr_ipv4_match() {
        assert!(eval("ip.src == 192.168.1.0/24"));
        assert!(eval("ip.addr == 192.168.1.0/24"));
        assert!(!eval("ip.src == 10.1.0.0/16"));
    }

    #[test]
    fn cidr_ipv4_ne() {
        assert!(!eval("ip.src != 192.168.1.0/24"));
        assert!(eval("ip.src != 10.1.0.0/16"));
    }

    #[test]
    fn cidr_dst() {
        assert!(eval("ip.dst == 10.0.0.0/8"));
        assert!(!eval("ip.dst == 172.16.0.0/12"));
    }

    #[test]
    fn cidr_slash_zero_matches_all() {
        assert!(eval("ip.src == 0.0.0.0/0"));
        assert!(eval("ip.dst == 0.0.0.0/0"));
    }

    #[test]
    fn cidr_slash_32_exact() {
        assert!(eval("ip.src == 192.168.1.10/32"));
        assert!(!eval("ip.src == 192.168.1.11/32"));
    }

    // --- Bare protocol name ---

    #[test]
    fn bare_proto_tcp() {
        assert!(eval("tcp"));
        assert!(!eval("udp"));
        assert!(!eval("arp"));
    }

    #[test]
    fn bare_proto_combined() {
        assert!(eval("tcp and port == 443"));
        assert!(!eval("udp or arp"));
    }

    #[test]
    fn bare_proto_not() {
        assert!(eval("not udp"));
        assert!(!eval("not tcp"));
    }

    #[test]
    fn bare_proto_alias() {
        let mut pkt = sample_pkt();
        pkt.protocol = Protocol::Tls;
        let expr = parser::parse("https").unwrap();
        assert!(super::matches(&expr, &pkt));
        let expr = parser::parse("tls").unwrap();
        assert!(super::matches(&expr, &pkt));
    }

    // --- Wireshark field aliases ---

    #[test]
    fn tcp_srcport_alias() {
        assert!(eval("tcp.srcport == 54321"));
        assert!(!eval("tcp.srcport == 443"));
    }

    #[test]
    fn tcp_dstport_alias() {
        assert!(eval("tcp.dstport == 443"));
    }

    #[test]
    fn udp_srcport_alias() {
        assert!(eval("udp.srcport == 54321"));
    }

    #[test]
    fn frame_len_alias() {
        assert!(eval("frame.len == 1500"));
    }

    // --- Expanded protocol classification ---

    #[test]
    fn classify_ssh() {
        let mut pkt = sample_pkt();
        pkt.protocol = Protocol::Ssh;
        let expr = parser::parse("ssh").unwrap();
        assert!(super::matches(&expr, &pkt));
    }

    #[test]
    fn classify_dhcp() {
        let mut pkt = sample_pkt();
        pkt.protocol = Protocol::Dhcp;
        let expr = parser::parse("dhcp").unwrap();
        assert!(super::matches(&expr, &pkt));
    }

    // --- MAC address filter fields ---

    #[test]
    fn eth_src_filter() {
        assert!(eval("eth.src == aa:bb:cc:dd:ee:ff"));
        assert!(!eval("eth.src == 11:22:33:44:55:66"));
    }

    #[test]
    fn eth_dst_filter() {
        assert!(eval("eth.dst == 11:22:33:44:55:66"));
        assert!(!eval("eth.dst == aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn eth_addr_filter() {
        assert!(eval("eth.addr == aa:bb:cc:dd:ee:ff"));
        assert!(eval("eth.addr == 11:22:33:44:55:66"));
        assert!(!eval("eth.addr == 00:00:00:00:00:00"));
    }

    #[test]
    fn eth_contains() {
        assert!(eval("eth.src contains \"aa:bb\""));
        assert!(eval("eth.addr contains \"33:44\""));
    }

    #[test]
    fn eth_no_mac() {
        let mut pkt = sample_pkt();
        pkt.eth_src = None;
        pkt.eth_dst = None;
        let expr = parser::parse("eth.src == aa:bb:cc:dd:ee:ff").unwrap();
        assert!(!super::matches(&expr, &pkt));
    }

    // --- VLAN ---

    #[test]
    fn vlan_id_filter() {
        assert!(eval("vlan.id == 100"));
        assert!(!eval("vlan.id == 200"));
        assert!(eval("vlan.id > 50"));
    }

    #[test]
    fn vlan_no_tag() {
        let mut pkt = sample_pkt();
        pkt.vlan_id = None;
        let expr = parser::parse("vlan.id == 100").unwrap();
        assert!(!super::matches(&expr, &pkt));
    }

    // --- TCP flags ---

    #[test]
    fn tcp_flags_bare() {
        assert!(eval("tcp.flags.syn"));
        assert!(!eval("tcp.flags.ack"));
        assert!(!eval("tcp.flags.fin"));
        assert!(!eval("tcp.flags.rst"));
    }

    #[test]
    fn tcp_flags_compare() {
        assert!(eval("tcp.flags.syn == 1"));
        assert!(eval("tcp.flags.ack == 0"));
    }

    #[test]
    fn tcp_flags_combined() {
        let mut pkt = sample_pkt();
        pkt.tcp_flags = 0x12; // SYN+ACK
        let expr = parser::parse("tcp.flags.syn and tcp.flags.ack").unwrap();
        assert!(super::matches(&expr, &pkt));
        let expr = parser::parse("tcp.flags.fin").unwrap();
        assert!(!super::matches(&expr, &pkt));
    }

    #[test]
    fn tcp_flags_not() {
        assert!(eval("not tcp.flags.rst"));
        assert!(!eval("not tcp.flags.syn"));
    }

    // --- IPv6 address tokenization ---

    #[test]
    fn ipv6_filter() {
        let mut pkt = sample_pkt();
        pkt.source = "2001:db8::1".into();
        pkt.destination = "fe80::1".into();
        let expr = parser::parse("ip.src == 2001:db8::1").unwrap();
        assert!(super::matches(&expr, &pkt));
        let expr = parser::parse("ip.dst == fe80::1").unwrap();
        assert!(super::matches(&expr, &pkt));
    }

    #[test]
    fn ipv6_cidr() {
        let mut pkt = sample_pkt();
        pkt.source = "2001:db8::1".into();
        let expr = parser::parse("ip.src == 2001:db8::/32").unwrap();
        assert!(super::matches(&expr, &pkt));
        let expr = parser::parse("ip.src == fe80::/10").unwrap();
        assert!(!super::matches(&expr, &pkt));
    }

    // --- Numeric IP comparison ---

    #[test]
    fn ip_numeric_ordering() {
        assert!(eval("ip.src > 192.168.1.1"));
        assert!(eval("ip.src < 192.168.2.0"));
        assert!(eval("ip.dst >= 10.0.0.1"));
        assert!(eval("ip.dst <= 10.0.0.1"));
    }
}

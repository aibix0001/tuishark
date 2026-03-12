use std::net::IpAddr;

use super::lookup::IpInfo;

struct SpecialRange {
    rfc: &'static str,
    title: &'static str,
}

/// Check if an IP address belongs to a special-use range (RFC1918, etc.).
/// Returns `Some(IpInfo)` with RFC number as ASN and RFC title as AS name.
pub fn check_special(addr: IpAddr) -> Option<IpInfo> {
    let range = match addr {
        IpAddr::V4(v4) => check_v4(v4.octets()),
        IpAddr::V6(v6) => check_v6(v6.octets()),
    }?;

    Some(IpInfo {
        address: addr.to_string(),
        asn: range.rfc.to_string(),
        as_name: range.title.to_string(),
        country: "N/A".to_string(),
        rir: "N/A".to_string(),
        is_special: true,
        error: None,
    })
}

fn check_v4(o: [u8; 4]) -> Option<SpecialRange> {
    // 0.0.0.0/8
    if o[0] == 0 {
        return Some(SpecialRange {
            rfc: "RFC1122",
            title: "This Network",
        });
    }
    // 10.0.0.0/8
    if o[0] == 10 {
        return Some(SpecialRange {
            rfc: "RFC1918",
            title: "Address Allocation for Private Internets",
        });
    }
    // 100.64.0.0/10
    if o[0] == 100 && (o[1] & 0xC0) == 64 {
        return Some(SpecialRange {
            rfc: "RFC6598",
            title: "IANA-Reserved IPv4 Prefix for Shared Address Space",
        });
    }
    // 127.0.0.0/8
    if o[0] == 127 {
        return Some(SpecialRange {
            rfc: "RFC1122",
            title: "Loopback",
        });
    }
    // 169.254.0.0/16
    if o[0] == 169 && o[1] == 254 {
        return Some(SpecialRange {
            rfc: "RFC3927",
            title: "Dynamic Configuration of IPv4 Link-Local Addresses",
        });
    }
    // 172.16.0.0/12
    if o[0] == 172 && (o[1] & 0xF0) == 16 {
        return Some(SpecialRange {
            rfc: "RFC1918",
            title: "Address Allocation for Private Internets",
        });
    }
    // 192.0.2.0/24
    if o[0] == 192 && o[1] == 0 && o[2] == 2 {
        return Some(SpecialRange {
            rfc: "RFC5737",
            title: "IPv4 Address Blocks Reserved for Documentation",
        });
    }
    // 192.168.0.0/16
    if o[0] == 192 && o[1] == 168 {
        return Some(SpecialRange {
            rfc: "RFC1918",
            title: "Address Allocation for Private Internets",
        });
    }
    // 198.18.0.0/15
    if o[0] == 198 && (o[1] & 0xFE) == 18 {
        return Some(SpecialRange {
            rfc: "RFC2544",
            title: "Benchmarking Methodology for Network Interconnect Devices",
        });
    }
    // 198.51.100.0/24
    if o[0] == 198 && o[1] == 51 && o[2] == 100 {
        return Some(SpecialRange {
            rfc: "RFC5737",
            title: "IPv4 Address Blocks Reserved for Documentation",
        });
    }
    // 203.0.113.0/24
    if o[0] == 203 && o[1] == 0 && o[2] == 113 {
        return Some(SpecialRange {
            rfc: "RFC5737",
            title: "IPv4 Address Blocks Reserved for Documentation",
        });
    }
    // 224.0.0.0/4 — Multicast
    if (o[0] & 0xF0) == 224 {
        return Some(SpecialRange {
            rfc: "RFC5771",
            title: "IANA IPv4 Multicast Address Space",
        });
    }
    // 255.255.255.255/32 — must come before 240.0.0.0/4
    if o == [255, 255, 255, 255] {
        return Some(SpecialRange {
            rfc: "RFC919",
            title: "Limited Broadcast",
        });
    }
    // 240.0.0.0/4
    if (o[0] & 0xF0) == 240 {
        return Some(SpecialRange {
            rfc: "RFC1112",
            title: "Reserved for Future Use",
        });
    }
    None
}

fn check_v6(o: [u8; 16]) -> Option<SpecialRange> {
    // ::/128 — Unspecified address
    if o == [0; 16] {
        return Some(SpecialRange {
            rfc: "RFC4291",
            title: "Unspecified Address",
        });
    }
    // ::1/128
    if o == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] {
        return Some(SpecialRange {
            rfc: "RFC4291",
            title: "Loopback Address",
        });
    }
    // fc00::/7
    if (o[0] & 0xFE) == 0xFC {
        return Some(SpecialRange {
            rfc: "RFC4193",
            title: "Unique Local IPv6 Unicast Addresses",
        });
    }
    // fe80::/10
    if o[0] == 0xFE && (o[1] & 0xC0) == 0x80 {
        return Some(SpecialRange {
            rfc: "RFC4291",
            title: "Link-Local IPv6 Unicast Addresses",
        });
    }
    // 2001:db8::/32
    if o[0] == 0x20 && o[1] == 0x01 && o[2] == 0x0D && o[3] == 0xB8 {
        return Some(SpecialRange {
            rfc: "RFC3849",
            title: "IPv6 Address Prefix Reserved for Documentation",
        });
    }
    // ff00::/8
    if o[0] == 0xFF {
        return Some(SpecialRange {
            rfc: "RFC4291",
            title: "IPv6 Multicast",
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ipv4_rfc1918() {
        let info = check_special("10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(info.asn, "RFC1918");
        assert!(info.is_special);

        let info = check_special("172.16.5.1".parse().unwrap()).unwrap();
        assert_eq!(info.asn, "RFC1918");

        let info = check_special("192.168.1.100".parse().unwrap()).unwrap();
        assert_eq!(info.asn, "RFC1918");
    }

    #[test]
    fn loopback_ipv4() {
        let info = check_special("127.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(info.asn, "RFC1122");
        assert_eq!(info.as_name, "Loopback");
    }

    #[test]
    fn cgnat_rfc6598() {
        let info = check_special("100.64.0.1".parse().unwrap()).unwrap();
        assert_eq!(info.asn, "RFC6598");
    }

    #[test]
    fn link_local_ipv4() {
        let info = check_special("169.254.1.1".parse().unwrap()).unwrap();
        assert_eq!(info.asn, "RFC3927");
    }

    #[test]
    fn documentation_ipv4() {
        let info = check_special("192.0.2.1".parse().unwrap()).unwrap();
        assert_eq!(info.asn, "RFC5737");

        let info = check_special("198.51.100.1".parse().unwrap()).unwrap();
        assert_eq!(info.asn, "RFC5737");

        let info = check_special("203.0.113.1".parse().unwrap()).unwrap();
        assert_eq!(info.asn, "RFC5737");
    }

    #[test]
    fn public_ipv4_returns_none() {
        assert!(check_special("1.1.1.1".parse().unwrap()).is_none());
        assert!(check_special("8.8.8.8".parse().unwrap()).is_none());
    }

    #[test]
    fn ipv6_loopback() {
        let info = check_special("::1".parse().unwrap()).unwrap();
        assert_eq!(info.asn, "RFC4291");
        assert_eq!(info.as_name, "Loopback Address");
    }

    #[test]
    fn ipv6_ula() {
        let info = check_special("fd00::1".parse().unwrap()).unwrap();
        assert_eq!(info.asn, "RFC4193");
    }

    #[test]
    fn ipv6_link_local() {
        let info = check_special("fe80::1".parse().unwrap()).unwrap();
        assert_eq!(info.asn, "RFC4291");
        assert_eq!(info.as_name, "Link-Local IPv6 Unicast Addresses");
    }

    #[test]
    fn ipv6_multicast() {
        let info = check_special("ff02::1".parse().unwrap()).unwrap();
        assert_eq!(info.asn, "RFC4291");
        assert_eq!(info.as_name, "IPv6 Multicast");
    }

    #[test]
    fn ipv6_documentation() {
        let info = check_special("2001:db8::1".parse().unwrap()).unwrap();
        assert_eq!(info.asn, "RFC3849");
    }

    #[test]
    fn public_ipv6_returns_none() {
        assert!(check_special("2606:4700::1111".parse().unwrap()).is_none());
    }

    #[test]
    fn multicast_ipv4() {
        let info = check_special("224.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(info.asn, "RFC5771");

        let info = check_special("239.255.255.250".parse().unwrap()).unwrap();
        assert_eq!(info.asn, "RFC5771");
    }

    #[test]
    fn broadcast_ipv4() {
        let info = check_special("255.255.255.255".parse().unwrap()).unwrap();
        assert_eq!(info.asn, "RFC919");
        assert_eq!(info.as_name, "Limited Broadcast");
    }

    #[test]
    fn reserved_ipv4() {
        let info = check_special("240.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(info.asn, "RFC1112");
        assert_eq!(info.as_name, "Reserved for Future Use");
    }

    #[test]
    fn ipv6_unspecified() {
        let info = check_special("::".parse().unwrap()).unwrap();
        assert_eq!(info.asn, "RFC4291");
        assert_eq!(info.as_name, "Unspecified Address");
    }
}

---
title: Display Filter Engine
date: 2026-05-12
author: Claude
status: current
related_issues:
  - "#8"
  - "#9"
related_mrs: []
---

## Overview

TuiShark includes a Wireshark-compatible display filter engine for narrowing packets by protocol, address, port, flags, and more. Press `/` to activate the filter bar, type a filter expression, and press Enter to apply.

## Usage

### Basic Filters

```
tcp                          # bare protocol name
proto == udp                 # explicit protocol comparison
ip.src == 192.168.1.1        # source IP
ip.addr == 10.0.0.0/8        # CIDR subnet (either src or dst)
port == 443                  # either source or destination port
tcp.dstport == 22            # Wireshark-style alias
frame.len > 1000             # wire length
info contains "SYN"          # case-insensitive substring
```

### Boolean Logic

```
tcp and port == 80
tcp or udp
not arp
(tcp or udp) and port == 443
```

Operators: `and` / `&&`, `or` / `||`, `not` / `!`, parentheses for grouping.

### CIDR Subnet Matching

Match addresses against a subnet with standard CIDR notation:

```
ip.src == 192.168.0.0/16
ip.addr == 10.0.0.0/8
ip.dst == 2001:db8::/32
```

Supports both IPv4 and IPv6 CIDR. Only `==` and `!=` operators work with CIDR values.

### Bare Protocol Names

Type a protocol name without any operator to match all packets of that protocol:

```
tcp          # same as proto == tcp
ssh          # matches port 22 traffic
dhcp         # matches port 67/68 traffic
not arp      # exclude ARP
```

All known protocol names work: tcp, udp, icmp, icmpv6, arp, dns, http, tls/https, ssh, smtp, ftp, telnet, rdp, bgp, ldap, dhcp, ntp, snmp, syslog, tftp, mdns, radius, ipv4/ip, ipv6, ethernet/eth, pflog/pf, enc/ipsec.

### TCP Flags

Filter by individual TCP flags using bare field syntax or comparison:

```
tcp.flags.syn                  # SYN flag set (bare)
tcp.flags.syn and tcp.flags.ack  # SYN+ACK
not tcp.flags.rst              # no RST
tcp.flags.fin == 1             # explicit comparison
```

Available flags: `tcp.flags.syn`, `tcp.flags.ack`, `tcp.flags.fin`, `tcp.flags.rst`, `tcp.flags.psh`, `tcp.flags.urg`.

### MAC Address Filters

Filter by Ethernet source/destination MAC address:

```
eth.src == aa:bb:cc:dd:ee:ff
eth.dst == 11:22:33:44:55:66
eth.addr == aa:bb:cc:dd:ee:ff   # matches either src or dst
eth.addr contains "aa:bb"       # substring match
```

Only available for Ethernet-framed captures. Returns false for raw IP, pflog, enc link types.

### VLAN Filtering

Filter by 802.1Q VLAN tag ID:

```
vlan.id == 100
vlan.id > 50 and vlan.id < 200
```

Only matches packets with a VLAN tag present.

### IPv6 Addresses

IPv6 addresses work natively without quoting:

```
ip.src == 2001:db8::1
ip.dst == fe80::1
ip.addr == ::1
```

### Numeric IP Comparison

IP address ordering uses numeric comparison (not lexicographic):

```
ip.src > 192.168.1.0
ip.dst <= 10.255.255.255
```

## Field Reference

| Field | Type | Description |
|---|---|---|
| `ip.src` | string | Source IP address |
| `ip.dst` | string | Destination IP address |
| `ip.addr` | string | Either source or destination IP |
| `port` / `port.src` / `port.dst` | integer | TCP/UDP port |
| `tcp.srcport` / `udp.srcport` | integer | Alias for `port.src` |
| `tcp.dstport` / `udp.dstport` | integer | Alias for `port.dst` |
| `proto` | string | Protocol name |
| `len` / `frame.len` | integer | Wire length (original, not captured) |
| `info` | string | Packet info/summary line |
| `eth.src` / `eth.dst` / `eth.addr` | string | MAC address (Ethernet only) |
| `vlan.id` | integer | 802.1Q VLAN identifier |
| `tcp.flags.syn/ack/fin/rst/psh/urg` | boolean | Individual TCP flags |
| `pf.action` | string | pflog action (pass/block/etc.) |
| `pf.direction` / `pf.dir` | string | pflog direction (in/out/fwd) |
| `pf.ifname` / `pf.interface` | string | pflog interface name |
| `pf.rule` | integer | pflog rule number |
| `pf.reason` | string | pflog reason code |
| `enc.spi` | integer | IPsec SPI value |
| `enc.flags` | string/int | IPsec enc flags |

## Semantics Note: `ip.addr !=`

The filter `ip.addr != X` uses OR-based expansion: it matches packets where *either* the source or destination address differs from X. This means almost every packet matches, because even if src equals X, dst likely doesn't.

This is the same behavior as Wireshark. To exclude all packets involving address X, use:

```
!(ip.addr == X)
```

This wraps the equality check in NOT, ensuring both src and dst are checked together.

## Protocol Classification

Protocols are classified by well-known port numbers:

**TCP:** HTTP (80, 8080), TLS (443), SSH (22), SMTP (25, 465, 587), FTP (20, 21), Telnet (23), RDP (3389), BGP (179), LDAP (389, 636)

**UDP:** DNS (53), DHCP (67, 68), NTP (123), SNMP (161, 162), Syslog (514), TFTP (69), mDNS (5353), RADIUS (1812, 1813)

## Technical Details

- Recursive descent parser: `filter/parser.rs`
- AST: `filter/ast.rs`
- Evaluator: `filter/eval.rs`
- Filter bar: persistent 1-line row, `/` to activate, Enter/Esc to apply/cancel
- String comparisons are case-insensitive
- `contains` needle is pre-lowercased at parse time for zero-alloc matching
- `len` uses original wire length, not captured length

---
title: "Non-Ethernet Link Type Support"
date: 2026-03-13
author: agent
status: active
related_issues: ["#31"]
related_mrs: []
---

## Overview

TuiShark now supports multiple link-layer types beyond Ethernet, enabling capture and analysis on loopback, tunnel, firewall log, and IPsec interfaces. This is a prerequisite for FreeBSD/OPNsense portability (Phase 11) and network visibility features (Phases 14-17).

## Supported Link Types

| Link Type | DLT Value | Header Size | Description |
|-----------|-----------|-------------|-------------|
| Ethernet | 1 | 14 bytes | Standard Ethernet II (existing) |
| Raw IP | 101, 228, 229 | 0 bytes | IPv4/IPv6 directly (tun/tap, loopback on some systems) |
| BSD Loopback (Null) | 0 | 4 bytes | BSD loopback with address family prefix |
| Linux SLL | 113 | 16 bytes | Linux cooked capture (any interface, tcpdump -i any) |
| pflog | 117 | variable (48+) | FreeBSD/OPNsense firewall log with rule metadata |
| enc | 109 | 12 bytes | IPsec tunnel encapsulation with SPI and flags |

## Usage

No user action required. TuiShark automatically detects the link type from the pcap file header or live capture interface and dispatches to the appropriate parser. Previously rejected interfaces (loopback, tun/tap, pflog0) now work transparently.

### pflog Metadata

When capturing on pflog interfaces (OPNsense/FreeBSD), each packet carries firewall metadata visible in the info column and detail tree:

- **Action**: pass, block, match, scrub, nat, rdr, binat
- **Direction**: in, out
- **Interface**: the interface the rule matched on (e.g., em0, igb0)
- **Rule Number**: the pf rule number that matched
- **Reason**: match reason code

### enc Metadata

For IPsec tunnel captures on enc interfaces, each packet shows:

- **Address Family**: IPv4 (2) or IPv6
- **SPI**: Security Parameter Index identifying the SA
- **Flags**: enc header flags

## Configuration

No configuration needed. The link type is auto-detected per capture session.

## Technical Details

### Architecture

- `LinkType` enum in `dissect/model.rs` maps pcap DLT values to internal types via `from_pcap()`/`to_pcap()`
- `PacketStore` stores one `LinkType` per session (set at capture start or file open)
- `parse_packet_with_wire_len()` dispatches to `etherparse::SlicedPacket::from_ethernet()`, `from_ip()`, `from_linux_sll()`, or custom parsers based on link type
- `dissect_detail()` produces correct `Layer` entries and byte ranges for each link type
- `LinkMeta` enum on `PacketSummary` carries pflog/enc metadata for downstream use

### Parser Dispatch

```
LinkType::Ethernet  -> SlicedPacket::from_ethernet(data)
LinkType::RawIp     -> SlicedPacket::from_ip(data)
LinkType::LinuxSll  -> SlicedPacket::from_linux_sll(data)
LinkType::Null      -> skip 4-byte AF header, then from_ip()
LinkType::Pflog     -> parse pflog header, then from_ip(payload)
LinkType::Enc       -> parse 12-byte enc header, then from_ip(payload)
```

### Key Files

- `tuishark/src/dissect/model.rs` -- LinkType, LinkMeta, PflogMeta, EncMeta, Protocol::Pflog/Enc
- `tuishark/src/dissect/fast.rs` -- parse_pflog_header(), parse_enc_header(), dispatch logic
- `tuishark/src/capture/live.rs` -- link type detection on live capture
- `tuishark/src/capture/file.rs` -- link type detection on file open, returned to caller
- `tuishark/src/capture/save.rs` -- uses stored link type for pcap output
- `tuishark/src/store/packet_store.rs` -- link_type field per session

### pflog Header Format (FreeBSD net/pflog.h)

```
Offset  Size  Field
0       1     header length
1       1     address family
2       1     action (pass=0, block=1, ...)
3       1     reason
4       16    interface name (null-terminated)
20      4     rule number (big-endian)
24      20    (subrule, uid, pid, rule_uid, rule_pid)
44      1     direction (in=0, out=1)
45      3     padding
48+     ...   IP payload
```

### enc Header Format (FreeBSD net/if_enc.h)

```
Offset  Size  Field
0       4     address family (host-endian)
4       4     SPI (host-endian)
8       4     flags (host-endian)
12+     ...   IP payload
```

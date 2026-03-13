---
title: "Roadmap: FreeBSD Portability & Network Visibility"
date: 2026-03-13
author: agent
status: active
related_issues: ["#31", "#32"]
related_mrs: []
---

## Overview

Two major goals for TuiShark's next evolution:

- **Goal A:** Multi-platform support (FreeBSD/OPNsense)
- **Goal B:** Network visibility tool (packet paths, processing steps, drop points on routers -- Linux, FreeBSD, FRR)

**Decision: FreeBSD portability first**, then network visibility. Rationale below.

## Why FreeBSD First

1. **90% already portable.** Core app (TUI, parsing, filters, stats, export, config) is cross-platform. eBPF is feature-gated behind `trace`.
2. **Shared prerequisite.** Non-Ethernet link type support (pflog, enc, raw IP) is needed by both goals. OPNsense uses these interfaces.
3. **Abstraction before features.** Platform trait layer established before visibility work begins -- each feature designed cross-platform from day one.
4. **Faster user value.** Basic packet analysis on OPNsense achievable in 2-3 sub-phases.
5. **pflog is free visibility.** Capturing on pflog0 gives firewall rule/action/direction in the header -- no kernel tracing needed.

## Dependency Graph

```
Phase 10: Non-Ethernet Link Types <-- shared prerequisite
    |
    +---> Phase 11: FreeBSD Base Port
    |        |
    |        +---> Phase 12: FreeBSD CI + Packaging
    |                 |
    |                 +---> Phase 13: Platform Trait Abstraction
    |                          |
    |                          +---> Phase 14: Linux Network Visibility
    |                          +---> Phase 15: FreeBSD Network Visibility  (parallel)
    |                          +---> Phase 16: FRR Integration             (parallel)
    |                          +---> Phase 17: Visibility UI
```

## Phase 10: Non-Ethernet Link Type Support

Both goals need this. OPNsense uses pflog/enc/raw IP. The Ethernet-only restriction blocks FreeBSD and limits Linux too (no loopback, no tun/tap).

### 10a: Link type registry and parser dispatch

- `LinkType` enum: Ethernet, RawIp, RawIpv4, RawIpv6, Pflog, Enc, LinuxSll, Null (BSD loopback)
- Store link type in `PacketStore` (set once per capture)
- Replace `SlicedPacket::from_ethernet()` with dispatch: `parse_link_layer(link_type, data)`
- Remove Ethernet-only bail in `capture/live.rs:68`, `capture/file.rs:19`
- Update `capture/save.rs:19` to use stored link type

### 10b: pflog and enc header parsing

- pflog header parser (48 bytes): action (pass/block), direction (in/out), interface name, rule number, reason
- enc header parser (12 bytes): address family, SPI, flags
- Store pflog/enc metadata in `PacketSummary` or new `LinkMeta` struct
- Add `Protocol::Pflog`, `Protocol::Enc` variants

### 10c: Detail tree and hex view updates

- Extend `dissect_detail()` for pflog/enc/raw headers as `Layer` entries
- Update hex view byte ranges for non-14-byte link headers

**Key files:** `dissect/fast.rs`, `capture/live.rs`, `capture/file.rs`, `capture/save.rs`

## Phase 11: FreeBSD Base Port

Get TuiShark compiling and running on FreeBSD without the `trace` feature.

### 11a: Build system and dependency audit

- Verify all crate deps compile on FreeBSD
- Check `libc::timeval` / `time_t` / `suseconds_t` types on FreeBSD
- Verify `dirs::config_dir()`, `libc::mkfifo`, signal handling
- The `#[cfg(not(feature = "trace"))]` stubs already handle no-eBPF builds

### 11b: Platform-specific adjustments

- Any `#[cfg(target_os)]` needed for type differences
- Test pcap with FreeBSD interface names (em0, igb0, ovpns1, pflog0)
- Verify tshark integration (`pkg install tshark`)

### 11c: OPNsense testing

- Live capture on pflog0, WAN, LAN interfaces
- Interface picker with FreeBSD interface names
- File open/save round-trip with pflog link type

**Key files:** `capture/save.rs`, `cli.rs`, `Cargo.toml`

## Phase 12: FreeBSD CI + Packaging

- Cross-compile from Linux using cross-rs (no FreeBSD runner)
- Add FreeBSD job to `.gitlab-ci.yml`
- FreeBSD pkg manifest or OPNsense plugin packaging
- Ensure `cargo test` passes under cross

## Phase 13: Platform Trait Abstraction Layer

Network visibility features need OS-specific backends. Build the trait hierarchy before implementing them.

```rust
pub trait FirewallInspector: Send { ... }
pub trait RoutingInspector: Send { ... }
pub trait PacketPathTracer: Send { ... }
pub trait ProcessIdentifier: Send { ... }
```

- Refactor existing eBPF `TraceEngine`/`PathTraceEngine` to implement traits behind `#[cfg(target_os = "linux")]`
- `App` holds `Box<dyn Trait>` instead of concrete types
- Generalize `PathHop`/`PacketPath` to string-based step names
- FreeBSD stubs return `None`/`Unavailable` (extended in Phase 15)

**Key files:** `trace/engine.rs`, `trace/path_engine.rs`, `trace/path_model.rs`, `app.rs`

## Phase 14: Linux Network Visibility

### 14a: Netfilter/nftables rule matching

- Extend `nf_hook_slow` kprobe to capture verdict and hook number
- Kprobe on `nft_trace` tracepoint for specific rule match
- Cache `nft list ruleset` at startup, map rule IDs to names
- Implement `FirewallInspector` for Linux

### 14b: Routing decision tracking

- Kprobes on `fib_lookup`, `ip_route_output_key` for route selection and next-hop
- Implement `RoutingInspector` for Linux (eBPF + netlink fallback)

### 14c: Drop detection

- Kprobe on `kfree_skb_reason` (Linux 5.17+) for drop reason enum
- Map drop reason codes to human-readable strings
- Extend `PacketPath` with `drop_point` field

## Phase 15: FreeBSD Network Visibility

### 15a: pf rule matching via pflog

- pflog headers already contain rule number + action (parsed in Phase 10b)
- Correlate rule numbers with `pfctl -sr -v` output
- For non-pflog packets, use `pfctl -ss` (state table)
- Implement `FirewallInspector` for FreeBSD

### 15b: FreeBSD routing

- Implement `RoutingInspector` via routing socket (`PF_ROUTE`) or `sysctl net.route`
- Route lookup via programmatic FIB lookup

### 15c: DTrace-based path tracing (optional/advanced)

- FreeBSD's DTrace `fbt` provider traces kernel functions like kprobes
- Trace `ip_input`, `pf_test`, `ip_output`, `ip_forward`, `ether_output`
- Subprocess-based (like rtshark wraps tshark)
- Implement `PacketPathTracer` for FreeBSD

## Phase 16: FRR Integration (Cross-Platform)

- FRR provides `vtysh` CLI and management socket (MGMT API in FRR 9.1+)
- Works identically on Linux and FreeBSD (FRR deployed on both)
- Query: route origin (BGP/OSPF/static), AS path, next-hop, route age
- New `FrrInspector` with single cross-platform implementation
- Config option for FRR socket path

## Phase 17: Visibility UI

- **Pipeline view:** ASCII diagram of packet flow (NIC -> firewall -> routing -> forward -> egress) with per-stage status
- **Firewall rule overlay:** New "Firewall" layer in detail tree
- **Route overlay:** New "Routing" layer in detail tree
- **Drop indicator:** Red marker in packet list, drop reason in info column
- **Stats integration:** Drop reasons tab, firewall action breakdown

## Parallel Tracks After Phase 13

Phases 14, 15, and 16 are independent and can proceed in parallel once the trait layer is in place.

## Environment

- **Test target:** OPNsense box available for direct SSH testing
- **FRR:** Running on both OPNsense (os-frr plugin) and separate Linux routers
- **CI strategy:** Cross-compile from Linux using cross-rs

## Risks

| Risk | Mitigation |
|------|------------|
| FreeBSD `pcap` crate compat | libpcap is native on FreeBSD; test early with cross-compile |
| pflog header format changes | Parse based on header length field, not hardcoded 48 bytes |
| DTrace integration complexity | Start with pflog-based visibility (80% value); DTrace is optional |
| `kfree_skb_reason` only on Linux 5.17+ | Graceful fallback (same pattern as existing kprobe attachment) |
| Hardcoded kernel struct offsets | Existing issue #27 (CO-RE/BTF migration) |

## Verification

- **Phase 10:** Open OPNsense-captured pcap files (pflog, enc) and verify correct parsing; live capture on loopback
- **Phase 11:** Cross-compile with `cross build --target x86_64-unknown-freebsd`; deploy to OPNsense, test live capture on WAN/LAN/pflog0
- **Phase 12:** CI produces FreeBSD binary automatically; `cargo test` passes under cross
- **Phase 13:** Existing Linux eBPF tracing works identically through trait layer; FreeBSD build compiles with stubs
- **Phase 14:** On Linux router with nftables, see matched rule per packet; routing decisions; drop events
- **Phase 15:** On OPNsense, see pf rule per packet via pflog; routing table and route lookups
- **Phase 16:** On both OPNsense and Linux FRR routers, see BGP/OSPF route origin and AS path
- **Phase 17:** Unified pipeline view works on both platforms

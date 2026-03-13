---
title: "FreeBSD Port (Phase 11)"
date: 2026-03-13
author: agent
status: active
related_issues: [32]
related_mrs: [32]
---

## Overview

TuiShark compiles and runs on FreeBSD (specifically OPNsense) without the `trace` feature.
The eBPF tracing subsystem is Linux-only and already feature-gated behind `#[cfg(feature = "trace")]`;
FreeBSD builds skip it entirely.

## Portability Audit

All dependencies compile for `x86_64-unknown-freebsd` without modification:

| Crate | Status | Notes |
|---|---|---|
| `ratatui` / `crossterm` | OK | Cross-platform terminal I/O |
| `pcap` | OK | Wraps libpcap via FFI; libpcap is native on FreeBSD |
| `etherparse` | OK | Pure Rust, no platform dependencies |
| `libc` | OK | FreeBSD x86_64: `time_t`=i64, `suseconds_t`=i64 (matches Linux); 32-bit FreeBSD: `suseconds_t`=i32 |
| `dirs` | OK | Returns `~/.config/` on FreeBSD via XDG |
| `rtshark` | OK | Spawns `tshark` subprocess; works if tshark is installed |
| `clap` / `serde` / `toml` | OK | Pure Rust |
| `aya` (optional) | Skipped | Feature-gated behind `trace`; not compiled on FreeBSD |

## Platform-Specific Notes

### libc types

On FreeBSD x86_64, `time_t` and `suseconds_t` are both `i64`, identical to Linux x86_64.
On 32-bit FreeBSD (ARM, PowerPC), `suseconds_t` is `i32`. The code in `save.rs` casts
directly to `libc::suseconds_t` rather than through an intermediate `i64` to avoid
silent truncation on 32-bit platforms.

### Signal handling

`libc::signal()` with `SIGINT`/`SIGTERM` uses POSIX APIs that are identical on FreeBSD.
`sighandler_t` is `size_t` on all Unix platforms in the `libc` crate.

### FIFO (named pipe)

`libc::mkfifo()` is POSIX and works identically on FreeBSD for tshark deep dissection.
`std::env::temp_dir()` returns `/tmp` on FreeBSD (same as Linux); OPNsense does not
mount `/tmp` as `noexec`, so FIFO creation works without issues.

### Config directory

`dirs::config_dir()` returns `~/.config/` on FreeBSD (XDG standard), same as Linux.

### Permissions for live capture

On FreeBSD, live packet capture requires read access to `/dev/bpf*` devices.
Unlike Linux where `CAP_NET_RAW` capability suffices, FreeBSD uses BPF device nodes:

- **Root access** is the simplest approach (typical for OPNsense)
- Alternatively, `chmod 0640 /dev/bpf*` and add the user to a group with access

Note: the error message "need root or CAP_NET_RAW?" in the capture module is
Linux-specific terminology. On FreeBSD, root is the standard approach.

## Supported Link Types on FreeBSD

| Interface | Link Type | DLT | Notes |
|---|---|---|---|
| `em0`, `igb0`, `ix0`, `vtnet0` | Ethernet | 1 | WAN/LAN physical interfaces |
| `pflog0` | Pflog | 117 | Firewall log — primary OPNsense debugging tool |
| `enc0` | Enc | 109 | IPsec tunnel traffic (Phase 2 debugging) |
| `lo0` | Null/Loopback | 0 | BSD loopback — 4-byte AF header in host byte order |
| `ovpnc1`, `ovpns1` | Ethernet | 1 | OpenVPN tunnel interfaces |
| `wg1` | Ethernet | 1 | WireGuard tunnel interfaces |
| `lagg0`, `vlan100`, `bridge0` | Ethernet | 1 | Aggregation, VLAN, bridge interfaces |

All link types listed above are supported by TuiShark's parser.

## Cross-Compilation

### Type checking (no linker)

```sh
rustup target add x86_64-unknown-freebsd
cargo check --target x86_64-unknown-freebsd -p tuishark
```

### Full build (requires cross + Docker)

```sh
cargo install cross
cross build --target x86_64-unknown-freebsd -p tuishark --release
```

A `Cross.toml` is provided at the repository root. The FreeBSD base system includes
libpcap, so no extra sysroot packages are needed.

### CI

The `.gitlab-ci.yml` includes a `check-freebsd` job in the `check` stage that runs
`cargo check --target x86_64-unknown-freebsd` on every push, ensuring FreeBSD
compatibility is not regressed. This is a type-checking gate only — full linking
and cross-compilation CI will be added in Phase 12.

## Deployment to OPNsense

1. Cross-compile or build on FreeBSD: `cargo build --release -p tuishark`
2. Copy binary to OPNsense: `scp target/release/tuishark root@opnsense:/usr/local/bin/`
3. Install tshark for deep dissection: `pkg install wireshark-nox11`
4. Run: `tuishark -i pflog0` (or `em0`, `igb0`, `enc0`, etc.)
5. Use `tuishark --list-interfaces` to discover available interfaces

## What Does NOT Work on FreeBSD

- **eBPF tracing** (`--trace`, `--trace-path`): Linux-only, requires aya + kprobes
- **Linux SLL link type**: Capture format is Linux-specific, but pcap files using it
  can still be opened and parsed on FreeBSD (etherparse handles the format)

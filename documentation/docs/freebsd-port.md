---
title: "FreeBSD Port (Phase 11)"
date: 2026-03-13
author: agent
status: active
related_issues: [32]
related_mrs: []
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
| `libc` | OK | FreeBSD types match Linux on x86_64 (`time_t`=i64, `suseconds_t`=i64) |
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

### Config directory

`dirs::config_dir()` returns `~/.config/` on FreeBSD (XDG standard), same as Linux.

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
compatibility is not regressed.

## Deployment to OPNsense

1. Cross-compile or build on FreeBSD: `cargo build --release -p tuishark`
2. Copy binary to OPNsense: `scp target/release/tuishark root@opnsense:/usr/local/bin/`
3. Install tshark for deep dissection: `pkg install tshark`
4. Run: `tuishark -i pflog0` (or `em0`, `igb0`, etc.)

## What Does NOT Work on FreeBSD

- **eBPF tracing** (`--trace`, `--trace-path`): Linux-only, requires aya + kprobes
- **Linux SLL link type**: Capture format is Linux-specific, but pcap files using it
  can still be opened and parsed on FreeBSD (etherparse handles the format)

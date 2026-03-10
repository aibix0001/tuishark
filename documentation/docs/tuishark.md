---
title: "TuiShark — Console-Based Packet Analyzer"
date: 2026-03-10
author: agent
status: active
related_issues: ["#1", "#2", "#3"]
related_mrs: ["!2"]
---

## Overview

TuiShark is a modern terminal-based packet analyzer built in Rust. It provides a Wireshark-style interface for inspecting network traffic directly in the terminal, with Catppuccin Mocha theming and vim-style keyboard navigation.

## Usage

### Opening a pcap file

```bash
cargo run -- path/to/capture.pcapng
```

### Live capture from a network interface

```bash
# Capture on a specific interface
cargo run -- -i eth0

# List available interfaces
cargo run -- --list-interfaces

# Launch without arguments to get an interactive interface picker
cargo run
```

Or with a release build:

```bash
cargo build --release
./target/release/tuishark path/to/capture.pcapng
./target/release/tuishark -i eth0
```

### Keyboard shortcuts

| Key | Action |
|-----|--------|
| `j` / `k` or Arrow keys | Navigate packets or layers |
| `g` / `G` | Jump to first / last packet |
| `PageUp` / `PageDown` | Jump 20 packets |
| `Tab` / `Shift+Tab` | Cycle panes forward / backward |
| `1` / `2` / `3` | Focus packet table / detail tree / hex view |
| `Enter` or `Space` | Expand/collapse protocol layer |
| `c` | Open interface picker (when not capturing) |
| `Esc` | Stop live capture |
| `f` | Toggle auto-scroll during live capture |
| `q` or `Ctrl+C` | Quit |

## Configuration

No configuration file yet — planned for Phase 9.

## Technical Details

### Build requirements

- Rust toolchain (1.75+)
- `libpcap-dev` system package

### Architecture

The application follows a 4-pane layout:

```
┌─────────────────────────────────────────┐
│ Header (app name, file path, theme)     │
├─────────────────────────────────────────┤
│ Packet Table (virtual scrolling)        │
├─────────────────────────────────────────┤
│ Detail Tree (collapsible protocol layers│
├───────────────────┬─────────────────────┤
│ Hex Dump          │ Kernel Trace (TBD)  │
├───────────────────┴─────────────────────┤
│ Status Bar (packet count, selection)    │
└─────────────────────────────────────────┘
```

### Two-tier packet dissection

- **Fast path** (`etherparse`): Zero-copy parsing for summary fields on every packet during capture
- **Deep path** (`rtshark`, Phase 3): Full Wireshark-grade dissection via tshark subprocess, on-demand per selected packet

### Supported protocols (Phase 1)

Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, ARP, plus port-based classification for DNS (53), HTTP (80/8080), and TLS (443).

### Live capture (Phase 2)

Live capture runs a background thread that sniffs packets via libpcap and streams them to the UI over an `mpsc` channel. The packet table auto-scrolls to follow new packets; manual navigation pauses auto-scroll, and `f` re-enables it. Capture state (Idle/Capturing/Stopped) is shown in both the header and status bar.

---
title: "Phase 1: Skeleton + File Viewer (MVP)"
date: 2026-03-10
author: agent
status: active
related_issues: ["#1"]
related_mrs: ["!2"]
---

## Overview

Phase 1 implements the foundational MVP of TuiShark: a Rust-based terminal packet analyzer that can open pcap/pcapng files and display packets in a Wireshark-style 3-pane layout with Catppuccin Mocha theming.

## Components Implemented

### Cargo Workspace

- Root workspace with `tuishark` binary crate
- Stub modules for future phases (capture, filter, session, export, trace, config)

### CLI (`clap`)

- `tuishark [file.pcap]` — opens a pcap file for viewing
- `--help` and `--version` flags via clap derive

### TUI Framework

- **ratatui + crossterm** for terminal rendering
- Event loop at ~30fps with tick-based rendering
- Terminal setup/teardown with alternate screen

### Catppuccin Mocha Theme

- Full palette mapping from `catppuccin` crate to ratatui colors
- Protocol-specific row coloring (TCP=blue, UDP=green, DNS=yellow, etc.)

### Layout (4-pane)

- Header bar with app name and file path
- Packet table with virtual scrolling (renders only visible rows)
- Detail tree with collapsible protocol layers
- Hex dump view
- Kernel trace placeholder (bottom-right)
- Status bar with packet count

### Packet Capture & Parsing

- `pcap` crate for reading pcap/pcapng files
- `etherparse` for zero-copy packet summary parsing
- Supports: Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, ARP, DNS, HTTP, TLS classification

### Keyboard Navigation

| Key | Action |
|-----|--------|
| `j`/`k` or `↑`/`↓` | Navigate packets / layers |
| `g`/`G` | First/last packet |
| `PageUp`/`PageDown` | Jump 20 packets |
| `Tab`/`Shift+Tab` | Cycle panes |
| `1`/`2`/`3` | Focus specific pane |
| `Enter`/`Space` | Expand/collapse layer (in detail view) |
| `q` or `Ctrl+C` | Quit |

## File Structure

```
tuishark/
├── Cargo.toml              # workspace root
├── tuishark/
│   ├── Cargo.toml          # binary crate
│   └── src/
│       ├── main.rs          # entry point
│       ├── app.rs           # state machine + render loop
│       ├── event.rs         # terminal event handling
│       ├── tui.rs           # terminal setup/teardown
│       ├── capture/file.rs  # pcap file reader
│       ├── dissect/fast.rs  # etherparse parsing
│       ├── dissect/model.rs # data types
│       ├── store/packet_store.rs  # in-memory storage
│       └── ui/              # theme, layout, widgets
└── tests/sample_data/       # test pcap files
```

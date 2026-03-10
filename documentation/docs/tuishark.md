---
title: "TuiShark — Console-Based Packet Analyzer"
date: 2026-03-10
author: agent
status: active
related_issues: ["#1", "#2", "#3", "#4", "#7", "#8"]
related_mrs: ["!2", "!4", "!7"]
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
| `/` | Open filter bar (type expression, Enter to apply, Esc to cancel) |
| `s` | Open save dialog |
| `w` | Quick save (reuse last path) |
| `o` | Open file / recent files dialog |
| `c` | Open interface picker (when not capturing) |
| `Esc` | Stop live capture |
| `f` | Toggle auto-scroll during live capture |
| `q` or `Ctrl+C` | Quit (prompts to save if unsaved) |

## Configuration

No configuration file yet — planned for Phase 9.

## Technical Details

### Build requirements

- Rust toolchain (1.75+)
- `libpcap-dev` system package
- `tshark` (optional, for deep dissection — install via `apt install tshark`)

### Architecture

The application follows a 4-pane layout:

```
┌─────────────────────────────────────────┐
│ Header (app name, file path, theme)     │
├─────────────────────────────────────────┤
│ Filter Bar (/ to activate)              │
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

- **Fast path** (`etherparse`): Zero-copy parsing for summary fields on every packet during capture. Provides immediate detail when selecting a packet.
- **Deep path** (`rtshark`, Phase 3): Full Wireshark-grade dissection via tshark subprocess, on-demand per selected packet. Runs in a background worker thread and replaces the fast result with richer protocol layers (HTTP headers, DNS queries, TLS handshake details, etc.) when ready.

The deep path uses a named FIFO to stream packets to a long-running tshark process, avoiding per-packet process startup overhead. If tshark is not installed, the application falls back to etherparse-only mode. Use `--no-deep` to explicitly disable deep dissection.

### Hex view byte highlighting

When selecting a protocol layer or individual field in the detail tree, the corresponding bytes are highlighted in the hex dump view. This requires deep dissection (tshark) for full byte-range coverage across all protocol layers.

### Supported protocols

**Fast path (etherparse):** Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, ARP, plus port-based classification for DNS (53), HTTP (80/8080), and TLS (443).

**Deep path (tshark):** All 3000+ Wireshark protocol dissectors, including full application-layer decoding for HTTP, DNS, TLS, DHCP, SMTP, SSH, and more.

### Live capture (Phase 2)

Live capture runs a background thread that sniffs packets via libpcap and streams them to the UI over an `mpsc` channel. The packet table auto-scrolls to follow new packets; manual navigation pauses auto-scroll, and `f` re-enables it. Capture state (Idle/Capturing/Stopped) is shown in both the header and status bar.

### Deep dissection (Phase 3)

Deep dissection runs a `DeepDissector` in a dedicated worker thread. When a packet is selected, the fast (etherparse) result is shown immediately while a deep dissection request is queued. The worker writes the raw packet to a named FIFO (with pcap headers), tshark reads and dissects it, and rtshark parses the PDML output into structured layers. The result is sent back via an `mpsc` channel and replaces the fast detail on the next UI tick. The status bar shows `DISSECTING...` while pending and `DEEP` when the deep result is displayed.

### Session management (Phase 4)

Save and open pcap files from within the TUI. Press `s` to save captured packets (with a text-input dialog for the filename), `w` to quick-save to the last used path, or `o` to open a file from the recent files list or by typing a path. When quitting with unsaved live capture data, a confirmation dialog offers to save, discard, or cancel.

Recent files (last 10) are tracked in `~/.config/tuishark/recent.json` and persist across sessions.

### Display filter engine (Phase 5)

Press `/` to activate the filter bar and type a Wireshark-style display filter expression. Press `Enter` to apply or `Esc` to cancel. The filter bar shows visual feedback: blue while editing, green when a valid filter is active, red on parse error. The status bar shows a `FILTER: matched/total` badge when filtering is active.

#### Supported filter fields

| Field | Type | Description |
|-------|------|-------------|
| `ip.src` | string | Source IP address |
| `ip.dst` | string | Destination IP address |
| `ip.addr` | string | Matches either source or destination |
| `port.src` | integer | Source port (TCP/UDP) |
| `port.dst` | integer | Destination port (TCP/UDP) |
| `port` | integer | Matches either source or destination port |
| `proto` | string | Protocol name (case-insensitive, e.g. `tcp`, `udp`, `dns`, `https`) |
| `len` | integer | Packet wire length in bytes |
| `info` | string | Info column text |

#### Operators

- **Comparison:** `==`, `!=`, `>`, `<`, `>=`, `<=`
- **String:** `contains` (case-insensitive substring match)
- **Boolean:** `and` / `&&`, `or` / `||`, `not` / `!`
- **Grouping:** parentheses `()`

#### Example expressions

```
proto == tcp
ip.src == 192.168.1.1 and port.dst == 443
proto == dns or proto == udp
not proto == arp
len > 1000 and (proto == tcp or proto == udp)
info contains "SYN"
```

The filter applies as a view layer — no packets are deleted, just hidden. During live capture, new packets are checked incrementally against the active filter. Clearing the filter (empty expression + Enter) restores the full packet list.

**Note:** `ip.addr != X` uses OR semantics (matches if *either* address differs from X), consistent with Wireshark. To exclude an address entirely, use `!(ip.addr == X)`.

## Changelog

- 2026-03-10: Phase 5 — display filter engine: expression parser, evaluator, filter bar UI
- 2026-03-10: Phase 4 — session management: save/open pcap files, recent files, quit confirmation
- 2026-03-10: Phase 3 — added deep dissection via tshark, hex byte highlighting, field-level selection

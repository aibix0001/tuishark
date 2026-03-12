---
title: "TuiShark — Console-Based Packet Analyzer"
date: 2026-03-10
author: agent
status: active
related_issues: ["#1", "#2", "#3", "#4", "#7", "#8", "#10", "#12", "#14", "#15", "#19", "#20"]
related_mrs: ["!2", "!4", "!7", "!18"]
---

## Overview

TuiShark is a modern terminal-based packet analyzer built in Rust. It provides a Wireshark-style interface for inspecting network traffic directly in the terminal, with configurable Catppuccin theming and vim-style keyboard navigation.

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
| `1` / `2` / `3` / `4` | Focus packet table / detail tree / hex view / kernel trace |
| `Enter` or `Space` | Expand/collapse protocol layer |
| `/` | Open filter bar (type expression, Enter to apply, Esc to cancel) |
| `s` | Open save dialog |
| `w` | Quick save (reuse last path) |
| `o` | Open file / recent files dialog |
| `c` | Open interface picker (when not capturing) |
| `S` (Shift+S) | Open statistics dialog |
| `e` | Open export dialog (CSV, JSON, Text) |
| `Esc` | Stop live capture |
| `f` | Toggle auto-scroll during live capture |
| `z` | Zoom / unzoom active pane (fills content area) |
| `]` / `[` | Select next / previous packet (works in any pane, including zoomed) |
| `p` | Open filter presets picker |
| `q` or `Ctrl+C` | Quit (prompts to save if unsaved) |

## Configuration (Phase 9)

TuiShark reads its configuration from `~/.config/tuishark/config.toml` at startup. The file is optional — all settings have sensible defaults matching the pre-config behavior.

### Example config

```toml
[theme]
flavor = "macchiato"    # mocha (default), macchiato, frappe, latte

[display]
timestamp_format = "absolute"  # relative (default), absolute, epoch
hex_uppercase = true           # true (default), false
auto_scroll = true             # auto-scroll during live capture

[columns]
visible = ["no", "time", "source", "destination", "protocol", "length", "info"]

[keys]
quit = "Ctrl+q"
filter = "/"
save = "s"
export = "e"
stats = "Shift+S"
filter_presets = "p"

[capture]
default_interface = ""    # empty = show picker
promiscuous = true
snap_length = 65535

[export]
default_format = "csv"    # csv, json, text
default_directory = "."

[[filter]]
name = "HTTP traffic"
expression = "proto == http or proto == https"

[[filter]]
name = "DNS only"
expression = "proto == dns"
description = "Show DNS queries and responses"

[[filter]]
name = "Large packets"
expression = "len > 1000"
```

### Key bindings

All keyboard shortcuts are configurable under the `[keys]` section. Key strings support modifiers: `Ctrl+`, `Shift+`, `Alt+`, and named keys: `Tab`, `Esc`, `Enter`, `PageDown`, `PageUp`, `Home`, `End`, `Backspace`, `Delete`, `F1`–`F12`, arrow keys (`Up`, `Down`, `Left`, `Right`).

Invalid key bindings are logged as warnings and fall back to defaults.

### Filter presets

Define named filter expressions as `[[filter]]` entries. Press `p` to open the preset picker popup, navigate with `j`/`k`, and press `Enter` to apply. Each preset has a `name`, `expression`, and optional `description`.

### Catppuccin themes

Set `[theme] flavor` to one of the four Catppuccin flavors:

| Flavor | Description |
|--------|-------------|
| `mocha` | Dark theme with warm tones (default) |
| `macchiato` | Dark theme with slightly cooler tones |
| `frappe` | Mid-tone theme |
| `latte` | Light theme |

### Timestamp formats

Set `[display] timestamp_format` to control the time column in the packet table:

| Format | Example | Description |
|--------|---------|-------------|
| `relative` | `0.000123` | Seconds since first packet (default) |
| `absolute` | `2026-03-10 14:30:05.000123` | UTC date and time (YYYY-MM-DD HH:MM:SS.us) |
| `epoch` | `1710085805.000123` | Unix epoch seconds |

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

### eBPF kernel tracing (Phase 6)

TuiShark can use eBPF to identify which process (PID, process name, UID) sent or received each packet during live capture. This is displayed in the Kernel Trace pane (bottom-right).

**Requirements:**
- Build with `cargo build --features trace`
- Run with `--trace` flag
- Requires root or `CAP_BPF` + `CAP_PERFMON` + `CAP_NET_ADMIN`
- Linux kernel 5.8+

**How it works:**
- Four kprobes attach to `tcp_sendmsg`, `tcp_recvmsg`, `udp_sendmsg`, `udp_recvmsg`
- Each kprobe maps the packet's 5-tuple (src/dst IP, src/dst port, protocol) to the calling process
- When pcap captures a packet, TuiShark looks up the 5-tuple in the eBPF map to find the process
- Only works for TCP/UDP packets during live capture; file mode shows "N/A"

**Graceful fallback:** If eBPF is unavailable (no permissions, old kernel, not compiled with the feature), the app continues to work normally — only the Kernel Trace pane shows a status message instead of process info.

### Statistics & analytics (Phase 7)

Press `Shift+S` to open the statistics dialog, a near-full-screen modal overlay with four tabs:

- **Protocol Hierarchy**: tree view of protocol distribution (packet/byte counts, percentages). Expand/collapse with Enter.
- **Conversations**: bidirectional traffic per IP:port pair. Sort columns with `s`, reverse with `r`.
- **Endpoints**: per-IP address TX/RX statistics. Sortable columns.
- **I/O Graph**: sparkline visualization of packet rate over time. Toggle packets/bytes with `b`, adjust granularity with `+`/`-`.

Switch tabs with `Tab`/`Shift+Tab`. Toggle between all packets and filtered-only with `a`. Stats update live during active capture. Close with `Esc`.

### Packet export (Phase 8)

Press `e` to open the export dialog. A two-step flow lets you:

1. **Select format**: use arrow keys to choose CSV, JSON, or Plain Text, then press Enter.
2. **Enter filename**: a suggested name is pre-filled (e.g., `capture_20260310_142018.csv`). Edit as needed, press Enter to export.

#### Supported formats

| Format | Description | Extension |
|--------|-------------|-----------|
| CSV | RFC 4180 comma-separated values with header row | `.csv` |
| JSON | Pretty-printed array of packet objects (via serde) | `.json` |
| Plain Text | Fixed-width table with capture metadata header | `.txt` |

#### Filter-aware export

When a display filter is active, only matching packets are exported by default. Press `a` in the format selection step to toggle between "filtered only" and "all packets". The plain text format includes a note in the header when a filter was applied.

## Changelog

- 2026-03-12: Global packet navigation — `[`/`]` select prev/next packet from any pane, including zoomed views (#20)
- 2026-03-12: Pane zoom toggle — press `z` to zoom active pane, `z` again to restore layout (#19)
- 2026-03-10: Phase 9 — configuration system: TOML config, themes, keybindings, filter presets, display preferences
- 2026-03-10: Phase 8 — packet export: CSV, JSON, and plain text formats with filter-aware dialog
- 2026-03-10: Phase 7 — statistics & analytics: protocol hierarchy, conversations, endpoints, I/O graph
- 2026-03-10: Phase 6 — eBPF kernel tracing: per-packet process identification
- 2026-03-10: Phase 5 — display filter engine: expression parser, evaluator, filter bar UI
- 2026-03-10: Phase 4 — session management: save/open pcap files, recent files, quit confirmation
- 2026-03-10: Phase 3 — added deep dissection via tshark, hex byte highlighting, field-level selection

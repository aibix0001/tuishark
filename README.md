# TuiShark

Modern console-based packet analyzer. A terminal alternative to Wireshark built in Rust with ratatui.

## Features

- **Packet capture** — live capture from network interfaces or open pcap/pcapng files
- **Two-tier dissection** — fast analysis via etherparse, deep dissection via tshark (optional)
- **Display filters** — expression-based filtering (`proto == tcp`, `ip.addr == 192.168.1.0`, `port == 443`)
- **Statistics** — protocol hierarchy, conversations, endpoints, I/O graphs
- **Export** — CSV, JSON, and plain text with filter-aware export
- **eBPF kernel tracing** — per-packet process identification and kernel path tracing (Linux, requires root)
- **AI packet analysis** — optional AI-assisted packet explanations via any OpenAI-compatible endpoint
- **Configurable** — TOML config for themes (Catppuccin), keybindings, columns, filter presets, capture defaults
- **Multi-platform** — Linux (amd64/arm64), FreeBSD (amd64) cross-compilation support

## Supported Protocols

TCP, UDP, ICMP, ICMPv6, ARP, DNS, HTTP, TLS, IPv4, IPv6, Ethernet, pflog, enc/IPsec

## Supported Link Types

Ethernet, Raw IP, BSD Loopback (Null), Linux SLL, pflog, enc (IPsec tunnel)

## Installation

### From source

```bash
# Dependencies
sudo apt install libpcap-dev    # Debian/Ubuntu
# Optional: install tshark for deep dissection
sudo apt install tshark

# Build
git clone https://git.lab.aibix.io/aibix0001/tuishark.git
cd tuishark
cargo build --release
```

The binary is at `target/release/tuishark`.

### Docker (multi-arch)

```bash
docker pull git.lab.aibix.io:5050/aibix0001/tuishark:latest
```

Available for amd64 and arm64.

## Usage

```bash
# Open a pcap file
tuishark capture.pcap

# Live capture (requires root or CAP_NET_RAW)
sudo tuishark -i eth0

# With eBPF tracing (requires root or CAP_BPF)
sudo tuishark -i eth0 --trace

# With kernel path tracing
sudo tuishark -i eth0 --trace-path

# CLI mode (non-interactive)
tuishark capture.pcap --cli -Y "proto == dns" -c 100

# List interfaces
tuishark --list-interfaces

# Disable deep dissection (etherparse only, no tshark needed)
tuishark --no-deep capture.pcap
```

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `1` / `2` / `3` | Focus packet table / detail tree / hex view |
| `Tab` / `Shift+Tab` | Cycle panes |
| `j` / `k` | Move down / up |
| `g` / `G` | First / last packet |
| `/` | Open display filter bar |
| `Enter` | Expand/collapse layer |
| `s` | Save capture |
| `o` | Open file |
| `e` | Export packets |
| `Shift+S` | Statistics dialog |
| `i` | IP address info |
| `c` | Container context |
| `4` | Kernel trace overlay |
| `Shift+P` | Toggle path tracing |
| `Shift+I` | AI packet analysis overlay |
| `p` | Filter presets |
| `z` | Zoom active pane |
| `?` | Help |
| `q` | Quit |

All keybindings are configurable via `~/.config/tuishark/config.toml`.

## Configuration

TuiShark reads configuration from `~/.config/tuishark/config.toml`. All sections are optional — missing values use defaults.

```toml
[theme]
flavor = "mocha"    # mocha, macchiato, frappe, latte

[display]
timestamp_format = "relative"    # relative, absolute, epoch
hex_uppercase = true
auto_scroll = true

[keys]
quit = "q"
filter = "/"
stats = "Shift+S"

[capture]
promiscuous = true
snap_length = 65535

[export]
default_format = "csv"
default_directory = "."

[[filter]]
name = "TCP only"
expression = "proto == tcp"

[[filter]]
name = "DNS"
expression = "proto == dns"
```

## AI Packet Analysis

TuiShark includes an optional AI-assisted packet learning overlay. Press `Shift+I` on any selected packet to get an educational explanation of the packet's protocol stack, fields, and significance.

### Setup

Add an `[ai]` section to your config:

```toml
[ai]
enabled = true
base_url = "http://localhost:11434/v1"    # Any OpenAI-compatible endpoint
api_key = ""                               # Empty for local models
model = "gemma3:4b"                        # Your model
timeout_ms = 60000
```

Works with any OpenAI-compatible API: Ollama, vLLM, llama.cpp, LM Studio, OpenAI, or any other provider.

### Important Notice

AI-generated explanations are produced by the language model configured by the user. TuiShark does not ship or host any AI model or inference service.

**Be aware that AI models can hallucinate.** Explanations may contain inaccuracies, fabricated protocol details, or incorrect interpretations. The quality and accuracy of explanations depend entirely on the capabilities of the model and endpoint you configure. Always verify AI-generated analysis against authoritative protocol documentation when accuracy matters.

TuiShark sends packet metadata (headers, fields, bounded raw bytes) to the configured endpoint. No packet data is sent to any third-party service unless you configure it to do so.

## Requirements

- Rust 1.94+ (build)
- `libpcap-dev` (runtime)
- `tshark` (optional, for deep dissection)
- Linux kernel 5.4+ with `CONFIG_DEBUG_INFO_BTF=y` (optional, for eBPF tracing)

## License

See repository for license details.

---
title: "CLI Mode"
date: 2026-03-12
author: agent
status: active
related_issues: []
related_mrs: []
---

## Overview

CLI mode provides a non-TUI interface for TuiShark that prints packets directly to stdout, similar to tshark. This enables scriptable packet analysis, piping output to other tools (grep, jq, awk), and automated testing of capture and filter functionality.

## Usage

Activate CLI mode with the `--cli` flag. Either a pcap file or a live interface (`-i`) is required.

### File mode

```bash
sudo tuishark --cli capture.pcap
sudo tuishark --cli capture.pcap -f "proto == tcp"
sudo tuishark --cli capture.pcap --format json
```

### Live capture

```bash
sudo tuishark --cli -i eth0
sudo tuishark --cli -i eth0 -f "port == 443" -c 100
sudo tuishark --cli -i eth0 --format csv
sudo tuishark --cli -i eth0 --trace
```

### Piping

```bash
sudo tuishark --cli -i eth0 | head -20
sudo tuishark --cli -i eth0 --format json | jq '.proto'
sudo tuishark --cli capture.pcap --format csv > export.csv
```

## Configuration

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--cli` | | Enable CLI mode (no TUI) | off |
| `--filter` | `-f` | Display filter expression | none |
| `--format` | | Output format: `text`, `csv`, `json` | `text` |
| `--count` | `-c` | Stop after N matching packets | unlimited |
| `--trace` | | Enable eBPF process tracing | off |

All existing flags (`-i`, `--no-deep`, `--list-interfaces`) remain available.

## Output Formats

### text (default)

One line per packet, tshark-style columns:

```
     1   0.000000 192.168.1.10                            10.0.0.1                                TCP         74 54321 > 443 [SYN]
```

When `--trace` is active, a process tag is appended:

```
     1   0.000000 192.168.1.10                            10.0.0.1                                TCP         74 54321 > 443 [SYN] [1234:curl]
```

### csv

Header row followed by one row per packet. The `Info` field is quoted to handle embedded commas. Includes a `Process` column (empty when tracing is off).

### json

NDJSON format (one JSON object per line). Fields: `no`, `time`, `src`, `dst`, `proto`, `len`, `info`, and optionally `process`. Streaming-friendly and pipeable to `jq`.

## Technical Details

The CLI runner (`tuishark/src/cli.rs`) is self-contained with no TUI dependencies. It reuses the existing capture, filter, and trace modules:

- `capture::live::LiveCapture` for live packet capture
- `capture::file::load_pcap()` for pcap file reading
- `filter::parser::parse()` and `filter::eval::matches()` for display filtering
- `trace::engine::TraceEngine` and `trace::lookup::flow_key_from_summary()` for eBPF process lookup

Signal handling uses a global `AtomicBool` with `libc::signal(SIGINT/SIGTERM)` for clean shutdown during live capture. Broken pipe errors (e.g., from `| head`) are caught and result in a clean exit.

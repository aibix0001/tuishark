---
title: "Phase 3: Deep Packet Dissection via tshark (rtshark)"
date: 2026-03-10
author: agent
status: active
related_issues: ["#4"]
related_mrs: []
---

## Overview

Phase 3 implements the "deep path" of TuiShark's two-tier dissection strategy. While etherparse provides fast zero-copy parsing for packet summaries and basic layer fields, deep dissection via tshark gives access to all 3000+ Wireshark protocol dissectors for full application-layer analysis.

## Architecture

### Two-Tier Dissection Flow

```
Packet selected
    │
    ├── Immediate: etherparse fast dissection (existing)
    │   └── Detail tree shows Ethernet/IP/TCP/UDP fields
    │
    └── Background: tshark deep dissection (new)
        └── Worker thread writes packet to FIFO → tshark reads → PDML → rtshark parses
            └── Result sent via mpsc channel → detail tree updated with rich layers
```

### FIFO-Based tshark Integration

```
┌──────────┐    pcap data     ┌──────────┐    PDML/XML     ┌──────────┐
│ App main │ ──────────────── │  Named   │ ──────────────── │  tshark  │
│  thread  │    (write)       │   FIFO   │    (stdout)      │ process  │
└──────────┘                  └──────────┘                  └──────────┘
      │                                                           │
      │  mpsc::channel                                            │
      │◄──────────── worker thread reads tshark output ◄──────────┘
      │              via rtshark crate
      │
      └── Updates detail tree with deep dissection result
```

### FIFO Protocol

1. **Global header** (24 bytes): written once at FIFO creation
   - Magic: `0xa1b2c3d4` (little-endian pcap)
   - Version: 2.4
   - Snaplen: 65535
   - Link type: 1 (Ethernet)

2. **Per-packet record** (16 bytes + data): written for each dissection request
   - Timestamp seconds + microseconds
   - Captured length + original length
   - Raw packet bytes

## Components

### New: `dissect/deep.rs` — DeepDissector

- Manages tshark process lifecycle via rtshark crate
- Creates/removes named FIFO in `/tmp/tuishark-<pid>.fifo`
- `dissect_packet(raw: &[u8], timestamp: f64) -> Result<PacketDetail>`
- Maps rtshark `Layer` → model `Layer`, `Metadata` → `LayerField`
- Extracts byte positions via `Metadata::position()` and `Metadata::size()`

### New: `dissect/worker.rs` — Background Dissection Worker

- Runs `DeepDissector` in a dedicated `std::thread`
- Receives dissection requests via `mpsc::Sender<DissectRequest>`
- Sends results via `mpsc::Sender<DissectResult>`
- Request contains: packet index + raw bytes + timestamp
- Result contains: packet index + `PacketDetail`

### Modified: `app.rs` — Two-Tier Integration

- `DissectState` enum: `Fast`, `DeepPending`, `Deep`
- `select_packet()`: show fast result immediately, queue deep request
- `drain_deep_results()`: called each tick, updates detail if result matches current packet
- New field: `dissect_state` for status bar indicator

### Modified: `ui/widgets/hex_view.rs` — Byte Highlighting

- New parameter: `highlight_range: Option<(usize, usize)>`
- When set, render highlighted bytes with contrasting background
- Highlight applies to both hex and ASCII columns

### Modified: `ui/widgets/detail_tree.rs` — Field Selection

- Track selected field index within expanded layers
- Report selected field's byte_range to app for hex highlighting

### Modified: `main.rs` — CLI Flag

- `--no-deep` flag to disable tshark integration
- tshark availability check at startup

## File Structure (new/modified)

```
tuishark/src/
├── dissect/
│   ├── mod.rs          # add deep + worker modules
│   ├── fast.rs         # unchanged
│   ├── model.rs        # unchanged (byte_range already prepared)
│   ├── deep.rs         # NEW: tshark/rtshark integration
│   └── worker.rs       # NEW: background dissection thread
├── main.rs             # add --no-deep flag
├── app.rs              # two-tier dissection, DissectState
└── ui/widgets/
    ├── hex_view.rs     # byte range highlighting
    └── detail_tree.rs  # field-level selection for highlighting
```

## Dependencies

```toml
rtshark = "4"     # tshark PDML wrapper
```

System requirement: `tshark` binary (part of `wireshark` / `tshark` package).

## Key Decisions

- **FIFO over temp files**: avoids disk I/O, tshark reads in streaming mode
- **One tshark process per session**: avoids ~100-500ms startup cost per packet
- **std::thread over tokio**: consistent with Phase 2 pattern, no async runtime needed
- **Replace, don't merge**: deep result fully replaces fast result (tshark covers all layers etherparse does, plus more)
- **Graceful fallback**: if tshark unavailable, etherparse-only mode works fine

## Keyboard Shortcuts (unchanged)

No new keybindings. Hex highlighting activates automatically when selecting layers/fields in the detail tree.

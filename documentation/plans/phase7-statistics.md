---
title: "Phase 7: Statistics & Analytics"
date: 2026-03-10
author: agent
status: active
related_issues: ["#12"]
related_mrs: []
---

## Overview

Add a statistics dialog providing four analytical views over captured packets. Accessed via `Shift+S` as a modal overlay with tabbed navigation. Works in both file mode and live capture.

## Features

### Protocol Hierarchy

Tree view showing protocol distribution across all packets:
- Columns: Protocol, Packets, Bytes, % Packets, % Bytes
- Layer hierarchy: Ethernet -> IPv4/IPv6/ARP -> TCP/UDP/ICMP -> DNS/HTTP/TLS
- Expandable/collapsible nodes (Enter/Space)
- Built from PacketSummary.protocol + original_length

### Conversations

Bidirectional traffic table per IP:port pair:
- Canonical address ordering (lower address = A) for deduplication
- Columns: Address A, Port A, Address B, Port B, Proto, Pkts A->B, Pkts B->A, Total Pkts, Duration
- Sortable columns (cycle with `s`, reverse with `r`)

### Endpoints

Per-IP address statistics:
- TX/RX packet and byte counts
- First/last seen timestamps
- Sortable columns

### I/O Graph

Packet rate visualization over time:
- Uses ratatui's built-in Sparkline widget (no new dependencies)
- Toggle between packets/sec and bytes/sec with `b`
- Adjustable bucket granularity with `+`/`-` (5-500 buckets)
- Time axis labels

## Technical Approach

### New module: `stats/`

| File | Purpose |
|------|---------|
| `mod.rs` | Re-exports |
| `model.rs` | `StatsTab` enum |
| `protocol.rs` | Protocol hierarchy computation + tree flattening |
| `conversations.rs` | Conversation aggregation + sorting |
| `endpoints.rs` | Endpoint aggregation + sorting |
| `io_graph.rs` | Time-bucketed packet/byte counts |

### New widget: `ui/dialogs/stats_dialog.rs`

Renders a near-full-screen modal (90% width, 80% height) with:
- Tab bar at top
- Tab-specific content area
- Help line at bottom

### Integration

- `app.rs`: 18 new fields for dialog state, cached stats, sort/scroll state
- Dialog priority: `quit_confirm > stats_dialog > save_dialog > open_dialog > picker`
- Live capture: stats recomputed in `drain_capture_packets()` when dialog is open
- Filter-aware: toggle with `a` to show stats for filtered packets only
- Cached stats freed when dialog closes

### Performance

Stats computation is O(n) over PacketStore — simple HashMap aggregation. Full recompute on each update rather than incremental counters, trading slight overhead for simplicity and correctness. For 100K packets this takes ~1ms.

## Keyboard Shortcuts

| Key | Context | Action |
|-----|---------|--------|
| `Shift+S` | Main view | Open statistics dialog |
| `Esc` | Stats dialog | Close dialog |
| `Tab` / `Shift+Tab` | Stats dialog | Next/previous tab |
| `j`/`k` / Arrows | Table tabs | Navigate rows |
| `Enter`/`Space` | Protocol tab | Expand/collapse node |
| `s` | Conv/Endpoint tabs | Cycle sort column |
| `r` | Conv/Endpoint tabs | Reverse sort |
| `g`/`G` | Table tabs | Jump to top/bottom |
| `a` | Stats dialog | Toggle all/filtered |
| `b` | I/O Graph tab | Toggle packets/bytes |
| `+`/`-` | I/O Graph tab | Adjust granularity |

## Acceptance Criteria

- [x] `Shift+S` opens statistics dialog as modal overlay
- [x] Four tabs navigable with Tab/Shift+Tab
- [x] Protocol Hierarchy shows correct counts/percentages with expandable tree
- [x] Conversations shows bidirectional packet/byte counts per IP:port pair
- [x] Endpoints shows per-address TX/RX statistics
- [x] I/O Graph renders sparkline of packet rate over time
- [x] Stats respect active display filter when filter-aware mode enabled
- [x] Stats update live during active capture with dialog open
- [x] Esc closes dialog and frees cached data
- [x] No new dependencies
- [x] Catppuccin Mocha theme consistent
- [x] j/k/arrow navigation, sorting in table views
- [x] Unit tests for each computation function (22 tests)
- [x] Works with empty packet store
- [x] All 98 existing tests pass

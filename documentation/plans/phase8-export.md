---
title: "Phase 8: Packet Export"
date: 2026-03-10
author: agent
status: active
related_issues: ["#14"]
related_mrs: []
---

## Goal

Add packet export functionality to TuiShark, allowing users to save captured packets in CSV, JSON, or plain text formats via a modal dialog.

## Scope

### Export formats

- **CSV**: RFC 4180 compliant with header row (`No,Time,Source,Destination,Protocol,Length,Info`). Fields with commas or quotes are properly escaped.
- **JSON**: Pretty-printed array of packet objects using `serde_json`. Includes index, timestamp, source, destination, protocol, length, info, and optional port fields.
- **Plain text**: Human-readable fixed-width table with capture metadata header (source file, packet count, duration).

### Export dialog

Two-step modal triggered by `e` key:
1. Format selection with arrow key navigation
2. Filename input with auto-suggested timestamped name

### Filter awareness

- Default: export only filtered packets when a display filter is active
- Toggle `a` to switch between filtered-only and all packets
- Plain text header indicates when filter was applied

## File structure

```
tuishark/src/export/
├── mod.rs    — ExportFormat enum, ExportStep enum
├── csv.rs    — CSV exporter with RFC 4180 escaping
├── json.rs   — JSON exporter via serde
└── text.rs   — Plain text table exporter

tuishark/src/ui/dialogs/
└── export_dialog.rs — Two-step modal widget
```

## Integration points

- `app.rs`: 6 new fields (show_export_dialog, export_step, export_format_selected, export_filename, export_cursor_pos, export_all_packets)
- Dialog priority: after stats_dialog, before save_dialog
- Key routing: `e` opens dialog, Esc cancels/goes back, Enter confirms

## Tasks

- [x] Export module with CSV, JSON, text formatters
- [x] Export dialog widget (format select + filename input)
- [x] App integration (fields, key routing, rendering)
- [x] Filter-aware export (toggle all vs filtered)
- [x] Unit tests for all three formats (12 tests)

## Dependencies

- `serde` + `serde_json` (already in Cargo.toml)
- `PacketStore::iter_packets()` for unified iteration (existing API)

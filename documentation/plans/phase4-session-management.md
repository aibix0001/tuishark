---
title: "Phase 4: Session Management"
date: 2026-03-10
author: agent
status: active
related_issues: ["#7"]
related_mrs: []
---

## Overview

Phase 4 adds session management to TuiShark: saving captured packets to pcap files, opening files from within the TUI, tracking recent files, and prompting to save unsaved captures on quit.

## Components Implemented

### Pcap Save Engine (`capture/save.rs`)

- `save_pcap(path, store) -> Result<usize>` writes all packets to a standard pcap file
- Uses `pcap::Capture::dead(Linktype::ETHERNET)` + `Savefile` for writing
- Reconstructs absolute timestamps: `base_ts + relative_ts` split into `tv_sec` / `tv_usec`
- Works during active live capture (saves current snapshot without stopping)

### PacketStore Enhancements (`store/packet_store.rs`)

- `first_absolute_ts: Option<f64>` — stores the absolute Unix timestamp of the first packet
- `modified_since_save: bool` — tracks whether packets have been added since last save
- `clear()` method — resets store for new file/session
- `mark_saved()` / `is_modified()` — save-state tracking for quit confirmation

### Absolute Timestamp Propagation

- `load_pcap()` now returns `(Vec<(PacketSummary, Vec<u8>)>, Option<f64>)` with the absolute first timestamp
- `LiveCapture` exposes `first_absolute_ts()` via `Arc<Mutex<Option<f64>>>` set by the capture thread
- `drain_capture_packets()` propagates the timestamp to the store on each tick

### Save Dialog (`ui/dialogs/save_dialog.rs`)

- Centered modal dialog with text input field
- Full cursor navigation: Left/Right/Home/End/Backspace/Delete
- Scrolling text input for long paths
- Default filename: `capture_YYYYMMDD_HHMMSS.pcap`
- Enter to confirm, Esc to cancel

### Open File Dialog (`ui/dialogs/open_dialog.rs`)

- Two-mode dialog: text input for manual path entry, or recent files list
- Tab key switches between modes
- Recent files list with j/k navigation and selection highlighting
- Long paths are truncated with `...` prefix
- Border color changes to indicate active mode (blue=text, mauve=list)

### Quit Confirmation Dialog (`ui/dialogs/quit_confirm.rs`)

- Shown when quitting with unsaved modified packets
- Three options: [S]ave, [D]iscard, [C]ancel
- Color-coded action keys (green/red/blue)

### Recent Files Tracking (`session/recent.rs`)

- Stores last 10 opened/saved files in `~/.config/tuishark/recent.json`
- Uses `serde_json` for serialization, `dirs` crate for XDG config path
- `add()` deduplicates by canonical path and moves to front
- Gracefully handles missing/corrupt config (returns empty list)
- Persisted on every save and file open

### App Integration (`app.rs`)

- Dialog priority: quit_confirm > save_dialog > open_dialog > interface_picker
- Text input handling pattern shared between save and open dialogs
- `do_open_file()` resets entire session state (stops capture, clears store, restarts deep worker)
- `try_quit()` checks `store.is_modified()` before allowing quit
- `quick_save()` reuses last save path or falls back to save dialog

## Keyboard Shortcuts (new)

| Key | Context | Action |
|-----|---------|--------|
| `s` | Not in dialog | Open save dialog |
| `w` | Not in dialog | Quick save (reuse last path, or open save dialog) |
| `o` | Not in dialog | Open file / recent files dialog |

## Dependencies (new)

```toml
serde = { version = "1", features = ["derive"] }
serde_json = "1"
dirs = "6"
```

## File Structure (new/modified)

```
tuishark/src/
├── capture/
│   ├── mod.rs          # added save module
│   ├── file.rs         # returns absolute first timestamp
│   ├── live.rs         # exposes first_absolute_ts
│   └── save.rs         # NEW: pcap save engine
├── session/
│   ├── mod.rs          # replaced stub with recent module
│   └── recent.rs       # NEW: recent files config
├── store/
│   └── packet_store.rs # absolute ts, modified tracking, clear
├── app.rs              # session dialogs, save/open/quit logic
└── ui/dialogs/
    ├── mod.rs           # registered new dialog modules
    ├── save_dialog.rs   # NEW: save file dialog
    ├── open_dialog.rs   # NEW: open file / recent files dialog
    └── quit_confirm.rs  # NEW: unsaved changes confirmation
```

## Key Decisions

- **No chrono dependency**: Date formatting uses a civil-days algorithm for filename generation
- **Timestamp reconstruction**: Store absolute base timestamp + relative offsets rather than absolute timestamps per packet (avoids changing PacketSummary)
- **Save during capture**: Allowed — saves a snapshot of current packets without stopping
- **Dialog stacking**: Only one dialog at a time, priority-based routing in key handler
- **Recent files location**: XDG config dir (`~/.config/tuishark/`) following Linux conventions

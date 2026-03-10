---
title: "Phase 2: Live Packet Capture"
date: 2026-03-10
author: agent
status: active
related_issues: ["#3"]
related_mrs: []
---

## Overview

Phase 2 adds real-time packet capture from network interfaces using libpcap, complementing the file-based pcap viewer from Phase 1.

## Components Implemented

### CLI Extensions

- `-i <interface>` flag to specify capture interface directly
- `--list-interfaces` flag to enumerate available interfaces and exit
- When launched without file or interface, an interactive TUI picker is shown

### Capture Engine (`capture/live.rs`)

- Background capture thread using `std::thread` + `std::sync::mpsc` channel
- `list_interfaces()` enumerates available network interfaces via libpcap
- `LiveCapture` struct spawns a capture thread, sends `(PacketSummary, Vec<u8>)` tuples
- Graceful stop via `Arc<AtomicBool>` flag
- Promiscuous mode enabled by default
- 100ms poll timeout for responsive stop handling
- Drains up to 1000 packets per tick to keep the UI responsive

### App Integration

- `CaptureState` enum: `Idle`, `Capturing`, `Stopped`
- On each tick: drain channel, add packets to store
- Auto-scroll follows tail of capture; manual navigation disables auto-scroll
- `f` key toggles auto-scroll back on during live capture

### Interface Picker Dialog (`ui/dialogs/interface_picker.rs`)

- Modal overlay centered on screen
- Lists all available interfaces with descriptions
- `j`/`k` to navigate, `Enter` to select, `Esc` to cancel/quit
- Shown automatically when app starts without `-i` or file argument

### Keyboard Shortcuts (new)

| Key | Context | Action |
|-----|---------|--------|
| `c` | Not capturing | Open interface picker to start capture |
| `Esc` | Capturing | Stop capture |
| `f` | Capturing | Toggle auto-scroll |

### Status Bar Updates

- Shows `LIVE` indicator (green) during active capture
- Shows `STOPPED` indicator (red) after capture ends
- Header shows interface name and capture state

## Technical Decisions

- **No async/tokio**: `std::thread` + `mpsc::channel` is sufficient for the capture thread pattern
- **PacketStore stays single-threaded**: main thread drains channel on each tick, no locking needed
- **Reuses `parse_packet()`**: same etherparse fast-path dissection as file mode
- **First packet becomes t=0**: same relative timestamp logic as file mode

## File Structure (new/modified)

```
tuishark/src/
├── capture/
│   ├── mod.rs          # added live module
│   ├── file.rs         # unchanged
│   └── live.rs         # NEW: live capture engine
├── main.rs             # added -i and --list-interfaces CLI flags
├── app.rs              # capture state, channel drain, picker integration
└── ui/
    ├── dialogs/
    │   ├── mod.rs              # added interface_picker module
    │   └── interface_picker.rs # NEW: modal interface selector
    └── widgets/
        └── status_bar.rs       # capture state indicator
```

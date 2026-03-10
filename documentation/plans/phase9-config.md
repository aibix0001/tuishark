---
title: "Phase 9: Configuration System"
date: 2026-03-10
author: agent
status: active
related_issues: ["#15"]
related_mrs: []
---

## Goal

Add a persistent, user-editable configuration system so TuiShark users can customize appearance, keyboard shortcuts, display preferences, and filter presets without modifying source code.

## Design decisions

- **TOML format** — human-readable, widely used in the Rust ecosystem, has mature serde support
- **Zero-config compatible** — missing file uses all current defaults; no setup required for new users
- **Partial config** — users only need to specify the settings they want to change; `#[serde(default)]` fills the rest
- **No runtime reload** — restart to apply changes; keeps implementation simple for v1
- **Config path** — `~/.config/tuishark/config.toml` via `dirs::config_dir()` (already used for recent files)

## Implementation

### New files

| File | Purpose |
|------|---------|
| `config/mod.rs` | Top-level `Config` struct, loader, `DisplayConfig`, `CaptureConfig`, `ExportConfig` |
| `config/theme.rs` | `ThemeConfig`, `CatppuccinFlavor` enum |
| `config/keys.rs` | `KeyConfig`, `KeyBindings`, `Action` enum, key string parser |
| `config/columns.rs` | `ColumnConfig`, `Column` enum with headers and default widths |
| `config/filters.rs` | `FilterPreset` struct |
| `ui/dialogs/preset_picker.rs` | Modal popup for selecting filter presets |

### Modified files

| File | Changes |
|------|---------|
| `Cargo.toml` | Added `toml = "0.8"` dependency |
| `main.rs` | Load config at startup, pass to `App::new()` |
| `app.rs` | Config/KeyBindings fields, action-based key dispatch, preset picker state, config-aware widget calls |
| `ui/theme.rs` | `from_flavor()`, `flavor_name()`, all 4 Catppuccin palettes |
| `ui/widgets/packet_table.rs` | Configurable columns and timestamp formats |
| `ui/widgets/hex_view.rs` | Configurable hex case (upper/lower) |
| `ui/dialogs/mod.rs` | Register `preset_picker` module |

## Features

### Theme selection
- All 4 Catppuccin flavors: Mocha, Macchiato, Frappé, Latte
- `Theme::from_flavor()` constructs the palette from `catppuccin::PALETTE`
- Header shows current flavor name

### Keyboard rebinding
- `KeyConfig` maps action names to key strings
- `KeyBindings` compiles config into a `HashMap<(KeyModifiers, KeyCode), Action>` at startup
- `parse_key_string()` handles modifiers (`Ctrl+`, `Shift+`, `Alt+`) and named keys
- Arrow keys always mapped as navigation aliases (non-overridable)
- Invalid bindings fall back to defaults with a stderr warning

### Column customization
- `Column` enum with `ALL` constant, headers, and default widths
- `ColumnConfig.visible` controls which columns appear and in what order
- `ColumnConfig.widths` provides per-column width overrides

### Filter presets
- `[[filter]]` TOML array with `name`, `expression`, optional `description`
- `p` key opens a modal picker; Enter applies the selected preset's expression
- Preset picker integrates into the dialog priority chain

### Display preferences
- Timestamp format: relative (default), absolute (HH:MM:SS.us), epoch
- Hex case: uppercase (default) or lowercase
- Auto-scroll: on/off default for live capture

### Export and capture defaults
- Export: default format and directory used in export dialog
- Capture: default interface (skip picker), promiscuous mode, snap length

## Tests

30 new unit tests covering:
- Config serialization/deserialization roundtrips
- Partial config fills defaults
- Key string parsing (chars, modifiers, named keys, F-keys)
- KeyBindings construction and custom overrides
- Column config visibility and width overrides
- Filter preset parsing
- Theme flavor serde
- Timestamp format serde

## Dependencies

- `toml = "0.8"` (new) — TOML parser with serde support
- `serde` (existing) — serialization framework
- `dirs` (existing) — XDG config directory resolution

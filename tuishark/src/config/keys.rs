use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde::{Deserialize, Serialize};

/// All rebindable actions in TuiShark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    Quit,
    ForceQuit,
    NextPane,
    PrevPane,
    FocusPacketTable,
    FocusDetailTree,
    FocusHexView,
    FocusKernelTrace,
    Save,
    QuickSave,
    Open,
    Filter,
    Export,
    Stats,
    InterfacePicker,
    StopCapture,
    ToggleAutoScroll,
    FilterPresets,
    // Navigation
    MoveDown,
    MoveUp,
    MoveFirst,
    MoveLast,
    PageDown,
    PageUp,
    ToggleExpand,
    NextPacket,
    PrevPacket,
    TogglePathTrace,
    Help,
    ZoomPane,
}

/// Keyboard configuration section.
///
/// Maps action names to key strings. Missing entries use defaults.
/// Example TOML:
/// ```toml
/// [keys]
/// quit = "Ctrl+q"
/// filter = "f"
/// save = "Ctrl+s"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct KeyConfig {
    pub quit: String,
    pub force_quit: String,
    pub next_pane: String,
    pub prev_pane: String,
    pub focus_packet_table: String,
    pub focus_detail_tree: String,
    pub focus_hex_view: String,
    pub focus_kernel_trace: String,
    pub save: String,
    pub quick_save: String,
    pub open: String,
    pub filter: String,
    pub export: String,
    pub stats: String,
    pub interface_picker: String,
    pub stop_capture: String,
    pub toggle_auto_scroll: String,
    pub filter_presets: String,
    pub move_down: String,
    pub move_up: String,
    pub move_first: String,
    pub move_last: String,
    pub page_down: String,
    pub page_up: String,
    pub toggle_expand: String,
    pub toggle_path_trace: String,
    pub help: String,
    pub zoom_pane: String,
    pub next_packet: String,
    pub prev_packet: String,
}

impl Default for KeyConfig {
    fn default() -> Self {
        Self {
            quit: "q".into(),
            force_quit: "Ctrl+c".into(),
            next_pane: "Tab".into(),
            prev_pane: "Shift+BackTab".into(),
            focus_packet_table: "1".into(),
            focus_detail_tree: "2".into(),
            focus_hex_view: "3".into(),
            focus_kernel_trace: "4".into(),
            save: "s".into(),
            quick_save: "w".into(),
            open: "o".into(),
            filter: "/".into(),
            export: "e".into(),
            stats: "Shift+S".into(),
            interface_picker: "c".into(),
            stop_capture: "Esc".into(),
            toggle_auto_scroll: "f".into(),
            filter_presets: "p".into(),
            move_down: "j".into(),
            move_up: "k".into(),
            move_first: "g".into(),
            move_last: "G".into(),
            page_down: "PageDown".into(),
            page_up: "PageUp".into(),
            toggle_expand: "Enter".into(),
            toggle_path_trace: "Shift+P".into(),
            help: "?".into(),
            zoom_pane: "z".into(),
            next_packet: "Ctrl+Down".into(),
            prev_packet: "Ctrl+Up".into(),
        }
    }
}

/// Compiled key bindings for fast runtime lookup.
pub struct KeyBindings {
    map: HashMap<(KeyModifiers, KeyCode), Action>,
}

impl KeyBindings {
    /// Build bindings from a KeyConfig, falling back to defaults for unparseable entries.
    pub fn from_config(config: &KeyConfig) -> Self {
        let defaults = KeyConfig::default();
        let mut map = HashMap::new();

        let entries: &[(Action, &str, &str)] = &[
            (Action::Quit, &config.quit, &defaults.quit),
            (Action::ForceQuit, &config.force_quit, &defaults.force_quit),
            (Action::NextPane, &config.next_pane, &defaults.next_pane),
            (Action::PrevPane, &config.prev_pane, &defaults.prev_pane),
            (Action::FocusPacketTable, &config.focus_packet_table, &defaults.focus_packet_table),
            (Action::FocusDetailTree, &config.focus_detail_tree, &defaults.focus_detail_tree),
            (Action::FocusHexView, &config.focus_hex_view, &defaults.focus_hex_view),
            (Action::FocusKernelTrace, &config.focus_kernel_trace, &defaults.focus_kernel_trace),
            (Action::Save, &config.save, &defaults.save),
            (Action::QuickSave, &config.quick_save, &defaults.quick_save),
            (Action::Open, &config.open, &defaults.open),
            (Action::Filter, &config.filter, &defaults.filter),
            (Action::Export, &config.export, &defaults.export),
            (Action::Stats, &config.stats, &defaults.stats),
            (Action::InterfacePicker, &config.interface_picker, &defaults.interface_picker),
            (Action::StopCapture, &config.stop_capture, &defaults.stop_capture),
            (Action::ToggleAutoScroll, &config.toggle_auto_scroll, &defaults.toggle_auto_scroll),
            (Action::FilterPresets, &config.filter_presets, &defaults.filter_presets),
            (Action::MoveDown, &config.move_down, &defaults.move_down),
            (Action::MoveUp, &config.move_up, &defaults.move_up),
            (Action::MoveFirst, &config.move_first, &defaults.move_first),
            (Action::MoveLast, &config.move_last, &defaults.move_last),
            (Action::PageDown, &config.page_down, &defaults.page_down),
            (Action::PageUp, &config.page_up, &defaults.page_up),
            (Action::ToggleExpand, &config.toggle_expand, &defaults.toggle_expand),
            (Action::TogglePathTrace, &config.toggle_path_trace, &defaults.toggle_path_trace),
            (Action::Help, &config.help, &defaults.help),
            (Action::ZoomPane, &config.zoom_pane, &defaults.zoom_pane),
            (Action::NextPacket, &config.next_packet, &defaults.next_packet),
            (Action::PrevPacket, &config.prev_packet, &defaults.prev_packet),
        ];

        for &(action, user_str, default_str) in entries {
            let key_str = if user_str.is_empty() { default_str } else { user_str };
            if let Some((mods, code)) = parse_key_string(key_str) {
                map.insert((mods, code), action);
            } else if let Some((mods, code)) = parse_key_string(default_str) {
                eprintln!("Warning: invalid key binding '{key_str}' for {action:?}, using default '{default_str}'");
                map.insert((mods, code), action);
            }
        }

        // Always add arrow key aliases for move_down/move_up (non-overridable convenience)
        map.entry((KeyModifiers::NONE, KeyCode::Down)).or_insert(Action::MoveDown);
        map.entry((KeyModifiers::NONE, KeyCode::Up)).or_insert(Action::MoveUp);
        map.entry((KeyModifiers::NONE, KeyCode::Home)).or_insert(Action::MoveFirst);
        map.entry((KeyModifiers::NONE, KeyCode::End)).or_insert(Action::MoveLast);

        Self { map }
    }

    /// Look up which action a key event maps to.
    pub fn action_for(&self, key: &KeyEvent) -> Option<Action> {
        self.map.get(&(key.modifiers, key.code)).copied()
    }
}

/// Parse a key string like "Ctrl+s", "Shift+S", "Tab", "Esc", "PageDown", "1", "/".
pub fn parse_key_string(s: &str) -> Option<(KeyModifiers, KeyCode)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let parts: Vec<&str> = s.split('+').collect();
    let mut modifiers = KeyModifiers::NONE;
    let key_part;

    if parts.len() == 1 {
        key_part = parts[0];
    } else {
        for &modifier in &parts[..parts.len() - 1] {
            match modifier.to_lowercase().as_str() {
                "ctrl" | "control" => modifiers |= KeyModifiers::CONTROL,
                "shift" => modifiers |= KeyModifiers::SHIFT,
                "alt" => modifiers |= KeyModifiers::ALT,
                _ => return None,
            }
        }
        key_part = parts[parts.len() - 1];
    }

    let code = match key_part.to_lowercase().as_str() {
        "tab" => KeyCode::Tab,
        "backtab" => KeyCode::BackTab,
        "esc" | "escape" => KeyCode::Esc,
        "enter" | "return" => KeyCode::Enter,
        "space" => KeyCode::Char(' '),
        "backspace" => KeyCode::Backspace,
        "delete" | "del" => KeyCode::Delete,
        "home" => KeyCode::Home,
        "end" => KeyCode::End,
        "pageup" | "pgup" => KeyCode::PageUp,
        "pagedown" | "pgdn" => KeyCode::PageDown,
        "up" => KeyCode::Up,
        "down" => KeyCode::Down,
        "left" => KeyCode::Left,
        "right" => KeyCode::Right,
        "f1" => KeyCode::F(1),
        "f2" => KeyCode::F(2),
        "f3" => KeyCode::F(3),
        "f4" => KeyCode::F(4),
        "f5" => KeyCode::F(5),
        "f6" => KeyCode::F(6),
        "f7" => KeyCode::F(7),
        "f8" => KeyCode::F(8),
        "f9" => KeyCode::F(9),
        "f10" => KeyCode::F(10),
        "f11" => KeyCode::F(11),
        "f12" => KeyCode::F(12),
        _ => {
            // Single character
            let mut chars = key_part.chars();
            let ch = chars.next()?;
            if chars.next().is_some() {
                return None; // More than one char and not a named key
            }
            // If Shift is set and it's a letter, use the uppercase char directly
            if modifiers.contains(KeyModifiers::SHIFT) && ch.is_ascii_alphabetic() {
                return Some((modifiers, KeyCode::Char(ch.to_ascii_uppercase())));
            }
            KeyCode::Char(ch)
        }
    };

    Some((modifiers, code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_char() {
        let (mods, code) = parse_key_string("q").unwrap();
        assert_eq!(mods, KeyModifiers::NONE);
        assert_eq!(code, KeyCode::Char('q'));
    }

    #[test]
    fn parse_ctrl_combo() {
        let (mods, code) = parse_key_string("Ctrl+c").unwrap();
        assert_eq!(mods, KeyModifiers::CONTROL);
        assert_eq!(code, KeyCode::Char('c'));
    }

    #[test]
    fn parse_shift_char() {
        let (mods, code) = parse_key_string("Shift+S").unwrap();
        assert!(mods.contains(KeyModifiers::SHIFT));
        assert_eq!(code, KeyCode::Char('S'));
    }

    #[test]
    fn parse_named_keys() {
        assert_eq!(parse_key_string("Tab").unwrap().1, KeyCode::Tab);
        assert_eq!(parse_key_string("Esc").unwrap().1, KeyCode::Esc);
        assert_eq!(parse_key_string("Enter").unwrap().1, KeyCode::Enter);
        assert_eq!(parse_key_string("PageDown").unwrap().1, KeyCode::PageDown);
        assert_eq!(parse_key_string("Backspace").unwrap().1, KeyCode::Backspace);
    }

    #[test]
    fn parse_shift_backtab() {
        let (mods, code) = parse_key_string("Shift+BackTab").unwrap();
        assert!(mods.contains(KeyModifiers::SHIFT));
        assert_eq!(code, KeyCode::BackTab);
    }

    #[test]
    fn parse_f_keys() {
        assert_eq!(parse_key_string("F1").unwrap().1, KeyCode::F(1));
        assert_eq!(parse_key_string("F12").unwrap().1, KeyCode::F(12));
    }

    #[test]
    fn parse_invalid_returns_none() {
        assert!(parse_key_string("").is_none());
        assert!(parse_key_string("Invalid+Key+Too+Many").is_none());
    }

    #[test]
    fn parse_slash() {
        let (mods, code) = parse_key_string("/").unwrap();
        assert_eq!(mods, KeyModifiers::NONE);
        assert_eq!(code, KeyCode::Char('/'));
    }

    #[test]
    fn keybindings_from_defaults() {
        let config = KeyConfig::default();
        let bindings = KeyBindings::from_config(&config);
        let quit_key = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        assert_eq!(bindings.action_for(&quit_key), Some(Action::Quit));
    }

    #[test]
    fn keybindings_custom_override() {
        let mut config = KeyConfig::default();
        config.quit = "Ctrl+q".into();
        let bindings = KeyBindings::from_config(&config);

        // Old key should not map to quit (unless something else maps there)
        let old = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        assert_ne!(bindings.action_for(&old), Some(Action::Quit));

        // New key should map to quit
        let new = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL);
        assert_eq!(bindings.action_for(&new), Some(Action::Quit));
    }

    #[test]
    fn arrow_keys_always_mapped() {
        let config = KeyConfig::default();
        let bindings = KeyBindings::from_config(&config);
        let down = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
        assert_eq!(bindings.action_for(&down), Some(Action::MoveDown));
    }

    #[test]
    fn ctrl_arrow_maps_to_packet_nav() {
        let config = KeyConfig::default();
        let bindings = KeyBindings::from_config(&config);
        let ctrl_down = KeyEvent::new(KeyCode::Down, KeyModifiers::CONTROL);
        let ctrl_up = KeyEvent::new(KeyCode::Up, KeyModifiers::CONTROL);
        assert_eq!(bindings.action_for(&ctrl_down), Some(Action::NextPacket));
        assert_eq!(bindings.action_for(&ctrl_up), Some(Action::PrevPacket));
    }
}

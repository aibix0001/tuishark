use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::PathBuf;

use crate::capture::file::load_pcap;
use crate::capture::live::{list_interfaces, InterfaceInfo, LiveCapture};
use crate::dissect::fast::dissect_detail;
use crate::dissect::model::PacketDetail;
use crate::event::{Event, EventHandler};
use crate::store::packet_store::PacketStore;
use crate::tui::Tui;
use crate::ui::dialogs::interface_picker::InterfacePicker;
use crate::ui::layout::AppLayout;
use crate::ui::theme::Theme;
use crate::ui::widgets::detail_tree::DetailTree;
use crate::ui::widgets::hex_view::HexView;
use crate::ui::widgets::packet_table::PacketTable;
use crate::ui::widgets::status_bar::StatusBar;

use ratatui::{
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    PacketTable,
    DetailTree,
    HexView,
}

impl Pane {
    fn next(self) -> Self {
        match self {
            Pane::PacketTable => Pane::DetailTree,
            Pane::DetailTree => Pane::HexView,
            Pane::HexView => Pane::PacketTable,
        }
    }

    fn prev(self) -> Self {
        match self {
            Pane::PacketTable => Pane::HexView,
            Pane::DetailTree => Pane::PacketTable,
            Pane::HexView => Pane::DetailTree,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureState {
    Idle,
    Capturing,
    Stopped,
}

pub struct App {
    running: bool,
    store: PacketStore,
    selected_packet: Option<usize>,
    scroll_offset: usize,
    visible_rows: usize,
    active_pane: Pane,
    theme: Theme,
    detail: Option<PacketDetail>,
    expanded_layers: Vec<bool>,
    selected_layer: Option<usize>,
    file_path: Option<PathBuf>,
    // Live capture state
    interface_name: Option<String>,
    capture_state: CaptureState,
    live_capture: Option<LiveCapture>,
    auto_scroll: bool,
    // Interface picker dialog
    show_interface_picker: bool,
    available_interfaces: Vec<InterfaceInfo>,
    picker_selected: usize,
    picker_scroll_offset: usize,
    // Status/error message
    status_message: Option<String>,
}

impl App {
    pub fn new(file: Option<PathBuf>, interface: Option<String>) -> Self {
        Self {
            running: true,
            store: PacketStore::default(),
            selected_packet: None,
            scroll_offset: 0,
            visible_rows: 20,
            active_pane: Pane::PacketTable,
            theme: Theme::mocha(),
            detail: None,
            expanded_layers: Vec::new(),
            selected_layer: None,
            file_path: file,
            interface_name: interface,
            capture_state: CaptureState::Idle,
            live_capture: None,
            auto_scroll: true,
            show_interface_picker: false,
            available_interfaces: Vec::new(),
            picker_selected: 0,
            picker_scroll_offset: 0,
            status_message: None,
        }
    }

    pub fn run(&mut self, terminal: &mut Tui) -> Result<()> {
        // Load file if provided
        if let Some(path) = &self.file_path {
            let packets = load_pcap(path)?;
            for (pkt, raw) in packets {
                self.store.add(pkt, raw);
            }
            if !self.store.is_empty() {
                self.select_packet(0);
            }
        } else if let Some(iface) = &self.interface_name {
            // Start live capture on specified interface
            let iface = iface.clone();
            self.start_capture(&iface)?;
        } else {
            // No file or interface — show interface picker
            self.open_interface_picker();
        }

        let events = EventHandler::new(33); // ~30fps

        while self.running {
            // Drain incoming packets from live capture
            self.drain_capture_packets();

            terminal.draw(|frame| self.render(frame))?;

            match events.next()? {
                Event::Key(key) => self.handle_key(key),
                Event::Tick => {}
                Event::Mouse(_) | Event::Resize(_, _) => {}
            }
        }

        // Drain remaining packets before dropping capture
        self.drain_capture_packets();

        Ok(())
    }

    fn start_capture(&mut self, interface: &str) -> Result<()> {
        let offset = self.store.len();
        let capture = LiveCapture::start(interface, offset)?;
        self.live_capture = Some(capture);
        self.capture_state = CaptureState::Capturing;
        self.interface_name = Some(interface.to_string());
        self.auto_scroll = true;
        self.status_message = None;
        Ok(())
    }

    fn stop_capture(&mut self) {
        if let Some(ref mut cap) = self.live_capture {
            cap.stop();
        }
        // Drain remaining packets from channel before dropping
        self.drain_capture_packets();
        self.live_capture = None;
        self.capture_state = CaptureState::Stopped;
    }

    fn drain_capture_packets(&mut self) {
        let Some(ref capture) = self.live_capture else {
            return;
        };

        let mut new_packets = false;
        // Drain up to 1000 packets per tick to avoid blocking the UI
        for _ in 0..1000 {
            match capture.try_recv() {
                Some((summary, raw)) => {
                    self.store.add(summary, raw);
                    new_packets = true;
                }
                None => break,
            }
        }

        // Auto-scroll: select the last packet if following tail
        if new_packets && self.auto_scroll {
            let last = self.store.len().saturating_sub(1);
            self.selected_packet = Some(last);
            // Adjust scroll to keep last packet visible
            if self.visible_rows > 0 && last >= self.scroll_offset + self.visible_rows {
                self.scroll_offset = last.saturating_sub(self.visible_rows - 1);
            }
        }

        // Check if capture thread died
        if let Some(ref cap) = self.live_capture {
            if !cap.is_running() && self.capture_state == CaptureState::Capturing {
                self.capture_state = CaptureState::Stopped;
                if let Some(err) = cap.error() {
                    self.status_message = Some(err);
                }
            }
        }
    }

    fn open_interface_picker(&mut self) {
        match list_interfaces() {
            Ok(interfaces) => {
                self.available_interfaces = interfaces;
                self.picker_selected = 0;
                self.picker_scroll_offset = 0;
                self.show_interface_picker = true;
            }
            Err(e) => {
                self.status_message = Some(format!("{e:#}"));
                self.show_interface_picker = false;
            }
        }
    }

    fn render(&mut self, frame: &mut ratatui::Frame) {
        let layout = AppLayout::new(frame.area());

        // Update visible rows from actual terminal height
        self.visible_rows = layout.packet_table.height.saturating_sub(3) as usize;

        // Header
        let source_info = if let Some(ref path) = self.file_path {
            format!(" -- {} ", path.display())
        } else if let Some(ref iface) = self.interface_name {
            format!(" -- {} ", iface)
        } else {
            " -- No source ".into()
        };

        let capture_indicator = match self.capture_state {
            CaptureState::Idle => Span::styled(
                " IDLE ",
                Style::default().fg(self.theme.subtext0),
            ),
            CaptureState::Capturing => Span::styled(
                " CAPTURING ",
                Style::default()
                    .fg(self.theme.base)
                    .bg(self.theme.green)
                    .add_modifier(Modifier::BOLD),
            ),
            CaptureState::Stopped => Span::styled(
                " STOPPED ",
                Style::default()
                    .fg(self.theme.base)
                    .bg(self.theme.red)
                    .add_modifier(Modifier::BOLD),
            ),
        };

        let header = Line::from(vec![
            Span::styled(
                format!(" TuiShark v{VERSION} "),
                Style::default()
                    .fg(self.theme.blue)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(source_info, Style::default().fg(self.theme.subtext0)),
            capture_indicator,
            Span::styled(
                " Catppuccin Mocha ",
                Style::default().fg(self.theme.mauve),
            ),
        ]);
        let header_widget = Paragraph::new(header)
            .style(Style::default().bg(self.theme.mantle));
        frame.render_widget(header_widget, layout.header);

        // Packet table -- virtual scroll: only render visible rows
        let visible = self.store.get_range(self.scroll_offset, self.visible_rows);
        let table = PacketTable::new(
            visible,
            self.selected_packet,
            &self.theme,
            self.active_pane == Pane::PacketTable,
        );
        frame.render_widget(table, layout.packet_table);

        // Detail tree
        let detail_tree = DetailTree::new(
            self.detail.as_ref(),
            &self.expanded_layers,
            self.selected_layer,
            &self.theme,
            self.active_pane == Pane::DetailTree,
        );
        frame.render_widget(detail_tree, layout.detail_tree);

        // Hex view
        let hex_data = self
            .selected_packet
            .and_then(|idx| self.store.get_raw(idx));
        let hex_view = HexView::new(hex_data, &self.theme, self.active_pane == Pane::HexView);
        frame.render_widget(hex_view, layout.bottom_left);

        // Kernel trace placeholder (Phase 6)
        let trace_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.surface2))
            .title(" Kernel Trace ")
            .title_style(Style::default().fg(self.theme.text))
            .style(Style::default().bg(self.theme.base));
        let trace_placeholder = Paragraph::new("Kernel tracing not yet available")
            .style(Style::default().fg(self.theme.subtext0))
            .block(trace_block);
        frame.render_widget(trace_placeholder, layout.bottom_right);

        // Status bar
        let status = StatusBar::new(
            self.store.len(),
            self.selected_packet,
            self.capture_state,
            self.status_message.as_deref(),
            &self.theme,
        );
        frame.render_widget(status, layout.status_bar);

        // Interface picker overlay
        if self.show_interface_picker {
            let picker = InterfacePicker::new(
                &self.available_interfaces,
                self.picker_selected,
                self.picker_scroll_offset,
                &self.theme,
            );
            frame.render_widget(picker, frame.area());
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        // Clear status message on any key press
        self.status_message = None;

        // Interface picker mode
        if self.show_interface_picker {
            self.handle_picker_key(key);
            return;
        }

        // Global shortcuts
        match (key.modifiers, key.code) {
            (KeyModifiers::CONTROL, KeyCode::Char('c')) | (_, KeyCode::Char('q')) => {
                self.running = false;
                return;
            }
            (_, KeyCode::Tab) => {
                self.active_pane = self.active_pane.next();
                return;
            }
            (KeyModifiers::SHIFT, KeyCode::BackTab) => {
                self.active_pane = self.active_pane.prev();
                return;
            }
            (_, KeyCode::Char('1')) => {
                self.active_pane = Pane::PacketTable;
                return;
            }
            (_, KeyCode::Char('2')) => {
                self.active_pane = Pane::DetailTree;
                return;
            }
            (_, KeyCode::Char('3')) => {
                self.active_pane = Pane::HexView;
                return;
            }
            // Live capture controls
            (_, KeyCode::Char('c')) if self.capture_state != CaptureState::Capturing => {
                if self.file_path.is_none() {
                    self.open_interface_picker();
                }
                return;
            }
            (_, KeyCode::Esc) if self.capture_state == CaptureState::Capturing => {
                self.stop_capture();
                return;
            }
            (_, KeyCode::Char('f')) if self.capture_state == CaptureState::Capturing => {
                self.auto_scroll = !self.auto_scroll;
                return;
            }
            _ => {}
        }

        // Pane-specific handling
        match self.active_pane {
            Pane::PacketTable => self.handle_packet_table_key(key),
            Pane::DetailTree => self.handle_detail_tree_key(key),
            Pane::HexView => {}
        }
    }

    fn handle_picker_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                if !self.available_interfaces.is_empty() {
                    self.picker_selected =
                        (self.picker_selected + 1).min(self.available_interfaces.len() - 1);
                    self.adjust_picker_scroll();
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.picker_selected = self.picker_selected.saturating_sub(1);
                self.adjust_picker_scroll();
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.picker_selected = 0;
                self.picker_scroll_offset = 0;
            }
            KeyCode::End | KeyCode::Char('G') => {
                if !self.available_interfaces.is_empty() {
                    self.picker_selected = self.available_interfaces.len() - 1;
                    self.adjust_picker_scroll();
                }
            }
            KeyCode::Enter => {
                if let Some(iface) = self.available_interfaces.get(self.picker_selected) {
                    let name = iface.name.clone();
                    self.show_interface_picker = false;
                    if let Err(e) = self.start_capture(&name) {
                        self.status_message = Some(format!("{e:#}"));
                    }
                }
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                self.show_interface_picker = false;
                if self.capture_state == CaptureState::Idle
                    && self.file_path.is_none()
                    && self.store.is_empty()
                {
                    self.running = false;
                }
            }
            _ => {}
        }
    }

    fn adjust_picker_scroll(&mut self) {
        // Approximate visible height for picker (will match render calculation)
        let picker_visible = 20usize; // conservative default
        if self.picker_selected < self.picker_scroll_offset {
            self.picker_scroll_offset = self.picker_selected;
        } else if self.picker_selected >= self.picker_scroll_offset + picker_visible {
            self.picker_scroll_offset = self.picker_selected.saturating_sub(picker_visible - 1);
        }
    }

    fn handle_packet_table_key(&mut self, key: KeyEvent) {
        if self.store.is_empty() {
            return;
        }

        // Manual navigation disables auto-scroll during live capture
        let navigating = matches!(
            key.code,
            KeyCode::Char('j')
                | KeyCode::Char('k')
                | KeyCode::Up
                | KeyCode::Down
                | KeyCode::Char('g')
                | KeyCode::Char('G')
                | KeyCode::Home
                | KeyCode::End
                | KeyCode::PageUp
                | KeyCode::PageDown
        );
        if navigating && self.capture_state == CaptureState::Capturing {
            self.auto_scroll = false;
        }

        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                let next = self
                    .selected_packet
                    .map(|i| (i + 1).min(self.store.len() - 1))
                    .unwrap_or(0);
                self.select_packet(next);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                let prev = self
                    .selected_packet
                    .map(|i| i.saturating_sub(1))
                    .unwrap_or(0);
                self.select_packet(prev);
            }
            KeyCode::Char('g') | KeyCode::Home => {
                self.select_packet(0);
            }
            KeyCode::Char('G') | KeyCode::End => {
                self.select_packet(self.store.len() - 1);
            }
            KeyCode::PageDown => {
                let next = self
                    .selected_packet
                    .map(|i| (i + 20).min(self.store.len() - 1))
                    .unwrap_or(0);
                self.select_packet(next);
            }
            KeyCode::PageUp => {
                let prev = self
                    .selected_packet
                    .map(|i| i.saturating_sub(20))
                    .unwrap_or(0);
                self.select_packet(prev);
            }
            _ => {}
        }
    }

    fn handle_detail_tree_key(&mut self, key: KeyEvent) {
        let Some(detail) = &self.detail else {
            return;
        };
        let layer_count = detail.layers.len();
        if layer_count == 0 {
            return;
        }

        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.selected_layer = Some(
                    self.selected_layer
                        .map(|i| (i + 1).min(layer_count - 1))
                        .unwrap_or(0),
                );
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.selected_layer = Some(
                    self.selected_layer
                        .map(|i| i.saturating_sub(1))
                        .unwrap_or(0),
                );
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                if let Some(idx) = self.selected_layer {
                    if idx < self.expanded_layers.len() {
                        self.expanded_layers[idx] = !self.expanded_layers[idx];
                    }
                }
            }
            _ => {}
        }
    }

    fn select_packet(&mut self, index: usize) {
        self.selected_packet = Some(index);

        // Dissect packet detail
        if let Some(raw) = self.store.get_raw(index) {
            let detail = dissect_detail(raw);
            let layer_count = detail.layers.len();
            self.detail = Some(detail);
            self.expanded_layers = vec![true; layer_count];
            self.selected_layer = if layer_count > 0 { Some(0) } else { None };
        }

        // Adjust scroll offset to keep selected packet visible
        if index < self.scroll_offset {
            self.scroll_offset = index;
        } else if self.visible_rows > 0 && index >= self.scroll_offset + self.visible_rows {
            self.scroll_offset = index - self.visible_rows + 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pane_next_cycles() {
        assert_eq!(Pane::PacketTable.next(), Pane::DetailTree);
        assert_eq!(Pane::DetailTree.next(), Pane::HexView);
        assert_eq!(Pane::HexView.next(), Pane::PacketTable);
    }

    #[test]
    fn pane_prev_cycles() {
        assert_eq!(Pane::PacketTable.prev(), Pane::HexView);
        assert_eq!(Pane::DetailTree.prev(), Pane::PacketTable);
        assert_eq!(Pane::HexView.prev(), Pane::DetailTree);
    }

    #[test]
    fn capture_state_default() {
        let app = App::new(None, None);
        assert_eq!(app.capture_state, CaptureState::Idle);
        assert!(app.auto_scroll);
    }

    #[test]
    fn picker_scroll_adjusts() {
        let mut app = App::new(None, None);
        app.picker_selected = 25;
        app.adjust_picker_scroll();
        assert!(app.picker_scroll_offset > 0);
        assert!(app.picker_selected >= app.picker_scroll_offset);
    }
}

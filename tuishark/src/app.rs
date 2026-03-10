use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::PathBuf;

use crate::capture::file::load_pcap;
use crate::capture::live::{list_interfaces, InterfaceInfo, LiveCapture};
use crate::capture::save::save_pcap;
use crate::dissect::deep::next_request_seq;
use crate::dissect::fast::dissect_detail;
use crate::dissect::model::{PacketDetail, PacketSummary};
use crate::dissect::worker::{DissectRequest, DissectWorker};
use crate::event::{Event, EventHandler};
use crate::session::recent::RecentFiles;
use crate::store::packet_store::PacketStore;
use crate::tui::Tui;
use crate::ui::dialogs::interface_picker::InterfacePicker;
use crate::ui::dialogs::open_dialog::{OpenDialog, OpenDialogMode};
use crate::ui::dialogs::quit_confirm::QuitConfirm;
use crate::ui::dialogs::save_dialog::SaveDialog;
use crate::ui::layout::AppLayout;
use crate::ui::theme::Theme;
use crate::ui::widgets::detail_tree::DetailTree;
use crate::ui::widgets::hex_view::HexView;
use crate::ui::widgets::packet_table::PacketTable;
use crate::ui::widgets::filter_bar::FilterBar;
use crate::ui::widgets::status_bar::StatusBar;
use crate::ui::widgets::trace_view::TraceView;
use crate::filter::ast::Expr;
use crate::filter::eval;
use crate::filter::parser;
use crate::trace::engine::TraceEngine;
use crate::trace::lookup::flow_key_from_summary;
use crate::trace::model::TraceState;
use crate::trace::store::TraceStore;

use ratatui::{
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    PacketTable,
    DetailTree,
    HexView,
    KernelTrace,
}

impl Pane {
    fn next(self) -> Self {
        match self {
            Pane::PacketTable => Pane::DetailTree,
            Pane::DetailTree => Pane::HexView,
            Pane::HexView => Pane::KernelTrace,
            Pane::KernelTrace => Pane::PacketTable,
        }
    }

    fn prev(self) -> Self {
        match self {
            Pane::PacketTable => Pane::KernelTrace,
            Pane::DetailTree => Pane::PacketTable,
            Pane::HexView => Pane::DetailTree,
            Pane::KernelTrace => Pane::HexView,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureState {
    Idle,
    Capturing,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DissectState {
    /// Only fast (etherparse) dissection available.
    Fast,
    /// Deep dissection requested, waiting for tshark result.
    DeepPending,
    /// Deep dissection result received and displayed.
    Deep,
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
    selected_field: Option<usize>,
    highlight_range: Option<(usize, usize)>,
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
    // Deep dissection
    dissect_worker: Option<DissectWorker>,
    dissect_state: DissectState,
    dissect_seq: usize,
    // Session management (Phase 4)
    show_save_dialog: bool,
    save_filename: String,
    save_cursor_pos: usize,
    show_open_dialog: bool,
    open_input: String,
    open_cursor_pos: usize,
    open_mode: OpenDialogMode,
    open_selected_recent: usize,
    open_scroll_offset: usize,
    recent_files: RecentFiles,
    show_quit_confirm: bool,
    quit_after_save: bool,
    last_save_path: Option<PathBuf>,
    enable_deep: bool,
    // Filter engine (Phase 5)
    filter_editing: bool,
    filter_input: String,
    filter_cursor_pos: usize,
    active_filter: Option<Expr>,
    active_filter_text: String,
    filter_error: bool,
    filtered_indices: Option<Vec<usize>>,
    // eBPF kernel tracing (Phase 6)
    trace_engine: Option<TraceEngine>,
    trace_store: TraceStore,
    trace_state: TraceState,
}

impl App {
    pub fn new(
        file: Option<PathBuf>,
        interface: Option<String>,
        enable_deep: bool,
        enable_trace: bool,
    ) -> Self {
        let dissect_worker = if enable_deep {
            match DissectWorker::try_spawn() {
                Ok(w) => Some(w),
                Err(e) => {
                    eprintln!("Warning: deep dissection unavailable: {e}");
                    None
                }
            }
        } else {
            None
        };

        // Determine trace state and try to load eBPF engine
        let is_file_mode = file.is_some();
        let (trace_engine, trace_state, trace_msg) = if is_file_mode {
            (None, TraceState::FileMode, None)
        } else if !enable_trace {
            (None, TraceState::Disabled, None)
        } else {
            match TraceEngine::new() {
                Ok(engine) => (Some(engine), TraceState::Active, None),
                Err(e) => {
                    (None, TraceState::Unavailable, Some(format!("eBPF tracing unavailable: {e}")))
                }
            }
        };

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
            selected_field: None,
            highlight_range: None,
            file_path: file,
            interface_name: interface,
            capture_state: CaptureState::Idle,
            live_capture: None,
            auto_scroll: true,
            show_interface_picker: false,
            available_interfaces: Vec::new(),
            picker_selected: 0,
            picker_scroll_offset: 0,
            status_message: trace_msg,
            dissect_worker,
            dissect_state: DissectState::Fast,
            dissect_seq: 0,
            // Session management
            show_save_dialog: false,
            save_filename: String::new(),
            save_cursor_pos: 0,
            show_open_dialog: false,
            open_input: String::new(),
            open_cursor_pos: 0,
            open_mode: OpenDialogMode::RecentList,
            open_selected_recent: 0,
            open_scroll_offset: 0,
            recent_files: RecentFiles::load(),
            show_quit_confirm: false,
            quit_after_save: false,
            last_save_path: None,
            enable_deep,
            // Filter engine
            filter_editing: false,
            filter_input: String::new(),
            filter_cursor_pos: 0,
            active_filter: None,
            active_filter_text: String::new(),
            filter_error: false,
            filtered_indices: None,
            // eBPF kernel tracing
            trace_engine,
            trace_store: TraceStore::default(),
            trace_state,
        }
    }

    pub fn run(&mut self, terminal: &mut Tui) -> Result<()> {
        // Load file if provided
        if let Some(path) = &self.file_path {
            let path = path.clone();
            self.do_open_file(&path)?;
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

            // Check for deep dissection results
            self.drain_deep_results();

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
        // Restore trace state for live capture
        if self.trace_engine.is_some() {
            self.trace_state = TraceState::Active;
        } else if self.trace_state == TraceState::FileMode {
            // Was in file mode — restore to Disabled or Unavailable
            self.trace_state = TraceState::Disabled;
        }
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

        // Propagate first absolute timestamp from capture thread
        if let Some(ts) = capture.first_absolute_ts() {
            self.store.set_first_absolute_ts(ts);
        }

        let mut new_packets = false;
        // Drain up to 1000 packets per tick to avoid blocking the UI
        for _ in 0..1000 {
            match capture.try_recv() {
                Some((summary, raw)) => {
                    let pkt_index = summary.index;
                    // Incrementally update filtered indices for new packet
                    if let Some(ref filter) = self.active_filter {
                        if eval::matches(filter, &summary) {
                            if let Some(ref mut indices) = self.filtered_indices {
                                indices.push(pkt_index);
                            }
                        }
                    }
                    // eBPF trace lookup for this packet
                    if let Some(ref mut engine) = self.trace_engine {
                        if let Some(flow_key) = flow_key_from_summary(&summary) {
                            if let Some(info) = engine.lookup(&flow_key) {
                                self.trace_store.insert(pkt_index, info);
                            }
                        }
                    }
                    self.store.add(summary, raw);
                    new_packets = true;
                }
                None => break,
            }
        }

        // Auto-scroll: select the last packet if following tail
        if new_packets && self.auto_scroll {
            let last_idx = if let Some(ref indices) = self.filtered_indices {
                indices.last().copied()
            } else {
                Some(self.store.len().saturating_sub(1))
            };
            if let Some(last) = last_idx {
                self.select_packet(last);
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

    fn drain_deep_results(&mut self) {
        // Collect results first to avoid borrow conflict
        let (results, worker_alive) = match self.dissect_worker.as_ref() {
            Some(w) => {
                let mut v = Vec::new();
                while let Some(r) = w.try_recv() {
                    v.push(r);
                }
                (v, w.is_alive())
            }
            None => return,
        };

        // Detect dead worker
        if !worker_alive && self.dissect_state == DissectState::DeepPending {
            self.dissect_state = DissectState::Fast;
            self.status_message = Some("Deep dissection worker died".into());
        }

        for result in results {
            // Only apply if this result matches our current request
            if result.seq != self.dissect_seq {
                continue;
            }
            if self.selected_packet != Some(result.index) {
                continue;
            }

            if let Some(detail) = result.detail {
                let layer_count = detail.layers.len();
                self.detail = Some(detail);
                self.expanded_layers = vec![true; layer_count];
                self.selected_layer = if layer_count > 0 { Some(0) } else { None };
                self.selected_field = None;
                self.dissect_state = DissectState::Deep;
                self.update_highlight();
            } else if let Some(err) = result.error {
                self.dissect_state = DissectState::Fast;
                self.status_message = Some(format!("Deep dissection failed: {err}"));
            }
        }
    }

    fn update_highlight(&mut self) {
        self.highlight_range = None;
        let Some(ref detail) = self.detail else {
            return;
        };
        let Some(layer_idx) = self.selected_layer else {
            return;
        };
        let Some(layer) = detail.layers.get(layer_idx) else {
            return;
        };

        if let Some(field_idx) = self.selected_field {
            // Specific field selected — highlight that field's bytes
            if let Some(field) = layer.fields.get(field_idx) {
                self.highlight_range = field.byte_range;
            }
        } else {
            // Layer selected — highlight the union of all field byte ranges
            let mut start = usize::MAX;
            let mut end = 0usize;
            for field in &layer.fields {
                if let Some((s, e)) = field.byte_range {
                    start = start.min(s);
                    end = end.max(e);
                }
            }
            if start < end {
                self.highlight_range = Some((start, end));
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

        // Filter bar
        let filter_match = self.filtered_indices.as_ref().map(|fi| (fi.len(), self.store.len()));
        let active_display = if self.active_filter.is_some() {
            Some(self.active_filter_text.as_str())
        } else {
            None
        };
        let filter_bar = FilterBar::new(
            &self.filter_input,
            self.filter_cursor_pos,
            self.filter_editing,
            active_display,
            filter_match,
            self.filter_error,
            &self.theme,
        );
        frame.render_widget(filter_bar, layout.filter_bar);

        // Packet table -- virtual scroll: only render visible rows
        let visible_packets = self.get_visible_packets();
        let table = PacketTable::new(
            &visible_packets,
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
            self.selected_field,
            &self.theme,
            self.active_pane == Pane::DetailTree,
        );
        frame.render_widget(detail_tree, layout.detail_tree);

        // Hex view
        let hex_data = self
            .selected_packet
            .and_then(|idx| self.store.get_raw(idx));
        let hex_view = HexView::new(
            hex_data,
            self.highlight_range,
            &self.theme,
            self.active_pane == Pane::HexView,
        );
        frame.render_widget(hex_view, layout.bottom_left);

        // Kernel trace (Phase 6)
        let trace_info = self
            .selected_packet
            .and_then(|idx| self.trace_store.get(idx));
        let trace_view = TraceView::new(
            trace_info,
            self.trace_state,
            &self.theme,
            self.active_pane == Pane::KernelTrace,
        );
        frame.render_widget(trace_view, layout.bottom_right);

        // Status bar
        let filter_match = self.filtered_indices.as_ref().map(|fi| (fi.len(), self.store.len()));
        let status = StatusBar::new(
            self.store.len(),
            self.selected_packet,
            self.capture_state,
            self.dissect_state,
            self.status_message.as_deref(),
            filter_match,
            &self.theme,
        );
        frame.render_widget(status, layout.status_bar);

        // Dialog overlays (priority order: quit > save > open > picker)
        if self.show_quit_confirm {
            let dialog = QuitConfirm::new(&self.theme);
            frame.render_widget(dialog, frame.area());
        } else if self.show_save_dialog {
            let dialog = SaveDialog::new(
                &self.save_filename,
                self.save_cursor_pos,
                &self.theme,
            );
            frame.render_widget(dialog, frame.area());
        } else if self.show_open_dialog {
            let dialog = OpenDialog::new(
                &self.open_input,
                self.open_cursor_pos,
                &self.recent_files.files,
                self.open_selected_recent,
                self.open_scroll_offset,
                self.open_mode,
                &self.theme,
            );
            frame.render_widget(dialog, frame.area());
        } else if self.show_interface_picker {
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

        // Dialog mode routing (highest priority first)
        if self.show_quit_confirm {
            self.handle_quit_confirm_key(key);
            return;
        }
        if self.show_save_dialog {
            self.handle_save_dialog_key(key);
            return;
        }
        if self.show_open_dialog {
            self.handle_open_dialog_key(key);
            return;
        }
        if self.show_interface_picker {
            self.handle_picker_key(key);
            return;
        }
        if self.filter_editing {
            self.handle_filter_key(key);
            return;
        }

        // Global shortcuts
        match (key.modifiers, key.code) {
            (KeyModifiers::CONTROL, KeyCode::Char('c')) => {
                // Ctrl+C always force-quits immediately
                self.running = false;
                return;
            }
            (_, KeyCode::Char('q')) => {
                self.try_quit();
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
            (_, KeyCode::Char('4')) => {
                self.active_pane = Pane::KernelTrace;
                return;
            }
            // Session management shortcuts
            (_, KeyCode::Char('s')) => {
                self.open_save_dialog();
                return;
            }
            (_, KeyCode::Char('w')) => {
                self.quick_save();
                return;
            }
            (_, KeyCode::Char('o')) => {
                self.open_open_dialog();
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
            (_, KeyCode::Char('/')) => {
                self.start_filter_edit();
                return;
            }
            _ => {}
        }

        // Pane-specific handling
        match self.active_pane {
            Pane::PacketTable => self.handle_packet_table_key(key),
            Pane::DetailTree => self.handle_detail_tree_key(key),
            Pane::HexView => {}
            Pane::KernelTrace => {}
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
        let display_len = self.filtered_len();
        if display_len == 0 {
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

        // Find current display position
        let current_display_pos = self.selected_display_pos();

        let new_display_pos = match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                current_display_pos.map(|p| (p + 1).min(display_len - 1)).unwrap_or(0)
            }
            KeyCode::Char('k') | KeyCode::Up => {
                current_display_pos.map(|p| p.saturating_sub(1)).unwrap_or(0)
            }
            KeyCode::Char('g') | KeyCode::Home => 0,
            KeyCode::Char('G') | KeyCode::End => display_len - 1,
            KeyCode::PageDown => {
                current_display_pos.map(|p| (p + 20).min(display_len - 1)).unwrap_or(0)
            }
            KeyCode::PageUp => {
                current_display_pos.map(|p| p.saturating_sub(20)).unwrap_or(0)
            }
            _ => return,
        };

        let store_index = self.display_to_store_index(new_display_pos);
        self.select_packet(store_index);
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
                if let Some(field_idx) = self.selected_field {
                    // Navigate within expanded layer fields
                    let layer_idx = self.selected_layer.unwrap_or(0);
                    let field_count = detail.layers.get(layer_idx).map(|l| l.fields.len()).unwrap_or(0);
                    if field_idx + 1 < field_count {
                        self.selected_field = Some(field_idx + 1);
                    } else {
                        // Move to next layer
                        self.selected_field = None;
                        self.selected_layer = Some(
                            self.selected_layer
                                .map(|i| (i + 1).min(layer_count - 1))
                                .unwrap_or(0),
                        );
                    }
                } else {
                    // At layer level — if expanded, enter fields; else next layer
                    let layer_idx = self.selected_layer.unwrap_or(0);
                    let is_expanded = self.expanded_layers.get(layer_idx).copied().unwrap_or(false);
                    let has_fields = detail.layers.get(layer_idx).map(|l| !l.fields.is_empty()).unwrap_or(false);
                    if is_expanded && has_fields {
                        self.selected_field = Some(0);
                    } else {
                        self.selected_layer = Some(
                            self.selected_layer
                                .map(|i| (i + 1).min(layer_count - 1))
                                .unwrap_or(0),
                        );
                    }
                }
                self.update_highlight();
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if let Some(field_idx) = self.selected_field {
                    if field_idx > 0 {
                        self.selected_field = Some(field_idx - 1);
                    } else {
                        // Back to layer header
                        self.selected_field = None;
                    }
                } else {
                    // At layer level — go to previous layer's last field if expanded
                    let prev_layer = self.selected_layer.map(|i| i.saturating_sub(1)).unwrap_or(0);
                    if prev_layer != self.selected_layer.unwrap_or(0) {
                        let is_expanded = self.expanded_layers.get(prev_layer).copied().unwrap_or(false);
                        let field_count = detail.layers.get(prev_layer).map(|l| l.fields.len()).unwrap_or(0);
                        if is_expanded && field_count > 0 {
                            self.selected_layer = Some(prev_layer);
                            self.selected_field = Some(field_count - 1);
                        } else {
                            self.selected_layer = Some(prev_layer);
                            self.selected_field = None;
                        }
                    }
                }
                self.update_highlight();
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                if self.selected_field.is_none() {
                    if let Some(idx) = self.selected_layer {
                        if idx < self.expanded_layers.len() {
                            self.expanded_layers[idx] = !self.expanded_layers[idx];
                            // Clear field selection when collapsing
                            if !self.expanded_layers[idx] {
                                self.selected_field = None;
                            }
                        }
                    }
                }
                self.update_highlight();
            }
            _ => {}
        }
    }

    fn select_packet(&mut self, index: usize) {
        self.selected_packet = Some(index);

        // Clone raw data upfront to avoid borrow conflict with &mut self
        let raw_owned = self.store.get_raw(index).map(|r| r.to_vec());
        let timestamp = self.store.get(index).map(|s| s.timestamp).unwrap_or(0.0);

        if let Some(raw) = raw_owned {
            // Fast dissection (immediate)
            let detail = dissect_detail(&raw);
            let layer_count = detail.layers.len();
            self.detail = Some(detail);
            self.expanded_layers = vec![true; layer_count];
            self.selected_layer = if layer_count > 0 { Some(0) } else { None };
            self.selected_field = None;
            self.dissect_state = DissectState::Fast;
            self.update_highlight();

            // Queue deep dissection if worker is available and alive
            if let Some(ref worker) = self.dissect_worker {
                if worker.is_alive() {
                    let seq = next_request_seq();
                    self.dissect_seq = seq;
                    worker.request(DissectRequest {
                        index,
                        seq,
                        raw, // move owned vec, no extra clone
                        timestamp,
                    });
                    self.dissect_state = DissectState::DeepPending;
                }
            }
        }

        // Adjust scroll offset to keep selected packet visible (using display position)
        if let Some(display_pos) = self.selected_display_pos() {
            if display_pos < self.scroll_offset {
                self.scroll_offset = display_pos;
            } else if self.visible_rows > 0 && display_pos >= self.scroll_offset + self.visible_rows {
                self.scroll_offset = display_pos - self.visible_rows + 1;
            }
        }
    }

    // --- Session management methods ---

    fn try_quit(&mut self) {
        if self.store.is_modified() {
            self.show_quit_confirm = true;
        } else {
            self.running = false;
        }
    }

    fn default_save_filename() -> String {
        let now = std::time::SystemTime::now();
        let secs = now
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Simple timestamp-based filename (avoid chrono dependency)
        // Format: capture_EPOCH.pcap
        let hours = (secs % 86400) / 3600;
        let minutes = (secs % 3600) / 60;
        let seconds = secs % 60;
        // Days since epoch for a rough date
        let days = secs / 86400;
        // Approximate date calculation (good enough for filenames)
        let (year, month, day) = epoch_days_to_date(days);
        format!(
            "capture_{year:04}{month:02}{day:02}_{hours:02}{minutes:02}{seconds:02}.pcap"
        )
    }

    fn open_save_dialog(&mut self) {
        if self.store.is_empty() {
            self.status_message = Some("No packets to save".into());
            return;
        }
        self.save_filename = if let Some(ref path) = self.last_save_path {
            path.display().to_string()
        } else {
            Self::default_save_filename()
        };
        self.save_cursor_pos = self.save_filename.chars().count();
        self.show_save_dialog = true;
    }

    fn quick_save(&mut self) {
        if self.store.is_empty() {
            self.status_message = Some("No packets to save".into());
            return;
        }
        if let Some(path) = self.last_save_path.clone() {
            self.do_save(&path);
        } else {
            self.open_save_dialog();
        }
    }

    fn do_save(&mut self, path: &std::path::Path) {
        match save_pcap(path, &self.store) {
            Ok(count) => {
                self.store.mark_saved();
                self.last_save_path = Some(path.to_path_buf());
                self.recent_files.add(path);
                self.recent_files.save();
                self.status_message = Some(format!("Saved {count} packets to {}", path.display()));
            }
            Err(e) => {
                self.status_message = Some(format!("Save failed: {e:#}"));
            }
        }
    }

    fn open_open_dialog(&mut self) {
        self.recent_files = RecentFiles::load(); // refresh
        self.open_input.clear();
        self.open_cursor_pos = 0;
        self.open_selected_recent = 0;
        self.open_scroll_offset = 0;
        self.open_mode = if self.recent_files.files.is_empty() {
            OpenDialogMode::TextInput
        } else {
            OpenDialogMode::RecentList
        };
        self.show_open_dialog = true;
    }

    fn do_open_file(&mut self, path: &std::path::Path) -> Result<()> {
        // Stop any active capture
        if self.capture_state == CaptureState::Capturing {
            self.stop_capture();
        }

        let (packets, first_ts) = load_pcap(path)?;

        // Reset state
        self.store.clear();
        self.selected_packet = None;
        self.scroll_offset = 0;
        self.detail = None;
        self.expanded_layers.clear();
        self.selected_layer = None;
        self.selected_field = None;
        self.highlight_range = None;
        self.dissect_state = DissectState::Fast;
        self.capture_state = CaptureState::Idle;
        self.interface_name = None;
        self.live_capture = None;
        self.clear_filter();
        self.trace_store.clear();
        self.trace_state = TraceState::FileMode;
        // Note: trace_engine stays as-is — it will be reused if the user starts live capture later

        // Restart deep dissection worker if needed
        if self.enable_deep && self.dissect_worker.is_none() {
            if let Ok(w) = DissectWorker::try_spawn() {
                self.dissect_worker = Some(w);
            }
        }

        if let Some(ts) = first_ts {
            self.store.set_first_absolute_ts(ts);
        }

        for (pkt, raw) in packets {
            self.store.add(pkt, raw);
        }

        // Mark as not modified (just loaded from file)
        self.store.mark_saved();

        self.file_path = Some(path.to_path_buf());

        // Update recent files
        self.recent_files.add(path);
        self.recent_files.save();

        if !self.store.is_empty() {
            self.select_packet(0);
        }

        Ok(())
    }

    fn handle_save_dialog_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c) if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT => {
                let byte_idx = char_to_byte_index(&self.save_filename, self.save_cursor_pos);
                self.save_filename.insert(byte_idx, c);
                self.save_cursor_pos += 1;
            }
            KeyCode::Backspace => {
                if self.save_cursor_pos > 0 {
                    let byte_idx = char_to_byte_index(&self.save_filename, self.save_cursor_pos - 1);
                    self.save_filename.remove(byte_idx);
                    self.save_cursor_pos -= 1;
                }
            }
            KeyCode::Delete => {
                let char_count = self.save_filename.chars().count();
                if self.save_cursor_pos < char_count {
                    let byte_idx = char_to_byte_index(&self.save_filename, self.save_cursor_pos);
                    self.save_filename.remove(byte_idx);
                }
            }
            KeyCode::Left => {
                self.save_cursor_pos = self.save_cursor_pos.saturating_sub(1);
            }
            KeyCode::Right => {
                let char_count = self.save_filename.chars().count();
                self.save_cursor_pos = (self.save_cursor_pos + 1).min(char_count);
            }
            KeyCode::Home => {
                self.save_cursor_pos = 0;
            }
            KeyCode::End => {
                self.save_cursor_pos = self.save_filename.chars().count();
            }
            KeyCode::Enter => {
                let filename = self.save_filename.trim().to_string();
                self.show_save_dialog = false;
                if !filename.is_empty() {
                    let path = PathBuf::from(&filename);
                    self.do_save(&path);
                    if self.quit_after_save {
                        self.quit_after_save = false;
                        self.running = false;
                    }
                } else {
                    self.quit_after_save = false;
                }
            }
            KeyCode::Esc => {
                self.show_save_dialog = false;
                self.quit_after_save = false;
            }
            _ => {}
        }
    }

    fn handle_open_dialog_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Tab => {
                if !self.recent_files.files.is_empty() {
                    self.open_mode = match self.open_mode {
                        OpenDialogMode::TextInput => OpenDialogMode::RecentList,
                        OpenDialogMode::RecentList => OpenDialogMode::TextInput,
                    };
                }
            }
            KeyCode::Esc => {
                self.show_open_dialog = false;
            }
            KeyCode::Enter => {
                let path = match self.open_mode {
                    OpenDialogMode::TextInput => {
                        if self.open_input.is_empty() {
                            return;
                        }
                        PathBuf::from(&self.open_input)
                    }
                    OpenDialogMode::RecentList => {
                        if let Some(entry) = self.recent_files.files.get(self.open_selected_recent) {
                            entry.path.clone()
                        } else {
                            return;
                        }
                    }
                };
                self.show_open_dialog = false;
                // Warn about unsaved data (lost on open)
                if self.store.is_modified() {
                    self.status_message = Some(
                        "Warning: unsaved packets discarded".into(),
                    );
                }
                if let Err(e) = self.do_open_file(&path) {
                    self.status_message = Some(format!("Open failed: {e:#}"));
                }
            }
            _ => match self.open_mode {
                OpenDialogMode::TextInput => self.handle_open_text_input(key),
                OpenDialogMode::RecentList => self.handle_open_recent_list(key),
            },
        }
    }

    fn handle_open_text_input(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c) if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT => {
                let byte_idx = char_to_byte_index(&self.open_input, self.open_cursor_pos);
                self.open_input.insert(byte_idx, c);
                self.open_cursor_pos += 1;
            }
            KeyCode::Backspace => {
                if self.open_cursor_pos > 0 {
                    let byte_idx = char_to_byte_index(&self.open_input, self.open_cursor_pos - 1);
                    self.open_input.remove(byte_idx);
                    self.open_cursor_pos -= 1;
                }
            }
            KeyCode::Delete => {
                let char_count = self.open_input.chars().count();
                if self.open_cursor_pos < char_count {
                    let byte_idx = char_to_byte_index(&self.open_input, self.open_cursor_pos);
                    self.open_input.remove(byte_idx);
                }
            }
            KeyCode::Left => {
                self.open_cursor_pos = self.open_cursor_pos.saturating_sub(1);
            }
            KeyCode::Right => {
                let char_count = self.open_input.chars().count();
                self.open_cursor_pos = (self.open_cursor_pos + 1).min(char_count);
            }
            KeyCode::Home => {
                self.open_cursor_pos = 0;
            }
            KeyCode::End => {
                self.open_cursor_pos = self.open_input.chars().count();
            }
            _ => {}
        }
    }

    fn handle_open_recent_list(&mut self, key: KeyEvent) {
        if self.recent_files.files.is_empty() {
            return;
        }
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.open_selected_recent =
                    (self.open_selected_recent + 1).min(self.recent_files.files.len() - 1);
                self.adjust_open_scroll();
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.open_selected_recent = self.open_selected_recent.saturating_sub(1);
                self.adjust_open_scroll();
            }
            KeyCode::Char('g') | KeyCode::Home => {
                self.open_selected_recent = 0;
                self.open_scroll_offset = 0;
            }
            KeyCode::Char('G') | KeyCode::End => {
                self.open_selected_recent = self.recent_files.files.len() - 1;
                self.adjust_open_scroll();
            }
            _ => {}
        }
    }

    fn adjust_open_scroll(&mut self) {
        let visible = 8usize; // conservative
        if self.open_selected_recent < self.open_scroll_offset {
            self.open_scroll_offset = self.open_selected_recent;
        } else if self.open_selected_recent >= self.open_scroll_offset + visible {
            self.open_scroll_offset = self.open_selected_recent.saturating_sub(visible - 1);
        }
    }

    fn handle_quit_confirm_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('s') | KeyCode::Char('S') => {
                self.show_quit_confirm = false;
                // Save then quit
                if let Some(path) = self.last_save_path.clone() {
                    self.do_save(&path);
                    self.running = false;
                } else {
                    // Open save dialog; quit automatically after save completes
                    self.quit_after_save = true;
                    self.open_save_dialog();
                }
            }
            KeyCode::Char('d') | KeyCode::Char('D') => {
                self.show_quit_confirm = false;
                self.running = false;
            }
            KeyCode::Char('c') | KeyCode::Char('C') | KeyCode::Esc => {
                self.show_quit_confirm = false;
                self.quit_after_save = false;
            }
            _ => {}
        }
    }

    // --- Filter engine methods ---

    fn start_filter_edit(&mut self) {
        self.filter_editing = true;
        self.filter_input = self.active_filter_text.clone();
        self.filter_cursor_pos = self.filter_input.chars().count();
        self.filter_error = false;
    }

    fn handle_filter_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                self.filter_editing = false;
                let input = self.filter_input.trim().to_string();
                if input.is_empty() {
                    self.clear_filter();
                } else {
                    self.apply_filter(&input);
                }
            }
            KeyCode::Esc => {
                self.filter_editing = false;
                self.filter_error = false;
                // Restore previous filter text
                self.filter_input = self.active_filter_text.clone();
            }
            KeyCode::Char(c) if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT => {
                let byte_idx = char_to_byte_index(&self.filter_input, self.filter_cursor_pos);
                self.filter_input.insert(byte_idx, c);
                self.filter_cursor_pos += 1;
            }
            KeyCode::Backspace => {
                if self.filter_cursor_pos > 0 {
                    let byte_idx = char_to_byte_index(&self.filter_input, self.filter_cursor_pos - 1);
                    self.filter_input.remove(byte_idx);
                    self.filter_cursor_pos -= 1;
                }
            }
            KeyCode::Delete => {
                let char_count = self.filter_input.chars().count();
                if self.filter_cursor_pos < char_count {
                    let byte_idx = char_to_byte_index(&self.filter_input, self.filter_cursor_pos);
                    self.filter_input.remove(byte_idx);
                }
            }
            KeyCode::Left => {
                self.filter_cursor_pos = self.filter_cursor_pos.saturating_sub(1);
            }
            KeyCode::Right => {
                let char_count = self.filter_input.chars().count();
                self.filter_cursor_pos = (self.filter_cursor_pos + 1).min(char_count);
            }
            KeyCode::Home => {
                self.filter_cursor_pos = 0;
            }
            KeyCode::End => {
                self.filter_cursor_pos = self.filter_input.chars().count();
            }
            _ => {}
        }
    }

    fn apply_filter(&mut self, input: &str) {
        match parser::parse(input) {
            Ok(expr) => {
                self.active_filter_text = input.to_string();
                self.filter_error = false;
                self.active_filter = Some(expr);
                self.rebuild_filtered_indices();
                // Reset scroll and selection to first match
                self.scroll_offset = 0;
                if let Some(ref indices) = self.filtered_indices {
                    self.selected_packet = indices.first().copied();
                    if let Some(idx) = self.selected_packet {
                        // Trigger dissection for first match
                        self.select_packet(idx);
                    }
                }
            }
            Err(e) => {
                self.filter_error = true;
                self.status_message = Some(format!("Filter error: {e}"));
                // Keep previous filter active if one exists, only clear text
                self.active_filter = None;
                self.active_filter_text.clear();
                self.filtered_indices = None;
            }
        }
    }

    fn clear_filter(&mut self) {
        self.active_filter = None;
        self.active_filter_text.clear();
        self.filter_input.clear();
        self.filter_cursor_pos = 0;
        self.filter_error = false;
        self.filtered_indices = None;
        // Reset scroll to keep view consistent
        self.scroll_offset = 0;
    }

    fn rebuild_filtered_indices(&mut self) {
        let Some(ref filter) = self.active_filter else {
            self.filtered_indices = None;
            return;
        };
        let mut indices = Vec::with_capacity(self.store.len() / 4 + 1);
        for i in 0..self.store.len() {
            if let Some(pkt) = self.store.get(i) {
                if eval::matches(filter, pkt) {
                    indices.push(i);
                }
            }
        }
        self.filtered_indices = Some(indices);
    }

    /// Number of packets visible in the current view (filtered or total).
    fn filtered_len(&self) -> usize {
        match &self.filtered_indices {
            Some(indices) => indices.len(),
            None => self.store.len(),
        }
    }

    /// Map a display row position to a store index.
    fn display_to_store_index(&self, display_pos: usize) -> usize {
        match &self.filtered_indices {
            Some(indices) => {
                // Clamp to valid range to avoid returning wrong packet
                let clamped = display_pos.min(indices.len().saturating_sub(1));
                indices.get(clamped).copied().unwrap_or(0)
            }
            None => display_pos,
        }
    }

    /// Find the display position of the currently selected packet.
    /// Uses binary search since filtered_indices is always sorted.
    fn selected_display_pos(&self) -> Option<usize> {
        let selected = self.selected_packet?;
        match &self.filtered_indices {
            Some(indices) => indices.binary_search(&selected).ok(),
            None => Some(selected),
        }
    }

    /// Get the visible packets for the current scroll offset and view.
    fn get_visible_packets(&self) -> Vec<PacketSummary> {
        match &self.filtered_indices {
            Some(indices) => {
                let start = self.scroll_offset.min(indices.len());
                let end = (self.scroll_offset + self.visible_rows).min(indices.len());
                indices[start..end]
                    .iter()
                    .filter_map(|&i| self.store.get(i).cloned())
                    .collect()
            }
            None => {
                self.store.get_range(self.scroll_offset, self.visible_rows).to_vec()
            }
        }
    }
}

/// Convert a char-based cursor position to a byte index in a string.
/// Panics if `char_pos` > number of chars (callers must clamp).
fn char_to_byte_index(s: &str, char_pos: usize) -> usize {
    s.char_indices()
        .nth(char_pos)
        .map(|(byte_idx, _)| byte_idx)
        .unwrap_or(s.len())
}

/// Convert days since Unix epoch to (year, month, day).
fn epoch_days_to_date(days: u64) -> (u64, u64, u64) {
    // Civil days algorithm (simplified)
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pane_next_cycles() {
        assert_eq!(Pane::PacketTable.next(), Pane::DetailTree);
        assert_eq!(Pane::DetailTree.next(), Pane::HexView);
        assert_eq!(Pane::HexView.next(), Pane::KernelTrace);
        assert_eq!(Pane::KernelTrace.next(), Pane::PacketTable);
    }

    #[test]
    fn pane_prev_cycles() {
        assert_eq!(Pane::PacketTable.prev(), Pane::KernelTrace);
        assert_eq!(Pane::DetailTree.prev(), Pane::PacketTable);
        assert_eq!(Pane::HexView.prev(), Pane::DetailTree);
        assert_eq!(Pane::KernelTrace.prev(), Pane::HexView);
    }

    #[test]
    fn capture_state_default() {
        let app = App::new(None, None, false, false);
        assert_eq!(app.capture_state, CaptureState::Idle);
        assert!(app.auto_scroll);
    }

    #[test]
    fn picker_scroll_adjusts() {
        let mut app = App::new(None, None, false, false);
        app.picker_selected = 25;
        app.adjust_picker_scroll();
        assert!(app.picker_scroll_offset > 0);
        assert!(app.picker_selected >= app.picker_scroll_offset);
    }

    #[test]
    fn default_save_filename_format() {
        let name = App::default_save_filename();
        assert!(name.starts_with("capture_"));
        assert!(name.ends_with(".pcap"));
        assert!(name.len() > 20); // capture_YYYYMMDD_HHMMSS.pcap
    }

    #[test]
    fn try_quit_with_empty_store() {
        let mut app = App::new(None, None, false, false);
        app.try_quit();
        assert!(!app.running); // Should quit immediately
    }

    #[test]
    fn epoch_date_known_value() {
        // 2024-01-01 is day 19723
        let (y, m, d) = epoch_days_to_date(19723);
        assert_eq!(y, 2024);
        assert_eq!(m, 1);
        assert_eq!(d, 1);
    }
}

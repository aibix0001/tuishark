use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::PathBuf;

use crate::capture::file::load_pcap;
use crate::dissect::fast::dissect_detail;
use crate::dissect::model::PacketDetail;
use crate::event::{Event, EventHandler};
use crate::store::packet_store::PacketStore;
use crate::tui::Tui;
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

pub struct App {
    running: bool,
    store: PacketStore,
    selected_packet: Option<usize>,
    scroll_offset: usize,
    active_pane: Pane,
    theme: Theme,
    detail: Option<PacketDetail>,
    expanded_layers: Vec<bool>,
    selected_layer: Option<usize>,
    file_path: Option<PathBuf>,
}

impl App {
    pub fn new(file: Option<PathBuf>) -> Self {
        Self {
            running: true,
            store: PacketStore::new(),
            selected_packet: None,
            scroll_offset: 0,
            active_pane: Pane::PacketTable,
            theme: Theme::mocha(),
            detail: None,
            expanded_layers: Vec::new(),
            selected_layer: None,
            file_path: file,
        }
    }

    pub async fn run(&mut self, terminal: &mut Tui) -> Result<()> {
        // Load file if provided
        if let Some(path) = &self.file_path {
            let packets = load_pcap(path)?;
            for pkt in packets {
                self.store.add(pkt);
            }
            if !self.store.is_empty() {
                self.select_packet(0);
            }
        }

        let events = EventHandler::new(33); // ~30fps

        while self.running {
            terminal.draw(|frame| self.render(frame))?;

            match events.next()? {
                Event::Key(key) => self.handle_key(key),
                Event::Tick => {}
                _ => {}
            }
        }

        Ok(())
    }

    fn render(&self, frame: &mut ratatui::Frame) {
        let layout = AppLayout::new(frame.area());

        // Header
        let header = Line::from(vec![
            Span::styled(
                " TuiShark v0.1.0 ",
                Style::default()
                    .fg(self.theme.blue)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                match &self.file_path {
                    Some(p) => format!(" — {} ", p.display()),
                    None => " — No file loaded ".into(),
                },
                Style::default().fg(self.theme.subtext0),
            ),
            Span::styled(
                " Catppuccin Mocha ",
                Style::default().fg(self.theme.mauve),
            ),
        ]);
        let header_widget = Paragraph::new(header)
            .style(Style::default().bg(self.theme.mantle));
        frame.render_widget(header_widget, layout.header);

        // Packet table — virtual scroll: only render visible rows
        let table_height = layout.packet_table.height.saturating_sub(3) as usize; // minus border + header
        let visible = self.store.get_range(self.scroll_offset, table_height);
        let table = PacketTable::new(
            visible,
            self.selected_packet,
            self.scroll_offset,
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
            .and_then(|idx| self.store.get(idx))
            .map(|pkt| pkt.raw_data.as_slice());
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
            &self.theme,
        );
        frame.render_widget(status, layout.status_bar);
    }

    fn handle_key(&mut self, key: KeyEvent) {
        // Global shortcuts
        match (key.modifiers, key.code) {
            (KeyModifiers::CONTROL, KeyCode::Char('c'))
            | (KeyModifiers::CONTROL, KeyCode::Char('q')) => {
                self.running = false;
                return;
            }
            (_, KeyCode::Char('q')) => {
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
            _ => {}
        }

        // Pane-specific handling
        match self.active_pane {
            Pane::PacketTable => self.handle_packet_table_key(key),
            Pane::DetailTree => self.handle_detail_tree_key(key),
            Pane::HexView => {} // no special keys yet
        }
    }

    fn handle_packet_table_key(&mut self, key: KeyEvent) {
        if self.store.is_empty() {
            return;
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
        if let Some(pkt) = self.store.get(index) {
            let detail = dissect_detail(&pkt.raw_data);
            let layer_count = detail.layers.len();
            self.detail = Some(detail);
            self.expanded_layers = vec![true; layer_count];
            self.selected_layer = if layer_count > 0 { Some(0) } else { None };
        }

        // Adjust scroll offset to keep selected packet visible
        // We estimate ~20 visible rows; will be refined when we know actual terminal height
        let visible_rows = 20_usize;
        if index < self.scroll_offset {
            self.scroll_offset = index;
        } else if index >= self.scroll_offset + visible_rows {
            self.scroll_offset = index - visible_rows + 1;
        }
    }
}

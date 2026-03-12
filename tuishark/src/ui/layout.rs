use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
};

use crate::app::Pane;

pub struct AppLayout {
    pub header: Rect,
    pub filter_bar: Rect,
    pub packet_table: Rect,
    pub detail_tree: Rect,
    pub bottom_left: Rect,
    pub bottom_right: Rect,
    pub status_bar: Rect,
}

impl AppLayout {
    pub fn new(area: Rect, zoomed: Option<Pane>) -> Self {
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),  // header
                Constraint::Length(1),  // filter bar
                Constraint::Min(10),   // content area
                Constraint::Length(1),  // status bar
            ])
            .split(area);

        let header = main_chunks[0];
        let filter_bar = main_chunks[1];
        let content = main_chunks[2];
        let status_bar = main_chunks[3];

        // When zoomed, give the full content area to the zoomed pane
        // and collapse all others to zero-height rects.
        if let Some(pane) = zoomed {
            let zero = Rect::new(content.x, content.y, content.width, 0);
            return match pane {
                Pane::PacketTable => Self {
                    header,
                    filter_bar,
                    packet_table: content,
                    detail_tree: zero,
                    bottom_left: zero,
                    bottom_right: zero,
                    status_bar,
                },
                Pane::DetailTree => Self {
                    header,
                    filter_bar,
                    packet_table: zero,
                    detail_tree: content,
                    bottom_left: zero,
                    bottom_right: zero,
                    status_bar,
                },
                Pane::HexView => Self {
                    header,
                    filter_bar,
                    packet_table: zero,
                    detail_tree: zero,
                    bottom_left: content,
                    bottom_right: zero,
                    status_bar,
                },
                Pane::KernelTrace => Self {
                    header,
                    filter_bar,
                    packet_table: zero,
                    detail_tree: zero,
                    bottom_left: zero,
                    bottom_right: content,
                    status_bar,
                },
            };
        }

        // Normal (non-zoomed) layout
        let normal_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(10),   // packet table
                Constraint::Length(10), // detail tree
                Constraint::Length(8),  // bottom panes
            ])
            .split(content);

        let bottom_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(50),
                Constraint::Percentage(50),
            ])
            .split(normal_chunks[2]);

        Self {
            header,
            filter_bar,
            packet_table: normal_chunks[0],
            detail_tree: normal_chunks[1],
            bottom_left: bottom_chunks[0],
            bottom_right: bottom_chunks[1],
            status_bar,
        }
    }
}

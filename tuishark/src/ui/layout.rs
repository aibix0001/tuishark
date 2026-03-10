use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
};

pub struct AppLayout {
    pub header: Rect,
    pub packet_table: Rect,
    pub detail_tree: Rect,
    pub bottom_left: Rect,
    pub bottom_right: Rect,
    pub status_bar: Rect,
}

impl AppLayout {
    pub fn new(area: Rect) -> Self {
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),  // header
                Constraint::Min(10),   // packet table
                Constraint::Length(10), // detail tree
                Constraint::Length(8),  // bottom panes
                Constraint::Length(1),  // status bar
            ])
            .split(area);

        let bottom_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(50),
                Constraint::Percentage(50),
            ])
            .split(main_chunks[3]);

        Self {
            header: main_chunks[0],
            packet_table: main_chunks[1],
            detail_tree: main_chunks[2],
            bottom_left: bottom_chunks[0],
            bottom_right: bottom_chunks[1],
            status_bar: main_chunks[4],
        }
    }
}

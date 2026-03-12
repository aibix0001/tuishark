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
            let (pt, dt, bl, br) = match pane {
                Pane::PacketTable => (content, zero, zero, zero),
                Pane::DetailTree => (zero, content, zero, zero),
                Pane::HexView    => (zero, zero, content, zero),
                Pane::KernelTrace => (zero, zero, zero, content),
            };
            return Self {
                header, filter_bar,
                packet_table: pt, detail_tree: dt,
                bottom_left: bl, bottom_right: br,
                status_bar,
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

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::layout::Rect;

    const AREA: Rect = Rect { x: 0, y: 0, width: 120, height: 40 };

    #[test]
    fn normal_layout_has_nonzero_panes() {
        let layout = AppLayout::new(AREA, None);
        assert_eq!(layout.header.height, 1);
        assert_eq!(layout.filter_bar.height, 1);
        assert_eq!(layout.status_bar.height, 1);
        assert!(layout.packet_table.height > 0);
        assert!(layout.detail_tree.height > 0);
        assert!(layout.bottom_left.height > 0);
        assert!(layout.bottom_right.height > 0);
    }

    #[test]
    fn zoom_packet_table_fills_content() {
        let layout = AppLayout::new(AREA, Some(Pane::PacketTable));
        assert!(layout.packet_table.height > 0);
        assert_eq!(layout.detail_tree.height, 0);
        assert_eq!(layout.bottom_left.height, 0);
        assert_eq!(layout.bottom_right.height, 0);
    }

    #[test]
    fn zoom_detail_tree_fills_content() {
        let layout = AppLayout::new(AREA, Some(Pane::DetailTree));
        assert_eq!(layout.packet_table.height, 0);
        assert!(layout.detail_tree.height > 0);
        assert_eq!(layout.bottom_left.height, 0);
        assert_eq!(layout.bottom_right.height, 0);
    }

    #[test]
    fn zoom_hex_view_fills_content() {
        let layout = AppLayout::new(AREA, Some(Pane::HexView));
        assert_eq!(layout.packet_table.height, 0);
        assert_eq!(layout.detail_tree.height, 0);
        assert!(layout.bottom_left.height > 0);
        assert_eq!(layout.bottom_right.height, 0);
    }

    #[test]
    fn zoom_kernel_trace_fills_content() {
        let layout = AppLayout::new(AREA, Some(Pane::KernelTrace));
        assert_eq!(layout.packet_table.height, 0);
        assert_eq!(layout.detail_tree.height, 0);
        assert_eq!(layout.bottom_left.height, 0);
        assert!(layout.bottom_right.height > 0);
    }

    #[test]
    fn zoomed_pane_gets_full_content_height() {
        let normal = AppLayout::new(AREA, None);
        let zoomed = AppLayout::new(AREA, Some(Pane::PacketTable));
        // Zoomed pane should be taller than the normal packet table
        assert!(zoomed.packet_table.height > normal.packet_table.height);
        // Zoomed height should equal the sum of all content pane heights
        let normal_content = normal.packet_table.height
            + normal.detail_tree.height
            + normal.bottom_left.height;
        assert_eq!(zoomed.packet_table.height, normal_content);
    }

    #[test]
    fn chrome_unchanged_when_zoomed() {
        let normal = AppLayout::new(AREA, None);
        let zoomed = AppLayout::new(AREA, Some(Pane::PacketTable));
        assert_eq!(normal.header, zoomed.header);
        assert_eq!(normal.filter_bar, zoomed.filter_bar);
        assert_eq!(normal.status_bar, zoomed.status_bar);
    }
}

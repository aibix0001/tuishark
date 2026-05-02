use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
};

use crate::app::Pane;

pub struct AppLayout {
    pub header: Rect,
    pub filter_bar: Rect,
    pub packet_table: Rect,
    pub detail_tree: Rect,
    pub hex_view: Rect,
    pub kernel_trace: Rect,
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
                Pane::KernelTrace => (zero, zero, zero, zero),
            };
            return Self {
                header, filter_bar,
                packet_table: pt, detail_tree: dt,
                hex_view: bl, kernel_trace: br,
                status_bar,
            };
        }

        // Normal (non-zoomed) layout
        const LOWER_HEIGHT: u16 = 18;

        // Step 1: packet table on top, lower area (detail + hex) below
        let main_rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(10),          // packet table
                Constraint::Max(LOWER_HEIGHT), // lower area shrinks on small terminals
            ])
            .split(content);

        // Step 2: split lower area into detail tree and hex dump
        let lower_cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(60),
                Constraint::Percentage(40),
            ])
            .split(main_rows[1]);

        Self {
            header,
            filter_bar,
            packet_table: main_rows[0],
            detail_tree: lower_cols[0],
            hex_view: lower_cols[1],
            kernel_trace: Rect::new(main_rows[1].x, main_rows[1].y, 0, 0),
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
        assert!(layout.hex_view.height > 0);
        assert_eq!(layout.kernel_trace.height, 0);
        assert_eq!(layout.kernel_trace.width, 0);
    }

    #[test]
    fn zoom_packet_table_fills_content() {
        let layout = AppLayout::new(AREA, Some(Pane::PacketTable));
        assert!(layout.packet_table.height > 0);
        assert_eq!(layout.detail_tree.height, 0);
        assert_eq!(layout.hex_view.height, 0);
        assert_eq!(layout.kernel_trace.height, 0);
    }

    #[test]
    fn zoom_detail_tree_fills_content() {
        let layout = AppLayout::new(AREA, Some(Pane::DetailTree));
        assert_eq!(layout.packet_table.height, 0);
        assert!(layout.detail_tree.height > 0);
        assert_eq!(layout.hex_view.height, 0);
        assert_eq!(layout.kernel_trace.height, 0);
    }

    #[test]
    fn zoom_hex_view_fills_content() {
        let layout = AppLayout::new(AREA, Some(Pane::HexView));
        assert_eq!(layout.packet_table.height, 0);
        assert_eq!(layout.detail_tree.height, 0);
        assert!(layout.hex_view.height > 0);
        assert_eq!(layout.kernel_trace.height, 0);
    }

    #[test]
    fn zoomed_pane_gets_full_content_height() {
        let normal = AppLayout::new(AREA, None);
        let zoomed = AppLayout::new(AREA, Some(Pane::PacketTable));
        // Zoomed pane should be taller than the normal packet table
        assert!(zoomed.packet_table.height > normal.packet_table.height);
        assert_eq!(
            zoomed.packet_table.height,
            normal.packet_table.height + normal.detail_tree.height
        );
    }

    #[test]
    fn detail_and_hex_share_lower_row() {
        let layout = AppLayout::new(AREA, None);
        assert_eq!(layout.detail_tree.y, layout.hex_view.y);
        assert_eq!(layout.detail_tree.height, layout.hex_view.height);
    }

    #[test]
    fn lower_row_uses_sixty_forty_split() {
        let layout = AppLayout::new(AREA, None);
        let total = layout.detail_tree.width + layout.hex_view.width;
        assert_eq!(total, AREA.width);
        assert!((layout.detail_tree.width as i16 - 72).abs() <= 1);
        assert!((layout.hex_view.width as i16 - 48).abs() <= 1);
    }

    #[test]
    fn small_terminal_layout_no_panic() {
        let small = Rect { x: 0, y: 0, width: 80, height: 24 };
        let layout = AppLayout::new(small, None);
        // Packet table should still be usable
        assert!(layout.packet_table.height >= 3);
        // All panes should have some height
        assert!(layout.detail_tree.height > 0);
        assert!(layout.hex_view.height > 0);
        assert_eq!(layout.kernel_trace.height, 0);
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

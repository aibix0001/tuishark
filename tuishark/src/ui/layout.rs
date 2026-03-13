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
                Pane::KernelTrace => (zero, zero, zero, content),
            };
            return Self {
                header, filter_bar,
                packet_table: pt, detail_tree: dt,
                hex_view: bl, kernel_trace: br,
                status_bar,
            };
        }

        // Normal (non-zoomed) layout
        const DETAIL_HEIGHT: u16 = 10;
        const HEX_HEIGHT: u16 = 8;
        const LOWER_HEIGHT: u16 = DETAIL_HEIGHT + HEX_HEIGHT;

        // Step 1: packet table on top, lower area (detail + hex | kernel trace) below
        let main_rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(10),          // packet table
                Constraint::Max(LOWER_HEIGHT), // lower area shrinks on small terminals
            ])
            .split(content);

        // Step 2: split lower area into left column and kernel trace (right)
        let lower_cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(50),
                Constraint::Percentage(50),
            ])
            .split(main_rows[1]);

        // Step 3: split left column into detail tree (top) and hex dump (bottom)
        let left_rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(DETAIL_HEIGHT),
                Constraint::Length(HEX_HEIGHT),
            ])
            .split(lower_cols[0]);

        Self {
            header,
            filter_bar,
            packet_table: main_rows[0],
            detail_tree: left_rows[0],
            hex_view: left_rows[1],
            kernel_trace: lower_cols[1],
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
        assert!(layout.kernel_trace.height > 0);
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
    fn zoom_kernel_trace_fills_content() {
        let layout = AppLayout::new(AREA, Some(Pane::KernelTrace));
        assert_eq!(layout.packet_table.height, 0);
        assert_eq!(layout.detail_tree.height, 0);
        assert_eq!(layout.hex_view.height, 0);
        assert!(layout.kernel_trace.height > 0);
    }

    #[test]
    fn zoomed_pane_gets_full_content_height() {
        let normal = AppLayout::new(AREA, None);
        let zoomed = AppLayout::new(AREA, Some(Pane::PacketTable));
        // Zoomed pane should be taller than the normal packet table
        assert!(zoomed.packet_table.height > normal.packet_table.height);
        // Zoomed height equals packet_table + left column stack (detail + hex)
        // (kernel_trace overlaps vertically with detail + hex, not additive)
        let left_stack = normal.packet_table.height
            + normal.detail_tree.height
            + normal.hex_view.height;
        assert_eq!(zoomed.packet_table.height, left_stack);
    }

    #[test]
    fn left_column_height_equals_right_column() {
        let layout = AppLayout::new(AREA, None);
        assert_eq!(
            layout.detail_tree.height + layout.hex_view.height,
            layout.kernel_trace.height,
            "left column sub-panes should sum to kernel trace height"
        );
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
        assert!(layout.kernel_trace.height > 0);
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

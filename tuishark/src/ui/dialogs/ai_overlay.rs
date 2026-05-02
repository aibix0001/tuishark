/// AI overlay dialog: two-pane modal showing packet detail tree on the left
/// and AI-generated explanation on the right.

use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Widget, Wrap},
};

use crate::ai::model::{AiOverlayFocus, AiState};
use crate::dissect::model::PacketDetail;
use crate::ui::theme::Theme;
use crate::ui::widgets::detail_tree::DetailTree;

pub struct AiOverlay<'a> {
    detail: Option<&'a PacketDetail>,
    expanded: &'a [bool],
    selected_layer: Option<usize>,
    selected_field: Option<usize>,
    detail_scroll_offset: usize,
    focus: AiOverlayFocus,
    ai_state: &'a AiState,
    right_scroll: usize,
    theme: &'a Theme,
}

impl<'a> AiOverlay<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        detail: Option<&'a PacketDetail>,
        expanded: &'a [bool],
        selected_layer: Option<usize>,
        selected_field: Option<usize>,
        detail_scroll_offset: usize,
        focus: AiOverlayFocus,
        ai_state: &'a AiState,
        right_scroll: usize,
        theme: &'a Theme,
    ) -> Self {
        Self {
            detail,
            expanded,
            selected_layer,
            selected_field,
            detail_scroll_offset,
            focus,
            ai_state,
            right_scroll,
            theme,
        }
    }
}

impl Widget for AiOverlay<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Dialog sizing: 90% width and height, centered
        let dialog_w = (u32::from(area.width) * 90 / 100).min(u32::from(area.width)) as u16;
        let dialog_h = (u32::from(area.height) * 90 / 100).min(u32::from(area.height)) as u16;
        let dialog_x = area.x + area.width.saturating_sub(dialog_w) / 2;
        let dialog_y = area.y + area.height.saturating_sub(dialog_h) / 2;
        let dialog_area = Rect::new(dialog_x, dialog_y, dialog_w, dialog_h);

        // Clear background
        Clear.render(dialog_area, buf);

        // Outer block
        let outer_block = Block::default()
            .title(" AI Packet Info ")
            .borders(Borders::ALL)
            .style(Style::default().fg(self.theme.text).bg(self.theme.base))
            .border_style(Style::default().fg(self.theme.lavender));
        let inner = outer_block.inner(dialog_area);
        outer_block.render(dialog_area, buf);

        if inner.height < 3 {
            return;
        }

        // Layout: content (fill) + help bar (1)
        let rows = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(inner);
        let content_area = rows[0];
        let help_area = rows[1];

        // Two-column split: 40% left (detail tree), 60% right (AI explanation)
        let cols = Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(content_area);
        let left_area = cols[0];
        let right_area = cols[1];

        // Left pane: DetailTree widget
        let left_focused = self.focus == AiOverlayFocus::Left;
        let detail_tree = DetailTree::new(
            self.detail,
            self.expanded,
            self.selected_layer,
            self.selected_field,
            self.theme,
            left_focused,
            self.detail_scroll_offset,
        );
        detail_tree.render(left_area, buf);

        // Right pane: AI explanation
        let right_focused = self.focus == AiOverlayFocus::Right;
        let right_border_style = if right_focused {
            Style::default().fg(self.theme.blue)
        } else {
            Style::default().fg(self.theme.surface2)
        };

        // Determine status dot color and label, and explanation text
        let (status_dot, dot_color, status_label, explanation) = match self.ai_state {
            AiState::Idle => (
                " ",
                self.theme.surface1,
                "",
                String::new(),
            ),
            AiState::Loading { .. } => (
                "●",
                self.theme.green,
                " Requesting explanation...",
                String::new(),
            ),
            AiState::Ready(text) => (
                "●",
                self.theme.green,
                " Explanation ready",
                text.clone(),
            ),
            AiState::Error(msg) => (
                "●",
                self.theme.red,
                "",
                msg.clone(),
            ),
            AiState::Unconfigured => (
                "●",
                self.theme.red,
                " AI not configured — add [ai] section to config.toml",
                "AI not configured.\n\nAdd [ai] section to ~/.config/tuishark/config.toml:\n\n\
                 [ai]\n\
                 enabled = true\n\
                 base_url = \"http://localhost:8100/v1\"\n\
                 model = \"your-model\""
                    .into(),
            ),
        };

        // Right pane block: reserve 1 line at the bottom for the status line
        // Layout within right pane: block wraps everything; inside: text (fill) + status (1)
        let right_block = Block::default()
            .title(" AI Explanation ")
            .borders(Borders::ALL)
            .border_style(right_border_style)
            .style(Style::default().bg(self.theme.base));
        let right_inner = right_block.inner(right_area);
        right_block.render(right_area, buf);

        if right_inner.height < 2 {
            // Not enough space to show content and status
        } else {
            let right_rows = Layout::vertical([
                Constraint::Min(1),
                Constraint::Length(1),
            ])
            .split(right_inner);
            let text_area = right_rows[0];
            let status_area = right_rows[1];

            // Explanation text with word wrap and scroll
            let text_widget = Paragraph::new(explanation)
                .style(Style::default().fg(self.theme.text).bg(self.theme.base))
                .wrap(Wrap { trim: false })
                .scroll((u16::try_from(self.right_scroll).unwrap_or(u16::MAX), 0));
            text_widget.render(text_area, buf);

            // Status line: colored dot + label
            let status_line = Line::from(vec![
                Span::styled(status_dot, Style::default().fg(dot_color)),
                Span::styled(status_label, Style::default().fg(self.theme.subtext0)),
            ]);
            Paragraph::new(status_line)
                .style(Style::default().bg(self.theme.mantle))
                .render(status_area, buf);
        }

        // Help bar at the very bottom of the dialog inner area
        let help = " Space:explain  Enter:expand  ←/→:pane  ö/ä:packet  Esc:close";
        let help_widget = Paragraph::new(help)
            .style(Style::default().fg(self.theme.subtext0).bg(self.theme.mantle));
        help_widget.render(help_area, buf);
    }
}

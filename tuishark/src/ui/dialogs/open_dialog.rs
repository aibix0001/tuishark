use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Widget},
};

use crate::session::recent::RecentEntry;
use crate::ui::theme::Theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenDialogMode {
    TextInput,
    RecentList,
}

pub struct OpenDialog<'a> {
    input: &'a str,
    cursor_pos: usize,
    recent: &'a [RecentEntry],
    selected_recent: usize,
    scroll_offset: usize,
    mode: OpenDialogMode,
    theme: &'a Theme,
}

impl<'a> OpenDialog<'a> {
    pub fn new(
        input: &'a str,
        cursor_pos: usize,
        recent: &'a [RecentEntry],
        selected_recent: usize,
        scroll_offset: usize,
        mode: OpenDialogMode,
        theme: &'a Theme,
    ) -> Self {
        Self {
            input,
            cursor_pos,
            recent,
            selected_recent,
            scroll_offset,
            mode,
            theme,
        }
    }
}

impl Widget for OpenDialog<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let dialog_width = 70u16.min(area.width.saturating_sub(4));
        let list_rows = self.recent.len().min(10) as u16;
        let dialog_height = (list_rows + 8).min(area.height.saturating_sub(4));
        let x = area.x + (area.width.saturating_sub(dialog_width)) / 2;
        let y = area.y + (area.height.saturating_sub(dialog_height)) / 2;
        let dialog_area = Rect::new(x, y, dialog_width, dialog_height);

        Clear.render(dialog_area, buf);

        let border_color = match self.mode {
            OpenDialogMode::TextInput => self.theme.blue,
            OpenDialogMode::RecentList => self.theme.mauve,
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(" Open File ")
            .title_style(
                Style::default()
                    .fg(border_color)
                    .add_modifier(Modifier::BOLD),
            )
            .style(Style::default().bg(self.theme.mantle));

        let inner = block.inner(dialog_area);
        block.render(dialog_area, buf);

        if inner.height < 4 {
            return;
        }

        let mut row = inner.y;

        // Path input label
        let label_style = if self.mode == OpenDialogMode::TextInput {
            Style::default().fg(self.theme.blue).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(self.theme.subtext0)
        };
        let label = Line::from(Span::styled(" Path:", label_style));
        buf.set_line(inner.x, row, &label, inner.width);
        row += 1;

        // Text input field
        let input_width = inner.width.saturating_sub(2) as usize;
        let input_style = Style::default()
            .fg(self.theme.text)
            .bg(self.theme.surface0);
        for col in (inner.x + 1)..(inner.x + inner.width.saturating_sub(1)) {
            buf[(col, row)].set_style(input_style);
        }

        let display_start = if self.cursor_pos > input_width.saturating_sub(1) {
            self.cursor_pos - input_width + 1
        } else {
            0
        };
        let visible: String = self
            .input
            .chars()
            .skip(display_start)
            .take(input_width)
            .collect();
        let text = Line::from(Span::styled(visible, input_style));
        buf.set_line(inner.x + 1, row, &text, inner.width.saturating_sub(2));

        // Cursor (only when in text mode)
        if self.mode == OpenDialogMode::TextInput {
            let cursor_screen_pos = self.cursor_pos - display_start;
            let cursor_x = inner.x + 1 + cursor_screen_pos as u16;
            if cursor_x < inner.x + inner.width.saturating_sub(1) {
                let cursor_style = Style::default()
                    .fg(self.theme.base)
                    .bg(self.theme.text);
                buf[(cursor_x, row)].set_style(cursor_style);
            }
        }
        row += 2; // blank line

        // Recent files section
        if !self.recent.is_empty() {
            let recent_label_style = if self.mode == OpenDialogMode::RecentList {
                Style::default().fg(self.theme.mauve).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(self.theme.subtext0)
            };
            let recent_label = Line::from(Span::styled(" Recent files:", recent_label_style));
            buf.set_line(inner.x, row, &recent_label, inner.width);
            row += 1;

            let list_height = inner.height.saturating_sub(row - inner.y + 1) as usize;
            let visible_recent = self
                .recent
                .iter()
                .enumerate()
                .skip(self.scroll_offset)
                .take(list_height);

            for (i, entry) in visible_recent {
                if row >= inner.y + inner.height.saturating_sub(1) {
                    break;
                }
                let is_selected =
                    self.mode == OpenDialogMode::RecentList && i == self.selected_recent;
                let style = if is_selected {
                    Style::default()
                        .fg(self.theme.base)
                        .bg(self.theme.mauve)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                        .fg(self.theme.text)
                        .bg(self.theme.mantle)
                };

                // Fill row background
                for col in inner.x..inner.x + inner.width {
                    buf[(col, row)].set_style(style);
                }

                let path_str = entry.path.display().to_string();
                let max_len = inner.width.saturating_sub(2) as usize;
                let truncated: String = if path_str.len() > max_len {
                    format!("...{}", &path_str[path_str.len() - max_len + 3..])
                } else {
                    path_str
                };
                let line = Line::from(Span::styled(format!(" {truncated}"), style));
                buf.set_line(inner.x, row, &line, inner.width);
                row += 1;
            }
        }

        // Help line
        let help_y = inner.y + inner.height.saturating_sub(1);
        let help = Line::from(Span::styled(
            " Tab:switch  Enter:open  Esc:cancel ",
            Style::default().fg(self.theme.subtext0),
        ));
        buf.set_line(inner.x, help_y, &help, inner.width);
    }
}

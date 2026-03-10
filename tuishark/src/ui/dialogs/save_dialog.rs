use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Widget},
};

use crate::ui::theme::Theme;

pub struct SaveDialog<'a> {
    filename: &'a str,
    cursor_pos: usize,
    theme: &'a Theme,
}

impl<'a> SaveDialog<'a> {
    pub fn new(filename: &'a str, cursor_pos: usize, theme: &'a Theme) -> Self {
        Self {
            filename,
            cursor_pos,
            theme,
        }
    }
}

impl Widget for SaveDialog<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let dialog_width = 60u16.min(area.width.saturating_sub(4));
        let dialog_height = 7u16.min(area.height.saturating_sub(4));
        let x = area.x + (area.width.saturating_sub(dialog_width)) / 2;
        let y = area.y + (area.height.saturating_sub(dialog_height)) / 2;
        let dialog_area = Rect::new(x, y, dialog_width, dialog_height);

        Clear.render(dialog_area, buf);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.green))
            .title(" Save Capture ")
            .title_style(
                Style::default()
                    .fg(self.theme.green)
                    .add_modifier(Modifier::BOLD),
            )
            .style(Style::default().bg(self.theme.mantle));

        let inner = block.inner(dialog_area);
        block.render(dialog_area, buf);

        if inner.height < 3 {
            return;
        }

        // Label
        let label = Line::from(Span::styled(
            " Filename:",
            Style::default().fg(self.theme.subtext0),
        ));
        buf.set_line(inner.x, inner.y, &label, inner.width);

        // Text input field
        let input_y = inner.y + 1;
        let input_width = inner.width.saturating_sub(2) as usize;

        // Fill input background
        let input_style = Style::default()
            .fg(self.theme.text)
            .bg(self.theme.surface0);
        for col in (inner.x + 1)..(inner.x + inner.width.saturating_sub(1)) {
            buf[(col, input_y)].set_style(input_style);
        }

        // Render filename text (scroll if needed)
        let display_start = if self.cursor_pos > input_width.saturating_sub(1) {
            self.cursor_pos - input_width + 1
        } else {
            0
        };
        let visible: String = self
            .filename
            .chars()
            .skip(display_start)
            .take(input_width)
            .collect();
        let text = Line::from(Span::styled(visible, input_style));
        buf.set_line(inner.x + 1, input_y, &text, inner.width.saturating_sub(2));

        // Cursor
        let cursor_screen_pos = self.cursor_pos - display_start;
        let cursor_x = inner.x + 1 + cursor_screen_pos as u16;
        if cursor_x < inner.x + inner.width.saturating_sub(1) {
            let cursor_style = Style::default()
                .fg(self.theme.base)
                .bg(self.theme.text);
            buf[(cursor_x, input_y)].set_style(cursor_style);
        }

        // Help line
        let help_y = inner.y + inner.height.saturating_sub(1);
        let help = Line::from(Span::styled(
            " Enter:save  Esc:cancel ",
            Style::default().fg(self.theme.subtext0),
        ));
        buf.set_line(inner.x, help_y, &help, inner.width);
    }
}

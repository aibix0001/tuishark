use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Widget,
};

use crate::ui::theme::Theme;

pub struct FilterBar<'a> {
    input: &'a str,
    cursor_pos: usize,
    editing: bool,
    active_display: Option<&'a str>,
    match_count: Option<(usize, usize)>, // (matched, total)
    is_error: bool,
    theme: &'a Theme,
}

impl<'a> FilterBar<'a> {
    pub fn new(
        input: &'a str,
        cursor_pos: usize,
        editing: bool,
        active_display: Option<&'a str>,
        match_count: Option<(usize, usize)>,
        is_error: bool,
        theme: &'a Theme,
    ) -> Self {
        Self {
            input,
            cursor_pos,
            editing,
            active_display,
            match_count,
            is_error,
            theme,
        }
    }
}

impl Widget for FilterBar<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height == 0 || area.width < 10 {
            return;
        }

        // Fill background
        let bg = self.theme.mantle;
        for x in area.left()..area.right() {
            buf[(x, area.y)].set_style(Style::default().bg(bg));
        }

        let border_color = if self.is_error {
            self.theme.red
        } else if self.active_display.is_some() {
            self.theme.green
        } else if self.editing {
            self.theme.blue
        } else {
            self.theme.surface2
        };

        let label_style = Style::default()
            .fg(self.theme.base)
            .bg(border_color)
            .add_modifier(Modifier::BOLD);

        let mut spans = vec![Span::styled(" Filter ", label_style)];

        if self.editing {
            // Show input text with cursor
            let input_style = Style::default().fg(self.theme.text).bg(bg);
            spans.push(Span::styled(" ", input_style));

            let input_chars: Vec<char> = self.input.chars().collect();
            let before: String = input_chars[..self.cursor_pos].iter().collect();
            let cursor_char = input_chars.get(self.cursor_pos).copied().unwrap_or(' ');
            let after: String = if self.cursor_pos < input_chars.len() {
                input_chars[self.cursor_pos + 1..].iter().collect()
            } else {
                String::new()
            };

            spans.push(Span::styled(before, input_style));
            spans.push(Span::styled(
                cursor_char.to_string(),
                Style::default()
                    .fg(self.theme.base)
                    .bg(self.theme.text)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled(after, input_style));
        } else if let Some(display) = self.active_display {
            // Show active filter expression
            let display_style = if self.is_error {
                Style::default().fg(self.theme.red).bg(bg)
            } else {
                Style::default().fg(self.theme.green).bg(bg)
            };
            spans.push(Span::styled(format!(" {display} "), display_style));

            // Show match count
            if let Some((matched, total)) = self.match_count {
                let count_style = Style::default().fg(self.theme.subtext0).bg(bg);
                spans.push(Span::styled(
                    format!("[{matched}/{total}]"),
                    count_style,
                ));
            }
        } else {
            // Inactive: show hint
            let hint_style = Style::default().fg(self.theme.surface2).bg(bg);
            spans.push(Span::styled(" Press / to filter", hint_style));
        }

        let line = Line::from(spans);
        buf.set_line(area.x, area.y, &line, area.width);
    }
}

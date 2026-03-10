use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Widget},
};

use crate::ui::theme::Theme;

pub struct HexView<'a> {
    data: Option<&'a [u8]>,
    highlight_range: Option<(usize, usize)>,
    theme: &'a Theme,
    focused: bool,
}

impl<'a> HexView<'a> {
    pub fn new(
        data: Option<&'a [u8]>,
        highlight_range: Option<(usize, usize)>,
        theme: &'a Theme,
        focused: bool,
    ) -> Self {
        Self {
            data,
            highlight_range,
            theme,
            focused,
        }
    }
}

impl Widget for HexView<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let border_style = if self.focused {
            Style::default().fg(self.theme.blue)
        } else {
            Style::default().fg(self.theme.surface2)
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(" Hex Dump ")
            .title_style(Style::default().fg(self.theme.text))
            .style(Style::default().bg(self.theme.base));

        let Some(data) = self.data else {
            let p = Paragraph::new("No packet selected")
                .style(Style::default().fg(self.theme.subtext0))
                .block(block);
            p.render(area, buf);
            return;
        };

        let highlight = self.highlight_range;
        let hl_style = Style::default()
            .fg(self.theme.base)
            .bg(self.theme.yellow);
        let normal_hex_style = Style::default().fg(self.theme.text);
        let normal_ascii_style = Style::default().fg(self.theme.green);

        let max_lines = area.height.saturating_sub(2) as usize;
        let mut lines: Vec<Line<'_>> = Vec::new();

        for (i, chunk) in data.chunks(16).enumerate() {
            if lines.len() >= max_lines {
                break;
            }

            let row_offset = i * 16;
            let offset_str = format!("{:04x}  ", row_offset);

            // Build hex spans with highlighting
            let mut hex_spans: Vec<Span<'_>> = Vec::new();
            for (j, b) in chunk.iter().enumerate() {
                let byte_pos = row_offset + j;
                let is_highlighted = highlight
                    .map(|(s, e)| byte_pos >= s && byte_pos < e)
                    .unwrap_or(false);

                let separator = if j == 8 { " " } else { "" };
                if !separator.is_empty() {
                    hex_spans.push(Span::styled(separator.to_string(), normal_hex_style));
                }

                let hex_str = format!("{:02x} ", b);
                let style = if is_highlighted { hl_style } else { normal_hex_style };
                hex_spans.push(Span::styled(hex_str, style));
            }

            // Pad remaining hex space
            let remaining = 16 - chunk.len();
            if remaining > 0 {
                let pad_width = remaining * 3 + if chunk.len() <= 8 { 1 } else { 0 };
                hex_spans.push(Span::styled(
                    " ".repeat(pad_width),
                    normal_hex_style,
                ));
            }

            // Build ASCII spans with highlighting
            let mut ascii_spans: Vec<Span<'_>> = Vec::new();
            for (j, b) in chunk.iter().enumerate() {
                let byte_pos = row_offset + j;
                let is_highlighted = highlight
                    .map(|(s, e)| byte_pos >= s && byte_pos < e)
                    .unwrap_or(false);

                let ch = if b.is_ascii_graphic() || *b == b' ' {
                    *b as char
                } else {
                    '.'
                };

                let style = if is_highlighted { hl_style } else { normal_ascii_style };
                ascii_spans.push(Span::styled(ch.to_string(), style));
            }

            let mut spans = vec![
                Span::styled(offset_str, Style::default().fg(self.theme.overlay0)),
            ];
            spans.extend(hex_spans);
            spans.push(Span::styled(" ", Style::default()));
            spans.extend(ascii_spans);

            lines.push(Line::from(spans));
        }

        let p = Paragraph::new(lines).block(block);
        p.render(area, buf);
    }
}

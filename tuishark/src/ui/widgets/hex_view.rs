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
    theme: &'a Theme,
    focused: bool,
}

impl<'a> HexView<'a> {
    pub fn new(data: Option<&'a [u8]>, theme: &'a Theme, focused: bool) -> Self {
        Self {
            data,
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

        let max_lines = area.height.saturating_sub(2) as usize;
        let mut lines: Vec<Line<'_>> = Vec::new();

        for (i, chunk) in data.chunks(16).enumerate() {
            if lines.len() >= max_lines {
                break;
            }

            let offset_str = format!("{:04x}  ", i * 16);

            let hex_part: String = chunk
                .iter()
                .enumerate()
                .map(|(j, b)| {
                    if j == 8 {
                        format!(" {:02x}", b)
                    } else {
                        format!("{:02x} ", b)
                    }
                })
                .collect();
            let hex_padded = format!("{:<49}", hex_part);

            let ascii_part: String = chunk
                .iter()
                .map(|b| {
                    if b.is_ascii_graphic() || *b == b' ' {
                        *b as char
                    } else {
                        '.'
                    }
                })
                .collect();

            lines.push(Line::from(vec![
                Span::styled(offset_str, Style::default().fg(self.theme.overlay0)),
                Span::styled(hex_padded, Style::default().fg(self.theme.text)),
                Span::styled(" ".to_string(), Style::default()),
                Span::styled(ascii_part, Style::default().fg(self.theme.green)),
            ]));
        }

        let p = Paragraph::new(lines).block(block);
        p.render(area, buf);
    }
}

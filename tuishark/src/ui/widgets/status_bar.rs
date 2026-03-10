use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Widget,
};

use crate::ui::theme::Theme;

pub struct StatusBar<'a> {
    packet_count: usize,
    selected: Option<usize>,
    theme: &'a Theme,
}

impl<'a> StatusBar<'a> {
    pub fn new(packet_count: usize, selected: Option<usize>, theme: &'a Theme) -> Self {
        Self {
            packet_count,
            selected,
            theme,
        }
    }
}

impl Widget for StatusBar<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let sel_text = match self.selected {
            Some(idx) => format!("Selected: {} ", idx + 1),
            None => String::new(),
        };

        let line = Line::from(vec![
            Span::styled(
                format!(" Packets: {} ", self.packet_count),
                Style::default().fg(self.theme.text).bg(self.theme.surface0),
            ),
            Span::styled(
                " │ ",
                Style::default().fg(self.theme.overlay0).bg(self.theme.surface0),
            ),
            Span::styled(
                sel_text,
                Style::default().fg(self.theme.text).bg(self.theme.surface0),
            ),
            Span::styled(
                " TuiShark v0.1.0 ",
                Style::default().fg(self.theme.subtext0).bg(self.theme.surface0),
            ),
        ]);

        // Fill background
        for x in area.left()..area.right() {
            buf[(x, area.y)]
                .set_style(Style::default().bg(self.theme.surface0));
        }

        buf.set_line(area.x, area.y, &line, area.width);
    }
}

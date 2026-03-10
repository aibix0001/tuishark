use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Widget},
};

use crate::ui::theme::Theme;

pub struct QuitConfirm<'a> {
    theme: &'a Theme,
}

impl<'a> QuitConfirm<'a> {
    pub fn new(theme: &'a Theme) -> Self {
        Self { theme }
    }
}

impl Widget for QuitConfirm<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let dialog_width = 50u16.min(area.width.saturating_sub(4));
        let dialog_height = 5u16.min(area.height.saturating_sub(4));
        let x = area.x + (area.width.saturating_sub(dialog_width)) / 2;
        let y = area.y + (area.height.saturating_sub(dialog_height)) / 2;
        let dialog_area = Rect::new(x, y, dialog_width, dialog_height);

        Clear.render(dialog_area, buf);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.yellow))
            .title(" Unsaved Packets ")
            .title_style(
                Style::default()
                    .fg(self.theme.yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .style(Style::default().bg(self.theme.mantle));

        let inner = block.inner(dialog_area);
        block.render(dialog_area, buf);

        if inner.height < 2 {
            return;
        }

        let msg = Line::from(Span::styled(
            " Save before quitting?",
            Style::default().fg(self.theme.text),
        ));
        buf.set_line(inner.x, inner.y, &msg, inner.width);

        let help_y = inner.y + inner.height.saturating_sub(1);
        let help = Line::from(vec![
            Span::styled(" [", Style::default().fg(self.theme.subtext0)),
            Span::styled("S", Style::default().fg(self.theme.green).add_modifier(Modifier::BOLD)),
            Span::styled("]ave  [", Style::default().fg(self.theme.subtext0)),
            Span::styled("D", Style::default().fg(self.theme.red).add_modifier(Modifier::BOLD)),
            Span::styled("]iscard  [", Style::default().fg(self.theme.subtext0)),
            Span::styled("C", Style::default().fg(self.theme.blue).add_modifier(Modifier::BOLD)),
            Span::styled("]ancel", Style::default().fg(self.theme.subtext0)),
        ]);
        buf.set_line(inner.x, help_y, &help, inner.width);
    }
}

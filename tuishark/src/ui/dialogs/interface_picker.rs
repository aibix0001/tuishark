use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Widget},
};

use crate::capture::live::InterfaceInfo;
use crate::ui::theme::Theme;

pub struct InterfacePicker<'a> {
    interfaces: &'a [InterfaceInfo],
    selected: usize,
    theme: &'a Theme,
}

impl<'a> InterfacePicker<'a> {
    pub fn new(interfaces: &'a [InterfaceInfo], selected: usize, theme: &'a Theme) -> Self {
        Self {
            interfaces,
            selected,
            theme,
        }
    }
}

impl Widget for InterfacePicker<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Calculate centered dialog size
        let dialog_width = 60u16.min(area.width.saturating_sub(4));
        let dialog_height = (self.interfaces.len() as u16 + 4).min(area.height.saturating_sub(4));
        let x = area.x + (area.width.saturating_sub(dialog_width)) / 2;
        let y = area.y + (area.height.saturating_sub(dialog_height)) / 2;
        let dialog_area = Rect::new(x, y, dialog_width, dialog_height);

        // Clear background
        Clear.render(dialog_area, buf);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.blue))
            .title(" Select Interface ")
            .title_style(Style::default().fg(self.theme.blue).add_modifier(Modifier::BOLD))
            .style(Style::default().bg(self.theme.mantle));

        let inner = block.inner(dialog_area);
        block.render(dialog_area, buf);

        // Help line at bottom
        let help_y = inner.y + inner.height.saturating_sub(1);
        let help = Line::from(vec![
            Span::styled(
                " j/k:navigate  Enter:select  Esc:quit ",
                Style::default().fg(self.theme.subtext0),
            ),
        ]);
        buf.set_line(inner.x, help_y, &help, inner.width);

        // Interface list
        let list_height = inner.height.saturating_sub(1) as usize;
        for (i, iface) in self.interfaces.iter().enumerate() {
            if i >= list_height {
                break;
            }

            let is_selected = i == self.selected;
            let style = if is_selected {
                Style::default()
                    .fg(self.theme.base)
                    .bg(self.theme.blue)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(self.theme.text)
                    .bg(self.theme.mantle)
            };

            let desc = if iface.description.is_empty() {
                String::new()
            } else {
                format!(" ({})", iface.description)
            };

            let max_name = (inner.width as usize).saturating_sub(desc.len() + 2);
            let name = if iface.name.len() > max_name {
                format!("{}...", &iface.name[..max_name.saturating_sub(3)])
            } else {
                iface.name.clone()
            };

            let line = format!(" {name}{desc}");
            let row_y = inner.y + i as u16;

            // Fill row background
            for col in inner.x..inner.x + inner.width {
                buf[(col, row_y)].set_style(style);
            }

            let text = Line::from(Span::styled(line, style));
            buf.set_line(inner.x, row_y, &text, inner.width);
        }
    }
}

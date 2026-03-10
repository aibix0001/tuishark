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
    scroll_offset: usize,
    theme: &'a Theme,
}

impl<'a> InterfacePicker<'a> {
    pub fn new(
        interfaces: &'a [InterfaceInfo],
        selected: usize,
        scroll_offset: usize,
        theme: &'a Theme,
    ) -> Self {
        Self {
            interfaces,
            selected,
            scroll_offset,
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
        let help = Line::from(Span::styled(
            " j/k:navigate  Enter:select  Esc:quit ",
            Style::default().fg(self.theme.subtext0),
        ));
        buf.set_line(inner.x, help_y, &help, inner.width);

        // Empty list message
        if self.interfaces.is_empty() {
            let msg = Line::from(Span::styled(
                " No interfaces found (need root?)",
                Style::default().fg(self.theme.red),
            ));
            buf.set_line(inner.x, inner.y, &msg, inner.width);
            return;
        }

        // Interface list with scroll offset
        let list_height = inner.height.saturating_sub(1) as usize;
        let visible_interfaces = self
            .interfaces
            .iter()
            .enumerate()
            .skip(self.scroll_offset)
            .take(list_height);

        for (i, iface) in visible_interfaces {
            let row_index = i - self.scroll_offset;
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

            let available_width = inner.width as usize;
            let max_len = available_width.saturating_sub(1); // 1 char leading space
            let full_text = format!("{}{}", iface.name, desc);
            let truncated: String = full_text.chars().take(max_len).collect();
            let line = format!(" {truncated}");

            let row_y = inner.y + row_index as u16;

            // Fill row background
            for col in inner.x..inner.x + inner.width {
                buf[(col, row_y)].set_style(style);
            }

            let text = Line::from(Span::styled(line, style));
            buf.set_line(inner.x, row_y, &text, inner.width);
        }
    }
}

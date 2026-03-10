use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Widget},
};

use crate::config::filters::FilterPreset;
use crate::ui::theme::Theme;

pub struct PresetPicker<'a> {
    presets: &'a [FilterPreset],
    selected: usize,
    scroll_offset: usize,
    theme: &'a Theme,
}

impl<'a> PresetPicker<'a> {
    pub fn new(
        presets: &'a [FilterPreset],
        selected: usize,
        scroll_offset: usize,
        theme: &'a Theme,
    ) -> Self {
        Self {
            presets,
            selected,
            scroll_offset,
            theme,
        }
    }
}

impl Widget for PresetPicker<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let dialog_w = 60u16.min(area.width.saturating_sub(4));
        let max_items = 12u16;
        let item_count = self.presets.len() as u16;
        let list_h = item_count.min(max_items);
        let dialog_h = list_h + 4; // border(2) + title line + help line
        let x = area.x + (area.width.saturating_sub(dialog_w)) / 2;
        let y = area.y + (area.height.saturating_sub(dialog_h)) / 2;
        let dialog_area = Rect::new(x, y, dialog_w, dialog_h);

        Clear.render(dialog_area, buf);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.blue))
            .title(" Filter Presets ")
            .title_style(Style::default().fg(self.theme.text).add_modifier(Modifier::BOLD))
            .style(Style::default().bg(self.theme.base));

        let inner = block.inner(dialog_area);
        block.render(dialog_area, buf);

        if self.presets.is_empty() {
            let msg = Paragraph::new("No filter presets configured.")
                .style(Style::default().fg(self.theme.subtext0));
            msg.render(inner, buf);
            return;
        }

        let visible_count = list_h as usize;
        let mut lines: Vec<Line<'_>> = Vec::new();

        for i in self.scroll_offset..(self.scroll_offset + visible_count).min(self.presets.len()) {
            let preset = &self.presets[i];
            let is_selected = i == self.selected;
            let marker = if is_selected { "▸ " } else { "  " };
            let style = if is_selected {
                Style::default()
                    .fg(self.theme.base)
                    .bg(self.theme.blue)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(self.theme.text)
            };

            let desc_str = preset
                .description
                .as_deref()
                .map(|d| format!(" — {d}"))
                .unwrap_or_default();

            let name_spans = vec![
                Span::styled(marker.to_string(), style),
                Span::styled(preset.name.clone(), style),
                Span::styled(
                    desc_str,
                    if is_selected {
                        style
                    } else {
                        Style::default().fg(self.theme.subtext0)
                    },
                ),
            ];
            lines.push(Line::from(name_spans));
        }

        // Help line
        let help_y = inner.y + inner.height.saturating_sub(1);
        if help_y > inner.y + lines.len() as u16 {
            let help = Line::from(vec![
                Span::styled("Enter", Style::default().fg(self.theme.green)),
                Span::styled(" apply  ", Style::default().fg(self.theme.subtext0)),
                Span::styled("Esc", Style::default().fg(self.theme.green)),
                Span::styled(" cancel", Style::default().fg(self.theme.subtext0)),
            ]);
            buf.set_line(inner.x, help_y, &help, inner.width);
        }

        let list_area = Rect::new(inner.x, inner.y, inner.width, list_h.min(inner.height.saturating_sub(1)));
        let paragraph = Paragraph::new(lines);
        paragraph.render(list_area, buf);
    }
}

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Widget},
};

use crate::dissect::model::PacketDetail;
use crate::ui::theme::Theme;

pub struct DetailTree<'a> {
    detail: Option<&'a PacketDetail>,
    expanded: &'a [bool],
    selected_layer: Option<usize>,
    selected_field: Option<usize>,
    theme: &'a Theme,
    focused: bool,
}

impl<'a> DetailTree<'a> {
    pub fn new(
        detail: Option<&'a PacketDetail>,
        expanded: &'a [bool],
        selected_layer: Option<usize>,
        selected_field: Option<usize>,
        theme: &'a Theme,
        focused: bool,
    ) -> Self {
        Self {
            detail,
            expanded,
            selected_layer,
            selected_field,
            theme,
            focused,
        }
    }
}

impl Widget for DetailTree<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let border_style = if self.focused {
            Style::default().fg(self.theme.blue)
        } else {
            Style::default().fg(self.theme.surface2)
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(" Packet Detail ")
            .title_style(Style::default().fg(self.theme.text))
            .style(Style::default().bg(self.theme.base));

        let Some(detail) = self.detail else {
            let p = Paragraph::new("No packet selected")
                .style(Style::default().fg(self.theme.subtext0))
                .block(block);
            p.render(area, buf);
            return;
        };

        let mut lines = Vec::new();

        for (i, layer) in detail.layers.iter().enumerate() {
            let is_expanded = self.expanded.get(i).copied().unwrap_or(true);
            let is_selected = self.selected_layer == Some(i) && self.selected_field.is_none();

            let arrow = if is_expanded { "▾" } else { "▸" };
            let layer_style = if is_selected {
                Style::default()
                    .fg(self.theme.base)
                    .bg(self.theme.blue)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(self.theme.green)
                    .add_modifier(Modifier::BOLD)
            };

            lines.push(Line::from(Span::styled(
                format!("{arrow} {}", layer.name),
                layer_style,
            )));

            if is_expanded {
                for (fi, field) in layer.fields.iter().enumerate() {
                    let is_field_selected = self.selected_layer == Some(i)
                        && self.selected_field == Some(fi);

                    if is_field_selected {
                        lines.push(Line::from(vec![
                            Span::styled("    ", Style::default().bg(self.theme.surface1)),
                            Span::styled(
                                &field.name,
                                Style::default()
                                    .fg(self.theme.base)
                                    .bg(self.theme.yellow),
                            ),
                            Span::styled(
                                ": ",
                                Style::default()
                                    .fg(self.theme.base)
                                    .bg(self.theme.yellow),
                            ),
                            Span::styled(
                                &field.value,
                                Style::default()
                                    .fg(self.theme.base)
                                    .bg(self.theme.yellow),
                            ),
                        ]));
                    } else {
                        lines.push(Line::from(vec![
                            Span::styled("    ", Style::default()),
                            Span::styled(&field.name, Style::default().fg(self.theme.subtext1)),
                            Span::styled(": ", Style::default().fg(self.theme.overlay0)),
                            Span::styled(&field.value, Style::default().fg(self.theme.text)),
                        ]));
                    }
                }
            }
        }

        let p = Paragraph::new(lines).block(block);
        p.render(area, buf);
    }
}

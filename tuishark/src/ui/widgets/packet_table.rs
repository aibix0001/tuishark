use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    widgets::{Block, Borders, Row, Table, Widget},
};

use crate::dissect::model::PacketSummary;
use crate::ui::theme::Theme;

pub struct PacketTable<'a> {
    packets: &'a [PacketSummary],
    selected: Option<usize>,
    offset: usize,
    theme: &'a Theme,
    focused: bool,
}

impl<'a> PacketTable<'a> {
    pub fn new(
        packets: &'a [PacketSummary],
        selected: Option<usize>,
        offset: usize,
        theme: &'a Theme,
        focused: bool,
    ) -> Self {
        Self {
            packets,
            selected,
            offset,
            theme,
            focused,
        }
    }
}

impl Widget for PacketTable<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let border_style = if self.focused {
            Style::default().fg(self.theme.blue)
        } else {
            Style::default().fg(self.theme.surface2)
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(" Packets ")
            .title_style(Style::default().fg(self.theme.text))
            .style(Style::default().bg(self.theme.base));

        let header = Row::new(vec!["No.", "Time", "Source", "Destination", "Proto", "Len", "Info"])
            .style(
                Style::default()
                    .fg(self.theme.text)
                    .bg(self.theme.surface0)
                    .add_modifier(Modifier::BOLD),
            );

        let rows: Vec<Row> = self
            .packets
            .iter()
            .map(|pkt| {
                let proto_color = self.theme.protocol_color(&pkt.protocol);
                let is_selected = self.selected == Some(pkt.index);

                let style = if is_selected {
                    Style::default()
                        .fg(self.theme.base)
                        .bg(self.theme.blue)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(proto_color).bg(self.theme.base)
                };

                Row::new(vec![
                    format!("{}", pkt.index + 1),
                    format!("{:.6}", pkt.timestamp),
                    pkt.source.clone(),
                    pkt.destination.clone(),
                    format!("{}", pkt.protocol),
                    format!("{}", pkt.length),
                    pkt.info.clone(),
                ])
                .style(style)
            })
            .collect();

        let widths = [
            ratatui::layout::Constraint::Length(6),
            ratatui::layout::Constraint::Length(12),
            ratatui::layout::Constraint::Length(18),
            ratatui::layout::Constraint::Length(18),
            ratatui::layout::Constraint::Length(8),
            ratatui::layout::Constraint::Length(6),
            ratatui::layout::Constraint::Min(20),
        ];

        let table = Table::new(rows, widths)
            .header(header)
            .block(block);

        table.render(area, buf);
    }
}

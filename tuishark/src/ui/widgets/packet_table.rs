use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    widgets::{Block, Borders, Row, Table, Widget},
};

use crate::config::columns::{Column, ColumnConfig};
use crate::config::TimestampFormat;
use crate::dissect::model::PacketSummary;
use crate::ui::theme::Theme;

pub struct PacketTable<'a> {
    packets: &'a [PacketSummary],
    selected: Option<usize>,
    theme: &'a Theme,
    focused: bool,
    columns: &'a ColumnConfig,
    timestamp_format: TimestampFormat,
    first_absolute_ts: Option<f64>,
}

impl<'a> PacketTable<'a> {
    pub fn new(
        packets: &'a [PacketSummary],
        selected: Option<usize>,
        theme: &'a Theme,
        focused: bool,
        columns: &'a ColumnConfig,
        timestamp_format: TimestampFormat,
        first_absolute_ts: Option<f64>,
    ) -> Self {
        Self {
            packets,
            selected,
            theme,
            focused,
            columns,
            timestamp_format,
            first_absolute_ts,
        }
    }

    fn format_timestamp(&self, pkt: &PacketSummary) -> String {
        match self.timestamp_format {
            TimestampFormat::Relative => format!("{:.6}", pkt.timestamp),
            TimestampFormat::Epoch => {
                if let Some(base) = self.first_absolute_ts {
                    format!("{:.6}", base + pkt.timestamp)
                } else {
                    format!("{:.6}", pkt.timestamp)
                }
            }
            TimestampFormat::Absolute => {
                if let Some(base) = self.first_absolute_ts {
                    let abs = base + pkt.timestamp;
                    let secs = abs.floor() as u64;
                    let frac = abs - secs as f64;
                    // Guard against negative frac from floating point precision
                    let micros = ((frac * 1_000_000.0).round() as i64).clamp(0, 999_999) as u64;
                    let days = secs / 86400;
                    let day_secs = secs % 86400;
                    let hours = day_secs / 3600;
                    let minutes = (day_secs % 3600) / 60;
                    let seconds_part = day_secs % 60;
                    let (year, month, day) = crate::export::epoch_days_to_date(days);
                    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{seconds_part:02}.{micros:06}")
                } else {
                    format!("{:.6}", pkt.timestamp)
                }
            }
        }
    }

    fn cell_value(&self, col: &Column, pkt: &PacketSummary) -> String {
        match col {
            Column::No => (pkt.index + 1).to_string(),
            Column::Time => self.format_timestamp(pkt),
            Column::Source => pkt.source.clone(),
            Column::Destination => pkt.destination.clone(),
            Column::Protocol => pkt.protocol.to_string(),
            Column::Length => pkt.length.to_string(),
            Column::Info => pkt.info.clone(),
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

        let headers: Vec<&str> = self.columns.visible.iter().map(|c| c.header()).collect();
        let header = Row::new(headers).style(
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

                let cells: Vec<String> = self
                    .columns
                    .visible
                    .iter()
                    .map(|col| self.cell_value(col, pkt))
                    .collect();

                Row::new(cells).style(style)
            })
            .collect();

        let widths: Vec<Constraint> = self
            .columns
            .visible
            .iter()
            .map(|col| {
                let w = self.columns.width(col);
                if w == 0 {
                    Constraint::Min(20)
                } else {
                    Constraint::Length(w)
                }
            })
            .collect();

        let table = Table::new(rows, widths).header(header).block(block);

        table.render(area, buf);
    }
}

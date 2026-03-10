/// Statistics dialog: modal overlay with tabbed views for protocol hierarchy,
/// conversations, endpoints, and I/O graph.

use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Sparkline, Widget},
};

use crate::stats::conversations::{ConvSortColumn, ConversationStats};
use crate::stats::endpoints::{EndpointSortColumn, EndpointStats};
use crate::stats::io_graph::IoGraphData;
use crate::stats::model::StatsTab;
use crate::stats::protocol::ProtocolHierarchy;
use crate::ui::theme::Theme;

pub struct StatsDialog<'a> {
    tab: StatsTab,
    protocol_hierarchy: Option<&'a ProtocolHierarchy>,
    proto_rows: &'a [(usize, String, usize, u64, f64, f64)],
    proto_selected: usize,
    conversations: &'a [ConversationStats],
    conv_selected: usize,
    conv_scroll: usize,
    conv_sort: ConvSortColumn,
    conv_ascending: bool,
    endpoints: &'a [EndpointStats],
    ep_selected: usize,
    ep_scroll: usize,
    ep_sort: EndpointSortColumn,
    ep_ascending: bool,
    io_graph: Option<&'a IoGraphData>,
    io_show_bytes: bool,
    filter_aware: bool,
    theme: &'a Theme,
}

impl<'a> StatsDialog<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tab: StatsTab,
        protocol_hierarchy: Option<&'a ProtocolHierarchy>,
        proto_rows: &'a [(usize, String, usize, u64, f64, f64)],
        proto_selected: usize,
        conversations: &'a [ConversationStats],
        conv_selected: usize,
        conv_scroll: usize,
        conv_sort: ConvSortColumn,
        conv_ascending: bool,
        endpoints: &'a [EndpointStats],
        ep_selected: usize,
        ep_scroll: usize,
        ep_sort: EndpointSortColumn,
        ep_ascending: bool,
        io_graph: Option<&'a IoGraphData>,
        io_show_bytes: bool,
        filter_aware: bool,
        theme: &'a Theme,
    ) -> Self {
        Self {
            tab,
            protocol_hierarchy,
            proto_rows,
            proto_selected,
            conversations,
            conv_selected,
            conv_scroll,
            conv_sort,
            conv_ascending,
            endpoints,
            ep_selected,
            ep_scroll,
            ep_sort,
            ep_ascending,
            io_graph,
            io_show_bytes,
            filter_aware,
            theme,
        }
    }
}

impl Widget for StatsDialog<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Dialog sizing: 90% width, 80% height, centered
        let dialog_w = (area.width as u32 * 90 / 100).min(area.width as u32) as u16;
        let dialog_h = (area.height as u32 * 80 / 100).min(area.height as u32) as u16;
        let dialog_x = area.x + (area.width.saturating_sub(dialog_w)) / 2;
        let dialog_y = area.y + (area.height.saturating_sub(dialog_h)) / 2;
        let dialog_area = Rect::new(dialog_x, dialog_y, dialog_w, dialog_h);

        // Clear background
        Clear.render(dialog_area, buf);

        // Outer block
        let block = Block::default()
            .title(" Statistics ")
            .borders(Borders::ALL)
            .style(Style::default().fg(self.theme.text).bg(self.theme.base))
            .border_style(Style::default().fg(self.theme.blue));
        let inner = block.inner(dialog_area);
        block.render(dialog_area, buf);

        if inner.height < 4 {
            return;
        }

        // Layout: tab bar (1) + content (fill) + help (1)
        let chunks = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(inner);

        // Tab bar
        render_tab_bar(chunks[0], buf, self.tab, self.theme);

        // Content area
        match self.tab {
            StatsTab::ProtocolHierarchy => {
                render_protocol_hierarchy(
                    chunks[1],
                    buf,
                    self.protocol_hierarchy,
                    self.proto_rows,
                    self.proto_selected,
                    self.theme,
                );
            }
            StatsTab::Conversations => {
                render_conversations(
                    chunks[1],
                    buf,
                    self.conversations,
                    self.conv_selected,
                    self.conv_scroll,
                    self.conv_sort,
                    self.conv_ascending,
                    self.theme,
                );
            }
            StatsTab::Endpoints => {
                render_endpoints(
                    chunks[1],
                    buf,
                    self.endpoints,
                    self.ep_selected,
                    self.ep_scroll,
                    self.ep_sort,
                    self.ep_ascending,
                    self.theme,
                );
            }
            StatsTab::IoGraph => {
                render_io_graph(chunks[1], buf, self.io_graph, self.io_show_bytes, self.theme);
            }
        }

        // Help line
        let filter_label = if self.filter_aware { "filtered" } else { "all" };
        let help = match self.tab {
            StatsTab::ProtocolHierarchy => {
                format!(
                    " Tab:switch  j/k:navigate  Enter:expand/collapse  a:{filter_label}  Esc:close"
                )
            }
            StatsTab::Conversations | StatsTab::Endpoints => {
                format!(
                    " Tab:switch  j/k:navigate  s:sort  r:reverse  g/G:top/bottom  a:{filter_label}  Esc:close"
                )
            }
            StatsTab::IoGraph => {
                format!(
                    " Tab:switch  b:packets/bytes  +/-:granularity  a:{filter_label}  Esc:close"
                )
            }
        };
        let help_line = Paragraph::new(help)
            .style(Style::default().fg(self.theme.subtext0).bg(self.theme.mantle));
        help_line.render(chunks[2], buf);
    }
}

fn render_tab_bar(area: Rect, buf: &mut Buffer, active: StatsTab, theme: &Theme) {
    let mut spans = Vec::new();
    for &tab in StatsTab::ALL {
        let label = format!(" {} ", tab.label());
        let style = if tab == active {
            Style::default()
                .fg(theme.base)
                .bg(theme.blue)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.subtext0).bg(theme.surface0)
        };
        spans.push(Span::styled(label, style));
        spans.push(Span::raw(" "));
    }
    let line = Line::from(spans);
    Paragraph::new(line)
        .style(Style::default().bg(theme.base))
        .render(area, buf);
}

fn render_protocol_hierarchy(
    area: Rect,
    buf: &mut Buffer,
    hierarchy: Option<&ProtocolHierarchy>,
    rows: &[(usize, String, usize, u64, f64, f64)],
    selected: usize,
    theme: &Theme,
) {
    if rows.is_empty() {
        let msg = Paragraph::new(" No data")
            .style(Style::default().fg(theme.subtext0).bg(theme.base));
        msg.render(area, buf);
        return;
    }

    let _hierarchy = hierarchy; // used for total counts display

    // Header
    if area.height < 2 {
        return;
    }
    let header = format!(
        " {:<30} {:>10} {:>12} {:>8} {:>8}",
        "Protocol", "Packets", "Bytes", "% Pkts", "% Bytes"
    );
    let header_style = Style::default()
        .fg(theme.text)
        .bg(theme.surface0)
        .add_modifier(Modifier::BOLD);
    buf.set_string(area.x, area.y, &header, header_style);
    // Fill rest of header line
    let remaining = area.width as usize - header.len().min(area.width as usize);
    if remaining > 0 {
        buf.set_string(
            area.x + header.len().min(area.width as usize) as u16,
            area.y,
            &" ".repeat(remaining),
            header_style,
        );
    }

    // Data rows
    let content_area = Rect::new(area.x, area.y + 1, area.width, area.height - 1);
    let visible = content_area.height as usize;

    // Scroll to keep selection visible
    let scroll_offset = if selected >= visible {
        selected - visible + 1
    } else {
        0
    };

    for (i, row) in rows.iter().enumerate().skip(scroll_offset).take(visible) {
        let y = content_area.y + (i - scroll_offset) as u16;
        let (depth, name, packets, bytes, pct_pkts, pct_bytes) = row;

        let indent = "  ".repeat(*depth);
        let arrow = if *depth > 0 { "└ " } else { "" };
        let line = format!(
            " {}{}{:<width$} {:>10} {:>12} {:>7.1}% {:>7.1}%",
            indent,
            arrow,
            name,
            packets,
            format_bytes(*bytes),
            pct_pkts,
            pct_bytes,
            width = 30usize.saturating_sub(indent.len() + arrow.len()),
        );

        let style = if i == selected {
            Style::default()
                .fg(theme.base)
                .bg(theme.blue)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.text).bg(theme.base)
        };

        buf.set_string(area.x, y, &line, style);
        // Fill remaining width
        let line_len = line.len().min(area.width as usize);
        let remaining = area.width as usize - line_len;
        if remaining > 0 {
            buf.set_string(
                area.x + line_len as u16,
                y,
                &" ".repeat(remaining),
                style,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn render_conversations(
    area: Rect,
    buf: &mut Buffer,
    conversations: &[ConversationStats],
    selected: usize,
    scroll: usize,
    sort_col: ConvSortColumn,
    ascending: bool,
    theme: &Theme,
) {
    if conversations.is_empty() {
        let msg = Paragraph::new(" No data")
            .style(Style::default().fg(theme.subtext0).bg(theme.base));
        msg.render(area, buf);
        return;
    }

    if area.height < 2 {
        return;
    }

    // Header
    let sort_indicator = |col: ConvSortColumn| -> &str {
        if col == sort_col {
            if ascending { " ▲" } else { " ▼" }
        } else {
            ""
        }
    };

    let header = format!(
        " {:<18} {:>6} {:<18} {:>6} {:>5} {:>8}{} {:>8}{} {:>10}{} {:>10}",
        "Address A",
        "Port A",
        "Address B",
        "Port B",
        "Proto",
        "Pkts A→B",
        sort_indicator(ConvSortColumn::PacketsAtoB),
        "Pkts B→A",
        sort_indicator(ConvSortColumn::PacketsBtoA),
        "Total Pkts",
        sort_indicator(ConvSortColumn::TotalPackets),
        "Duration",
    );
    let header_style = Style::default()
        .fg(theme.text)
        .bg(theme.surface0)
        .add_modifier(Modifier::BOLD);
    buf.set_string(area.x, area.y, &header, header_style);
    let remaining = (area.width as usize).saturating_sub(header.len());
    if remaining > 0 {
        buf.set_string(
            area.x + header.len().min(area.width as usize) as u16,
            area.y,
            &" ".repeat(remaining),
            header_style,
        );
    }

    // Data rows
    let content_area = Rect::new(area.x, area.y + 1, area.width, area.height - 1);
    let visible = content_area.height as usize;

    for (i, conv) in conversations.iter().enumerate().skip(scroll).take(visible) {
        let y = content_area.y + (i - scroll) as u16;
        let port_a = conv.port_a.map(|p| p.to_string()).unwrap_or_default();
        let port_b = conv.port_b.map(|p| p.to_string()).unwrap_or_default();
        let duration = if conv.duration() > 0.0 {
            format!("{:.1}s", conv.duration())
        } else {
            "0s".into()
        };

        let line = format!(
            " {:<18} {:>6} {:<18} {:>6} {:>5} {:>10} {:>10} {:>10} {:>10}",
            truncate(&conv.addr_a, 18),
            port_a,
            truncate(&conv.addr_b, 18),
            port_b,
            truncate(&conv.protocol, 5),
            conv.packets_a_to_b,
            conv.packets_b_to_a,
            conv.total_packets(),
            duration,
        );

        let style = if i == selected {
            Style::default()
                .fg(theme.base)
                .bg(theme.blue)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.text).bg(theme.base)
        };

        buf.set_string(area.x, y, &line, style);
        let line_len = line.len().min(area.width as usize);
        let remaining = (area.width as usize).saturating_sub(line_len);
        if remaining > 0 {
            buf.set_string(area.x + line_len as u16, y, &" ".repeat(remaining), style);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn render_endpoints(
    area: Rect,
    buf: &mut Buffer,
    endpoints: &[EndpointStats],
    selected: usize,
    scroll: usize,
    sort_col: EndpointSortColumn,
    ascending: bool,
    theme: &Theme,
) {
    if endpoints.is_empty() {
        let msg = Paragraph::new(" No data")
            .style(Style::default().fg(theme.subtext0).bg(theme.base));
        msg.render(area, buf);
        return;
    }

    if area.height < 2 {
        return;
    }

    let sort_indicator = |col: EndpointSortColumn| -> &str {
        if col == sort_col {
            if ascending { " ▲" } else { " ▼" }
        } else {
            ""
        }
    };

    let header = format!(
        " {:<22} {:>10}{} {:>10}{} {:>12}{} {:>12}{} {:>12} {:>12}",
        "Address",
        "Tx Pkts",
        sort_indicator(EndpointSortColumn::TxPackets),
        "Rx Pkts",
        sort_indicator(EndpointSortColumn::RxPackets),
        "Tx Bytes",
        sort_indicator(EndpointSortColumn::TxBytes),
        "Rx Bytes",
        sort_indicator(EndpointSortColumn::RxBytes),
        "First Seen",
        "Last Seen",
    );
    let header_style = Style::default()
        .fg(theme.text)
        .bg(theme.surface0)
        .add_modifier(Modifier::BOLD);
    buf.set_string(area.x, area.y, &header, header_style);
    let remaining = (area.width as usize).saturating_sub(header.len());
    if remaining > 0 {
        buf.set_string(
            area.x + header.len().min(area.width as usize) as u16,
            area.y,
            &" ".repeat(remaining),
            header_style,
        );
    }

    let content_area = Rect::new(area.x, area.y + 1, area.width, area.height - 1);
    let visible = content_area.height as usize;

    for (i, ep) in endpoints.iter().enumerate().skip(scroll).take(visible) {
        let y = content_area.y + (i - scroll) as u16;
        let line = format!(
            " {:<22} {:>10} {:>10} {:>12} {:>12} {:>12.6} {:>12.6}",
            truncate(&ep.address, 22),
            ep.tx_packets,
            ep.rx_packets,
            format_bytes(ep.tx_bytes),
            format_bytes(ep.rx_bytes),
            ep.first_seen,
            ep.last_seen,
        );

        let style = if i == selected {
            Style::default()
                .fg(theme.base)
                .bg(theme.blue)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.text).bg(theme.base)
        };

        buf.set_string(area.x, y, &line, style);
        let line_len = line.len().min(area.width as usize);
        let remaining = (area.width as usize).saturating_sub(line_len);
        if remaining > 0 {
            buf.set_string(area.x + line_len as u16, y, &" ".repeat(remaining), style);
        }
    }
}

fn render_io_graph(
    area: Rect,
    buf: &mut Buffer,
    io_graph: Option<&IoGraphData>,
    show_bytes: bool,
    theme: &Theme,
) {
    let Some(data) = io_graph else {
        let msg = Paragraph::new(" No data")
            .style(Style::default().fg(theme.subtext0).bg(theme.base));
        msg.render(area, buf);
        return;
    };

    if area.height < 4 {
        return;
    }

    // Layout: title (1) + sparkline (fill) + time axis (1)
    let chunks = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .split(area);

    // Title with stats
    let (label, max_val, buckets) = if show_bytes {
        ("Bytes per interval", data.max_bytes, &data.buckets_bytes)
    } else {
        ("Packets per interval", data.max_packets, &data.buckets_packets)
    };

    let duration = data.end_time - data.start_time;
    let title = format!(
        " {} ({:.1}s buckets, {:.1}s total) — Max: {}",
        label,
        data.bucket_width_secs,
        duration,
        if show_bytes {
            format_bytes(max_val)
        } else {
            max_val.to_string()
        },
    );
    let title_widget = Paragraph::new(title)
        .style(Style::default().fg(theme.text).bg(theme.base));
    title_widget.render(chunks[0], buf);

    // Sparkline
    let sparkline = Sparkline::default()
        .data(buckets)
        .style(Style::default().fg(theme.green).bg(theme.base));
    sparkline.render(chunks[1], buf);

    // Time axis
    let start_label = format!("{:.1}s", 0.0);
    let end_label = format!("{:.1}s", duration);
    let axis = format!(
        " {:<width$}{}",
        start_label,
        end_label,
        width = (area.width as usize).saturating_sub(end_label.len() + 2),
    );
    let axis_widget = Paragraph::new(axis)
        .style(Style::default().fg(theme.subtext0).bg(theme.base));
    axis_widget.render(chunks[2], buf);
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

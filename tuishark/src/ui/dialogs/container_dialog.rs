use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Widget},
};

use crate::trace::model::{ContainerInfo, INIT_NETNS_INUM};
use crate::ui::theme::Theme;

pub struct ContainerDialog<'a> {
    info: Option<&'a ContainerInfo>,
    protocol: u8,
    theme: &'a Theme,
    trace_active: bool,
    path_trace_active: bool,
}

impl<'a> ContainerDialog<'a> {
    pub fn new(
        info: Option<&'a ContainerInfo>,
        protocol: u8,
        trace_active: bool,
        path_trace_active: bool,
        theme: &'a Theme,
    ) -> Self {
        Self { info, protocol, trace_active, path_trace_active, theme }
    }
}

impl Widget for ContainerDialog<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let dialog_w = 56u16.min(area.width.saturating_sub(4));
        let dialog_h = 12u16.min(area.height.saturating_sub(4));
        let x = area.x + (area.width.saturating_sub(dialog_w)) / 2;
        let y = area.y + (area.height.saturating_sub(dialog_h)) / 2;
        let dialog_area = Rect::new(x, y, dialog_w, dialog_h);

        Clear.render(dialog_area, buf);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.mauve))
            .title(" Container Context ")
            .title_style(
                Style::default()
                    .fg(self.theme.mauve)
                    .add_modifier(Modifier::BOLD),
            )
            .style(Style::default().bg(self.theme.base));

        let inner = block.inner(dialog_area);
        block.render(dialog_area, buf);

        if inner.height < 3 || inner.width < 10 {
            return;
        }

        if !self.trace_active {
            let msg = "Kernel tracing disabled (use --trace)";
            let msg_x = inner.x + (inner.width.saturating_sub(msg.len() as u16)) / 2;
            let msg_y = inner.y + inner.height / 2;
            buf.set_line(msg_x, msg_y, &Line::from(Span::styled(
                msg, Style::default().fg(self.theme.surface2),
            )), inner.width);
            render_help_line(inner, buf, self.theme);
            return;
        }

        let Some(info) = self.info else {
            let msg = if !self.path_trace_active {
                "Enable path tracing (Shift+P) for container context"
            } else {
                "No container context for this packet"
            };
            let msg_x = inner.x + (inner.width.saturating_sub(msg.len() as u16)) / 2;
            let msg_y = inner.y + inner.height / 2;
            buf.set_line(msg_x, msg_y, &Line::from(Span::styled(
                msg, Style::default().fg(self.theme.surface2),
            )), inner.width);
            render_help_line(inner, buf, self.theme);
            return;
        };

        let label_style = Style::default()
            .fg(self.theme.mauve)
            .add_modifier(Modifier::BOLD);
        let value_style = Style::default().fg(self.theme.text);

        let pad = 1u16;
        let cx = inner.x + pad;
        let cw = inner.width.saturating_sub(pad * 2);
        let mut row = inner.y;
        let max_row = inner.y + inner.height.saturating_sub(1); // reserve for help line

        // Network Namespace
        if row < max_row {
            let netns_str = if info.netns_inum == INIT_NETNS_INUM {
                format!("{} (default)", info.netns_inum)
            } else {
                info.netns_inum.to_string()
            };
            render_field(cx, row, cw, "  Net NS", &netns_str, label_style, value_style, buf);
            row += 1;
        }

        // Blank separator
        row += 1;

        // Network Device
        if row < max_row {
            let dev_str = format!("{} (#{})", info.dev_name_str(), info.ifindex);
            render_field(cx, row, cw, "  Device", &dev_str, label_style, value_style, buf);
            row += 1;
        }

        // Blank separator
        row += 1;

        // TCP State
        if row < max_row {
            if self.protocol == 6 {
                let state_str = info.tcp_state_str();
                let state_style = tcp_state_style(info.tcp_state, self.theme);
                let line = Line::from(vec![
                    Span::styled("TCP State: ", label_style),
                    Span::styled(state_str, state_style),
                ]);
                buf.set_line(cx, row, &line, cw);
            } else {
                render_field(cx, row, cw, "TCP State", "N/A (UDP)", label_style,
                    Style::default().fg(self.theme.surface2), buf);
            }
            row += 1;
        }

        // Blank separator
        row += 1;

        // cgroup ID (only meaningful on TX path; 0 = not available)
        if row < max_row {
            let cgroup_str = if info.cgroup_id == 0 {
                "N/A (RX path)".to_string()
            } else {
                info.cgroup_id.to_string()
            };
            render_field(cx, row, cw, "  cgroup", &cgroup_str, label_style, value_style, buf);
        }

        render_help_line(inner, buf, self.theme);
    }
}

fn render_field(
    x: u16, y: u16, width: u16,
    label: &str, value: &str,
    label_style: Style, value_style: Style,
    buf: &mut Buffer,
) {
    let line = Line::from(vec![
        Span::styled(format!("{}:", label), label_style),
        Span::styled(format!(" {value}"), value_style),
    ]);
    buf.set_line(x, y, &line, width);
}

/// Map TCP state to a themed style. Shared by container_dialog and trace_view.
pub fn tcp_state_style(state: u8, theme: &Theme) -> Style {
    match state {
        1 => Style::default().fg(theme.green).add_modifier(Modifier::BOLD),   // ESTABLISHED
        2 | 3 => Style::default().fg(theme.yellow),                             // SYN_SENT, SYN_RECV
        4 | 5 | 9 | 11 => Style::default().fg(theme.peach),                    // FIN_WAIT*, LAST_ACK, CLOSING
        6 => Style::default().fg(theme.surface2),                               // TIME_WAIT
        7 => Style::default().fg(theme.red),                                    // CLOSE
        8 => Style::default().fg(theme.peach),                                  // CLOSE_WAIT
        10 => Style::default().fg(theme.blue).add_modifier(Modifier::BOLD),    // LISTEN
        _ => Style::default().fg(theme.text),
    }
}

fn render_help_line(inner: Rect, buf: &mut Buffer, theme: &Theme) {
    let bottom_y = inner.y + inner.height - 1;
    let key_style = Style::default()
        .fg(theme.green)
        .add_modifier(Modifier::BOLD);
    let dim_style = Style::default().fg(theme.surface2);

    let help = Line::from(vec![
        Span::styled(" ", dim_style),
        Span::styled("prev/next", key_style),
        Span::styled(":navigate  ", dim_style),
        Span::styled("Esc", key_style),
        Span::styled(":close", dim_style),
    ]);
    buf.set_line(inner.x, bottom_y, &help, inner.width);
}

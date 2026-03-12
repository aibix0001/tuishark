use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Widget},
};

use crate::ipinfo::lookup::IpInfo;
use crate::ui::theme::Theme;

pub struct IpInfoDialog<'a> {
    src: Option<&'a IpInfo>,
    dst: Option<&'a IpInfo>,
    theme: &'a Theme,
}

impl<'a> IpInfoDialog<'a> {
    pub fn new(
        src: Option<&'a IpInfo>,
        dst: Option<&'a IpInfo>,
        theme: &'a Theme,
    ) -> Self {
        Self { src, dst, theme }
    }
}

impl Widget for IpInfoDialog<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let dialog_w = 72u16.min(area.width.saturating_sub(4));
        let dialog_h = 14u16.min(area.height.saturating_sub(4));
        let x = area.x + (area.width.saturating_sub(dialog_w)) / 2;
        let y = area.y + (area.height.saturating_sub(dialog_h)) / 2;
        let dialog_area = Rect::new(x, y, dialog_w, dialog_h);

        Clear.render(dialog_area, buf);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.blue))
            .title(" IP Address Info ")
            .title_style(
                Style::default()
                    .fg(self.theme.blue)
                    .add_modifier(Modifier::BOLD),
            )
            .style(Style::default().bg(self.theme.base));

        let inner = block.inner(dialog_area);
        block.render(dialog_area, buf);

        if inner.height < 3 || inner.width < 10 {
            return;
        }

        // No IP info at all — show centered message
        if self.src.is_none() && self.dst.is_none() {
            let msg = "No IP addresses in this packet";
            let msg_x = inner.x + (inner.width.saturating_sub(msg.len() as u16)) / 2;
            let msg_y = inner.y + inner.height / 2;
            let line = Line::from(Span::styled(
                msg,
                Style::default().fg(self.theme.surface2),
            ));
            buf.set_line(msg_x, msg_y, &line, inner.width);

            render_help_line(inner, buf, self.theme);
            return;
        }

        let label_style = Style::default()
            .fg(self.theme.mauve)
            .add_modifier(Modifier::BOLD);
        let value_style = Style::default().fg(self.theme.text);
        let header_style = Style::default()
            .fg(self.theme.blue)
            .add_modifier(Modifier::BOLD);

        // Two-column layout: split inner area in half
        let col_w = (inner.width.saturating_sub(1)) / 2;
        let left_x = inner.x;
        let right_x = inner.x + col_w + 1;

        // Draw vertical separator
        for row in inner.y..inner.y + inner.height.saturating_sub(1) {
            buf.set_string(
                inner.x + col_w,
                row,
                "│",
                Style::default().fg(self.theme.surface2),
            );
        }

        if let Some(src) = self.src {
            render_column(left_x, inner.y, col_w, inner.height, src, "Source", header_style, label_style, value_style, buf);
        }

        if let Some(dst) = self.dst {
            render_column(right_x, inner.y, col_w.min(inner.width.saturating_sub(col_w + 1)), inner.height, dst, "Destination", header_style, label_style, value_style, buf);
        }

        render_help_line(inner, buf, self.theme);
    }
}

/// Truncate a string to at most `max_chars` characters (UTF-8 safe).
fn truncate_chars(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((byte_idx, _)) => &s[..byte_idx],
        None => s,
    }
}

/// Split a string at a character boundary, returning (first, rest).
fn split_at_char(s: &str, char_pos: usize) -> (&str, &str) {
    match s.char_indices().nth(char_pos) {
        Some((byte_idx, _)) => (&s[..byte_idx], &s[byte_idx..]),
        None => (s, ""),
    }
}

fn render_column(
    x: u16,
    y: u16,
    width: u16,
    height: u16,
    info: &IpInfo,
    title: &str,
    header_style: Style,
    label_style: Style,
    value_style: Style,
    buf: &mut Buffer,
) {
    let pad = 1u16;
    let cx = x + pad;
    let cw = width.saturating_sub(pad * 2);
    let max_row = y + height.saturating_sub(2); // reserve bottom for help line

    // Column header
    let header_text = format!("── {} ", title);
    let hpad = (cw as usize).saturating_sub(header_text.len());
    let header = format!("{}{}", header_text, "─".repeat(hpad));
    buf.set_line(cx, y, &Line::from(Span::styled(header, header_style)), cw);

    let fields: [(&str, &str); 5] = [
        ("Address", &info.address),
        ("    ASN", &info.asn),
        ("AS Name", &info.as_name),
        ("Country", &info.country),
        ("    RIR", &info.rir),
    ];

    let mut row = y + 1;
    for (label, value) in &fields {
        if row >= max_row {
            break;
        }

        let label_len = label.len() + 2; // "label: "
        let value_max = (cw as usize).saturating_sub(label_len);
        let value_chars: usize = value.chars().count();

        if value_chars > value_max && value_max > 0 {
            // First line with label
            let (first, mut rest) = split_at_char(value, value_max);
            let line = Line::from(vec![
                Span::styled(format!("{}:", label), label_style),
                Span::styled(format!(" {first}"), value_style),
            ]);
            buf.set_line(cx, row, &line, cw);
            row += 1;

            // Continuation lines
            while !rest.is_empty() && row < max_row {
                let (chunk, remainder) = split_at_char(rest, value_max);
                let indent = " ".repeat(label_len);
                let line = Line::from(Span::styled(format!("{indent}{chunk}"), value_style));
                buf.set_line(cx, row, &line, cw);
                row += 1;
                rest = remainder;
            }
        } else {
            let display_value = if value.is_empty() { " " } else { value };
            let line = Line::from(vec![
                Span::styled(format!("{}:", label), label_style),
                Span::styled(format!(" {display_value}"), value_style),
            ]);
            buf.set_line(cx, row, &line, cw);
            row += 1;
        }
    }

    // Show error note if present
    if let Some(ref err) = info.error {
        if row < max_row {
            let err_style = Style::default().fg(ratatui::style::Color::Red);
            let truncated = truncate_chars(err, cw as usize);
            buf.set_line(cx, row, &Line::from(Span::styled(truncated, err_style)), cw);
        }
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
        Span::styled("ö", key_style),
        Span::styled(":prev  ", dim_style),
        Span::styled("ä", key_style),
        Span::styled(":next  ", dim_style),
        Span::styled("Esc", key_style),
        Span::styled(":close", dim_style),
    ]);
    buf.set_line(inner.x, bottom_y, &help, inner.width);
}

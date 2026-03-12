use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Widget},
};

use crate::config::keys::KeyConfig;
use crate::ui::theme::Theme;

pub struct HelpDialog<'a> {
    keys: &'a KeyConfig,
    scroll: usize,
    theme: &'a Theme,
}

impl<'a> HelpDialog<'a> {
    pub fn new(keys: &'a KeyConfig, scroll: usize, theme: &'a Theme) -> Self {
        Self { keys, scroll, theme }
    }
}

/// A section header + key/description pairs for the help screen.
struct HelpSection<'a> {
    title: &'static str,
    entries: Vec<(&'static str, &'a str)>,
}

fn build_sections(keys: &KeyConfig) -> Vec<HelpSection<'_>> {
    vec![
        HelpSection {
            title: "General",
            entries: vec![
                ("Quit", &keys.quit),
                ("Force quit", &keys.force_quit),
                ("Help", &keys.help),
                ("Filter", &keys.filter),
                ("Filter presets", &keys.filter_presets),
                ("Statistics", &keys.stats),
                ("Interface picker", &keys.interface_picker),
                ("Stop capture", &keys.stop_capture),
                ("Auto-scroll", &keys.toggle_auto_scroll),
            ],
        },
        HelpSection {
            title: "File",
            entries: vec![
                ("Save", &keys.save),
                ("Quick save", &keys.quick_save),
                ("Open", &keys.open),
                ("Export", &keys.export),
            ],
        },
        HelpSection {
            title: "Panes",
            entries: vec![
                ("Next pane", &keys.next_pane),
                ("Prev pane", &keys.prev_pane),
                ("Packet table", &keys.focus_packet_table),
                ("Detail tree", &keys.focus_detail_tree),
                ("Hex view", &keys.focus_hex_view),
                ("Kernel trace", &keys.focus_kernel_trace),
                ("Zoom / unzoom", &keys.zoom_pane),
            ],
        },
        HelpSection {
            title: "eBPF Tracing",
            entries: vec![
                ("Toggle path trace", &keys.toggle_path_trace),
            ],
        },
    ]
}

/// Navigation entries need owned strings (format!), built separately.
fn build_nav_lines<'a>(keys: &KeyConfig, key_style: Style, desc_style: Style) -> Vec<Line<'a>> {
    let nav = [
        ("Move down", format!("{} / Down", keys.move_down)),
        ("Move up", format!("{} / Up", keys.move_up)),
        ("First", format!("{} / Home", keys.move_first)),
        ("Last", format!("{} / End", keys.move_last)),
        ("Page down", keys.page_down.clone()),
        ("Page up", keys.page_up.clone()),
        ("Expand/collapse", keys.toggle_expand.clone()),
        ("Next packet (global)", keys.next_packet.clone()),
        ("Prev packet (global)", keys.prev_packet.clone()),
    ];
    nav.into_iter().map(|(desc, key)| {
        Line::from(vec![
            Span::styled(format!(" {:>16}  ", key), key_style),
            Span::styled(desc.to_string(), desc_style),
        ])
    }).collect()
}

/// Total number of content lines (section headers + entries + blank separators + nav section).
pub fn help_content_lines(keys: &KeyConfig) -> usize {
    let sections = build_sections(keys);
    let mut lines = 0;
    for (i, section) in sections.iter().enumerate() {
        if i > 0 {
            lines += 1; // blank separator
        }
        lines += 1; // section header
        lines += section.entries.len();
    }
    // Navigation section: separator + header + 9 entries
    lines += 1 + 1 + 9;
    lines
}

impl Widget for HelpDialog<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Dialog sizing: 60 wide, 70% height, centered
        let dialog_w = 60u16.min(area.width.saturating_sub(4));
        let dialog_h = ((area.height as u32 * 70 / 100) as u16).max(10);
        let x = area.x + (area.width.saturating_sub(dialog_w)) / 2;
        let y = area.y + (area.height.saturating_sub(dialog_h)) / 2;
        let dialog_area = Rect::new(x, y, dialog_w, dialog_h);

        Clear.render(dialog_area, buf);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.blue))
            .title(" Help ")
            .title_style(
                Style::default()
                    .fg(self.theme.blue)
                    .add_modifier(Modifier::BOLD),
            )
            .style(Style::default().bg(self.theme.base));

        let inner = block.inner(dialog_area);
        block.render(dialog_area, buf);

        if inner.height < 3 {
            return;
        }

        // Reserve last line for help hint
        let content_height = (inner.height - 1) as usize;

        // Build all content lines
        let key_style = Style::default().fg(self.theme.green).add_modifier(Modifier::BOLD);
        let desc_style = Style::default().fg(self.theme.text);
        let header_style = Style::default().fg(self.theme.mauve).add_modifier(Modifier::BOLD);
        let dim_style = Style::default().fg(self.theme.surface2);

        let sections = build_sections(self.keys);
        let mut lines: Vec<Line> = Vec::new();

        for (i, section) in sections.iter().enumerate() {
            if i > 0 {
                lines.push(Line::from(""));
            }
            // Section header with separator line
            let header_text = format!("── {} ", section.title);
            let pad = (inner.width as usize).saturating_sub(header_text.len());
            let padded = format!("{}{}", header_text, "─".repeat(pad));
            lines.push(Line::from(Span::styled(padded, header_style)));

            for &(desc, key) in &section.entries {
                let key_col = format!(" {:>16}  ", key);
                lines.push(Line::from(vec![
                    Span::styled(key_col, key_style),
                    Span::styled(desc, desc_style),
                ]));
            }
        }

        // Navigation section (needs owned strings for format! combos)
        lines.push(Line::from(""));
        let nav_header = format!("── Navigation ");
        let nav_pad = (inner.width as usize).saturating_sub(nav_header.len());
        lines.push(Line::from(Span::styled(
            format!("{}{}", nav_header, "─".repeat(nav_pad)),
            header_style,
        )));
        lines.extend(build_nav_lines(self.keys, key_style, desc_style));

        // Render visible lines with scroll
        for (i, line) in lines.iter().skip(self.scroll).take(content_height).enumerate() {
            buf.set_line(inner.x, inner.y + i as u16, line, inner.width);
        }

        // Bottom bar: help hint on left, scroll indicator on right
        let total = lines.len();
        let bottom_y = inner.y + inner.height - 1;

        // Render help hint first (left-aligned)
        let help = Line::from(vec![
            Span::styled(" ", dim_style),
            Span::styled("j/k", key_style),
            Span::styled(" scroll  ", dim_style),
            Span::styled("q/?/Esc", key_style),
            Span::styled(" close", dim_style),
        ]);
        buf.set_line(inner.x, bottom_y, &help, inner.width);

        // Render scroll indicator second (right-aligned, overwrites hint if needed)
        if total > content_height {
            let indicator = format!("[{}-{}/{}] ", self.scroll + 1, (self.scroll + content_height).min(total), total);
            let ind_line = Line::from(Span::styled(indicator, dim_style));
            let ind_x = inner.x + inner.width.saturating_sub(ind_line.width() as u16);
            buf.set_line(ind_x, bottom_y, &ind_line, inner.width);
        }
    }
}

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
struct HelpSection {
    title: &'static str,
    entries: Vec<(&'static str, String)>,
}

fn build_sections(keys: &KeyConfig) -> Vec<HelpSection> {
    vec![
        HelpSection {
            title: "General",
            entries: vec![
                ("Quit", keys.quit.clone()),
                ("Force quit", keys.force_quit.clone()),
                ("Help", "?".into()),
                ("Filter", keys.filter.clone()),
                ("Filter presets", keys.filter_presets.clone()),
                ("Statistics", keys.stats.clone()),
                ("Interface picker", keys.interface_picker.clone()),
                ("Stop capture", keys.stop_capture.clone()),
                ("Auto-scroll", keys.toggle_auto_scroll.clone()),
            ],
        },
        HelpSection {
            title: "File",
            entries: vec![
                ("Save", keys.save.clone()),
                ("Quick save", keys.quick_save.clone()),
                ("Open", keys.open.clone()),
                ("Export", keys.export.clone()),
            ],
        },
        HelpSection {
            title: "Navigation",
            entries: vec![
                ("Move down", format!("{} / Down", keys.move_down)),
                ("Move up", format!("{} / Up", keys.move_up)),
                ("First", format!("{} / Home", keys.move_first)),
                ("Last", format!("{} / End", keys.move_last)),
                ("Page down", keys.page_down.clone()),
                ("Page up", keys.page_up.clone()),
                ("Expand/collapse", keys.toggle_expand.clone()),
            ],
        },
        HelpSection {
            title: "Panes",
            entries: vec![
                ("Next pane", keys.next_pane.clone()),
                ("Prev pane", keys.prev_pane.clone()),
                ("Packet table", keys.focus_packet_table.clone()),
                ("Detail tree", keys.focus_detail_tree.clone()),
                ("Hex view", keys.focus_hex_view.clone()),
                ("Kernel trace", keys.focus_kernel_trace.clone()),
            ],
        },
        HelpSection {
            title: "eBPF Tracing",
            entries: vec![
                ("Toggle path trace", keys.toggle_path_trace.clone()),
            ],
        },
    ]
}

/// Total number of content lines (section headers + entries + blank separators).
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
    lines
}

impl Widget for HelpDialog<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Dialog sizing: 60 wide, 70% height, centered
        let dialog_w = 60u16.min(area.width.saturating_sub(4));
        let dialog_h = (area.height as u32 * 70 / 100).min(area.height as u32) as u16;
        let dialog_h = dialog_h.max(10);
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
        let sections = build_sections(self.keys);

        // Build all content lines
        let key_style = Style::default().fg(self.theme.green).add_modifier(Modifier::BOLD);
        let desc_style = Style::default().fg(self.theme.text);
        let header_style = Style::default().fg(self.theme.mauve).add_modifier(Modifier::BOLD);
        let dim_style = Style::default().fg(self.theme.surface2);

        let mut lines: Vec<Line> = Vec::new();
        for (i, section) in sections.iter().enumerate() {
            if i > 0 {
                lines.push(Line::from(""));
            }
            // Section header with separator
            let header_text = format!("── {} ", section.title);
            let pad = inner.width as usize - header_text.len().min(inner.width as usize);
            let padded = format!("{}{}", header_text, "─".repeat(pad));
            lines.push(Line::from(Span::styled(padded, header_style)));

            for (desc, key) in &section.entries {
                let key_col = format!(" {:>16}  ", key);
                lines.push(Line::from(vec![
                    Span::styled(key_col, key_style),
                    Span::styled(*desc, desc_style),
                ]));
            }
        }

        // Render visible lines with scroll
        for (i, line) in lines.iter().skip(self.scroll).take(content_height).enumerate() {
            buf.set_line(inner.x, inner.y + i as u16, line, inner.width);
        }

        // Scroll indicator
        let total = lines.len();
        if total > content_height {
            let indicator = format!(" [{}-{}/{}] ", self.scroll + 1, (self.scroll + content_height).min(total), total);
            let ind_line = Line::from(Span::styled(indicator, dim_style));
            let ind_x = inner.x + inner.width.saturating_sub(ind_line.width() as u16);
            buf.set_line(ind_x, inner.y + inner.height - 1, &ind_line, inner.width);
        }

        // Help hint at bottom-left
        let help = Line::from(vec![
            Span::styled(" ", dim_style),
            Span::styled("j/k", key_style),
            Span::styled(" scroll  ", dim_style),
            Span::styled("?/Esc", key_style),
            Span::styled(" close", dim_style),
        ]);
        buf.set_line(inner.x, inner.y + inner.height - 1, &help, inner.width);
    }
}

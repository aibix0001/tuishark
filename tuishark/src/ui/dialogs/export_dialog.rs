use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Widget},
};

use crate::export::{ExportFormat, ExportStep};
use crate::ui::theme::Theme;

pub struct ExportDialog<'a> {
    step: ExportStep,
    selected_format: usize,
    filename: &'a str,
    cursor_pos: usize,
    export_all: bool,
    total_packets: usize,
    filtered_packets: Option<usize>,
    theme: &'a Theme,
}

impl<'a> ExportDialog<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        step: ExportStep,
        selected_format: usize,
        filename: &'a str,
        cursor_pos: usize,
        export_all: bool,
        total_packets: usize,
        filtered_packets: Option<usize>,
        theme: &'a Theme,
    ) -> Self {
        Self {
            step,
            selected_format,
            filename,
            cursor_pos,
            export_all,
            total_packets,
            filtered_packets,
            theme,
        }
    }
}

impl Widget for ExportDialog<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let dialog_width = 60u16.min(area.width.saturating_sub(4));
        let dialog_height = match self.step {
            ExportStep::FormatSelect => 12u16,
            ExportStep::FilenameInput => 9u16,
        }
        .min(area.height.saturating_sub(4));

        let x = area.x + (area.width.saturating_sub(dialog_width)) / 2;
        let y = area.y + (area.height.saturating_sub(dialog_height)) / 2;
        let dialog_area = Rect::new(x, y, dialog_width, dialog_height);

        Clear.render(dialog_area, buf);

        let title = match self.step {
            ExportStep::FormatSelect => " Export — Select Format ",
            ExportStep::FilenameInput => " Export — Filename ",
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.mauve))
            .title(title)
            .title_style(
                Style::default()
                    .fg(self.theme.mauve)
                    .add_modifier(Modifier::BOLD),
            )
            .style(Style::default().bg(self.theme.mantle));

        let inner = block.inner(dialog_area);
        block.render(dialog_area, buf);

        if inner.height < 3 {
            return;
        }

        match self.step {
            ExportStep::FormatSelect => self.render_format_select(inner, buf),
            ExportStep::FilenameInput => self.render_filename_input(inner, buf),
        }
    }
}

impl ExportDialog<'_> {
    fn render_scope_line(&self, y: u16, inner: Rect, buf: &mut Buffer) {
        let scope_text = if let Some(filtered) = self.filtered_packets {
            if self.export_all {
                format!(" Exporting: all {0} packets", self.total_packets)
            } else {
                format!(" Exporting: {filtered} of {0} packets (filtered)", self.total_packets)
            }
        } else {
            format!(" Exporting: {} packets", self.total_packets)
        };
        let scope = Line::from(Span::styled(
            scope_text,
            Style::default().fg(self.theme.subtext0),
        ));
        buf.set_line(inner.x, y, &scope, inner.width);
    }

    fn render_format_select(&self, inner: Rect, buf: &mut Buffer) {
        // Scope line
        self.render_scope_line(inner.y, inner, buf);

        // Format list
        let list_y = inner.y + 2;
        for (i, format) in ExportFormat::ALL.iter().enumerate() {
            let is_selected = i == self.selected_format;
            let marker = if is_selected { "▸ " } else { "  " };
            let style = if is_selected {
                Style::default()
                    .fg(self.theme.mauve)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(self.theme.text)
            };

            let desc = match format {
                ExportFormat::Csv => "CSV  — Comma-separated values (.csv)",
                ExportFormat::Json => "JSON — Structured packet data  (.json)",
                ExportFormat::Text => "Text — Human-readable table    (.txt)",
            };

            let line = Line::from(vec![
                Span::styled(format!(" {marker}"), style),
                Span::styled(desc, style),
            ]);
            if list_y + i as u16 <= inner.y + inner.height.saturating_sub(3) {
                buf.set_line(inner.x, list_y + i as u16, &line, inner.width);
            }
        }

        // Toggle hint for filter-aware
        if self.filtered_packets.is_some() {
            let toggle_y = inner.y + inner.height.saturating_sub(2);
            let toggle = Line::from(Span::styled(
                if self.export_all {
                    " [a] Showing: all packets"
                } else {
                    " [a] Showing: filtered only"
                },
                Style::default().fg(self.theme.yellow),
            ));
            buf.set_line(inner.x, toggle_y, &toggle, inner.width);
        }

        // Help line
        let help_y = inner.y + inner.height.saturating_sub(1);
        let help = Line::from(Span::styled(
            " ↑↓:select  Enter:confirm  Esc:cancel",
            Style::default().fg(self.theme.subtext0),
        ));
        buf.set_line(inner.x, help_y, &help, inner.width);
    }

    fn render_filename_input(&self, inner: Rect, buf: &mut Buffer) {
        // Scope line
        self.render_scope_line(inner.y, inner, buf);

        // Format indicator
        let format = ExportFormat::ALL[self.selected_format];
        let format_line = Line::from(Span::styled(
            format!(" Format: {format}"),
            Style::default().fg(self.theme.subtext0),
        ));
        buf.set_line(inner.x, inner.y + 1, &format_line, inner.width);

        // Label
        let label = Line::from(Span::styled(
            " Filename:",
            Style::default().fg(self.theme.subtext0),
        ));
        buf.set_line(inner.x, inner.y + 3, &label, inner.width);

        // Text input field
        let input_y = inner.y + 4;
        let input_width = inner.width.saturating_sub(2) as usize;

        // Fill input background
        let input_style = Style::default()
            .fg(self.theme.text)
            .bg(self.theme.surface0);
        for col in (inner.x + 1)..(inner.x + inner.width.saturating_sub(1)) {
            buf[(col, input_y)].set_style(input_style);
        }

        // Render filename text (scroll if needed)
        let display_start = if self.cursor_pos > input_width.saturating_sub(1) {
            self.cursor_pos - input_width + 1
        } else {
            0
        };
        let visible: String = self
            .filename
            .chars()
            .skip(display_start)
            .take(input_width)
            .collect();
        let text = Line::from(Span::styled(visible, input_style));
        buf.set_line(inner.x + 1, input_y, &text, inner.width.saturating_sub(2));

        // Cursor
        let cursor_screen_pos = self.cursor_pos - display_start;
        let cursor_x = inner.x + 1 + cursor_screen_pos as u16;
        if cursor_x < inner.x + inner.width.saturating_sub(1) {
            let cursor_style = Style::default()
                .fg(self.theme.base)
                .bg(self.theme.text);
            buf[(cursor_x, input_y)].set_style(cursor_style);
        }

        // Help line
        let help_y = inner.y + inner.height.saturating_sub(1);
        let help = Line::from(Span::styled(
            " Enter:export  Esc:back",
            Style::default().fg(self.theme.subtext0),
        ));
        buf.set_line(inner.x, help_y, &help, inner.width);
    }
}

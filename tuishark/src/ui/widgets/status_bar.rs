use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Widget,
};

use crate::app::{CaptureState, DissectState};
use crate::ui::theme::Theme;

pub struct StatusBar<'a> {
    packet_count: usize,
    selected: Option<usize>,
    capture_state: CaptureState,
    dissect_state: DissectState,
    status_message: Option<&'a str>,
    theme: &'a Theme,
}

impl<'a> StatusBar<'a> {
    pub fn new(
        packet_count: usize,
        selected: Option<usize>,
        capture_state: CaptureState,
        dissect_state: DissectState,
        status_message: Option<&'a str>,
        theme: &'a Theme,
    ) -> Self {
        Self {
            packet_count,
            selected,
            capture_state,
            dissect_state,
            status_message,
            theme,
        }
    }
}

impl Widget for StatusBar<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let sel_text = match self.selected {
            Some(idx) => format!("Selected: {} ", idx + 1),
            None => String::new(),
        };

        let capture_span = match self.capture_state {
            CaptureState::Idle => Span::styled("", Style::default()),
            CaptureState::Capturing => Span::styled(
                " LIVE ",
                Style::default()
                    .fg(self.theme.base)
                    .bg(self.theme.green)
                    .add_modifier(Modifier::BOLD),
            ),
            CaptureState::Stopped => Span::styled(
                " STOPPED ",
                Style::default()
                    .fg(self.theme.base)
                    .bg(self.theme.red)
                    .add_modifier(Modifier::BOLD),
            ),
        };

        let dissect_span = match self.dissect_state {
            DissectState::Fast => Span::styled("", Style::default()),
            DissectState::DeepPending => Span::styled(
                " DISSECTING... ",
                Style::default()
                    .fg(self.theme.base)
                    .bg(self.theme.peach)
                    .add_modifier(Modifier::BOLD),
            ),
            DissectState::Deep => Span::styled(
                " DEEP ",
                Style::default()
                    .fg(self.theme.base)
                    .bg(self.theme.mauve)
                    .add_modifier(Modifier::BOLD),
            ),
        };

        let mut spans = vec![
            Span::styled(
                format!(" Packets: {} ", self.packet_count),
                Style::default().fg(self.theme.text).bg(self.theme.surface0),
            ),
            Span::styled(
                " | ",
                Style::default().fg(self.theme.overlay0).bg(self.theme.surface0),
            ),
            Span::styled(
                sel_text,
                Style::default().fg(self.theme.text).bg(self.theme.surface0),
            ),
        ];

        if self.capture_state != CaptureState::Idle {
            spans.push(capture_span);
            spans.push(Span::styled(
                " ",
                Style::default().bg(self.theme.surface0),
            ));
        }

        if self.dissect_state != DissectState::Fast {
            spans.push(dissect_span);
            spans.push(Span::styled(
                " ",
                Style::default().bg(self.theme.surface0),
            ));
        }

        // Show error/status message if present
        if let Some(msg) = self.status_message {
            spans.push(Span::styled(
                format!(" {msg} "),
                Style::default().fg(self.theme.red).bg(self.theme.surface0),
            ));
        }

        spans.push(Span::styled(
            format!(" TuiShark v{} ", env!("CARGO_PKG_VERSION")),
            Style::default().fg(self.theme.subtext0).bg(self.theme.surface0),
        ));

        let line = Line::from(spans);

        // Fill background
        for x in area.left()..area.right() {
            buf[(x, area.y)]
                .set_style(Style::default().bg(self.theme.surface0));
        }

        buf.set_line(area.x, area.y, &line, area.width);
    }
}

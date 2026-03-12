use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Widget},
};

use crate::trace::model::{ProcessInfo, TraceState};
use crate::ui::theme::Theme;

pub struct TraceView<'a> {
    process_info: Option<&'a ProcessInfo>,
    trace_state: TraceState,
    theme: &'a Theme,
    is_focused: bool,
    map_entries: usize,
}

impl<'a> TraceView<'a> {
    pub fn new(
        process_info: Option<&'a ProcessInfo>,
        trace_state: TraceState,
        theme: &'a Theme,
        is_focused: bool,
    ) -> Self {
        Self {
            process_info,
            trace_state,
            theme,
            is_focused,
            map_entries: 0,
        }
    }

    pub fn with_map_entries(mut self, count: usize) -> Self {
        self.map_entries = count;
        self
    }
}

impl Widget for TraceView<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let border_color = if self.is_focused {
            self.theme.blue
        } else {
            self.theme.surface2
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(" Kernel Trace ")
            .title_style(Style::default().fg(self.theme.text))
            .style(Style::default().bg(self.theme.base));

        let content = match self.trace_state {
            TraceState::Disabled => {
                vec![Line::from(Span::styled(
                    "Kernel tracing disabled (use --trace)",
                    Style::default().fg(self.theme.subtext0),
                ))]
            }
            TraceState::Unavailable => {
                vec![Line::from(Span::styled(
                    "eBPF unavailable (check permissions/kernel)",
                    Style::default().fg(self.theme.red),
                ))]
            }
            TraceState::FileMode => {
                vec![Line::from(Span::styled(
                    "N/A (file mode — trace requires live capture)",
                    Style::default().fg(self.theme.subtext0),
                ))]
            }
            TraceState::Active => {
                if let Some(info) = self.process_info {
                    vec![
                        Line::from(vec![
                            Span::styled(
                                " PID:     ",
                                Style::default()
                                    .fg(self.theme.subtext1)
                                    .add_modifier(Modifier::BOLD),
                            ),
                            Span::styled(
                                info.pid.to_string(),
                                Style::default().fg(self.theme.green),
                            ),
                        ]),
                        Line::from(vec![
                            Span::styled(
                                " Process: ",
                                Style::default()
                                    .fg(self.theme.subtext1)
                                    .add_modifier(Modifier::BOLD),
                            ),
                            Span::styled(
                                info.comm_str().to_string(),
                                Style::default()
                                    .fg(self.theme.peach)
                                    .add_modifier(Modifier::BOLD),
                            ),
                        ]),
                        Line::from(vec![
                            Span::styled(
                                " UID:     ",
                                Style::default()
                                    .fg(self.theme.subtext1)
                                    .add_modifier(Modifier::BOLD),
                            ),
                            Span::styled(
                                info.uid.to_string(),
                                Style::default().fg(self.theme.text),
                            ),
                        ]),
                    ]
                } else {
                    let mut lines = vec![Line::from(Span::styled(
                        "No process info for this packet",
                        Style::default().fg(self.theme.subtext0),
                    ))];
                    if self.map_entries > 0 {
                        lines.push(Line::from(Span::styled(
                            format!("BPF map entries: {}", self.map_entries),
                            Style::default().fg(self.theme.surface2),
                        )));
                    }
                    lines
                }
            }
        };

        let paragraph = Paragraph::new(content).block(block);
        paragraph.render(area, buf);
    }
}

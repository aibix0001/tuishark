use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Widget},
};

use crate::trace::model::{ProcessInfo, TraceState};
use crate::trace::path_model::{PacketPath, PathTraceState, Subsystem};
use crate::ui::theme::Theme;

pub struct TraceView<'a> {
    process_info: Option<&'a ProcessInfo>,
    kernel_path: Option<&'a PacketPath>,
    trace_state: TraceState,
    path_trace_state: PathTraceState,
    theme: &'a Theme,
    is_focused: bool,
    map_entries: usize,
    events_lost: u64,
    scroll_offset: usize,
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
            kernel_path: None,
            trace_state,
            path_trace_state: PathTraceState::Inactive,
            theme,
            is_focused,
            map_entries: 0,
            events_lost: 0,
            scroll_offset: 0,
        }
    }

    pub fn with_map_entries(mut self, count: usize) -> Self {
        self.map_entries = count;
        self
    }

    pub fn with_kernel_path(mut self, path: Option<&'a PacketPath>) -> Self {
        self.kernel_path = path;
        self
    }

    pub fn with_path_trace_state(mut self, state: PathTraceState) -> Self {
        self.path_trace_state = state;
        self
    }

    pub fn with_events_lost(mut self, lost: u64) -> Self {
        self.events_lost = lost;
        self
    }

    pub fn with_scroll_offset(mut self, offset: usize) -> Self {
        self.scroll_offset = offset;
        self
    }

    fn subsystem_color(&self, subsystem: Subsystem) -> ratatui::style::Color {
        match subsystem {
            Subsystem::Ingress => self.theme.green,
            Subsystem::Netfilter => self.theme.yellow,
            Subsystem::Transport => self.theme.blue,
            Subsystem::Socket => self.theme.lavender,
            Subsystem::IpOut => self.theme.peach,
            Subsystem::Forward => self.theme.mauve,
            Subsystem::Egress => self.theme.red,
        }
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
                let mut lines = Vec::new();

                // Process info section
                if let Some(info) = self.process_info {
                    lines.push(Line::from(vec![
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
                    ]));
                    lines.push(Line::from(vec![
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
                    ]));
                    lines.push(Line::from(vec![
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
                    ]));
                } else {
                    lines.push(Line::from(Span::styled(
                        "No process info for this packet",
                        Style::default().fg(self.theme.subtext0),
                    )));
                    if self.map_entries > 0 {
                        lines.push(Line::from(Span::styled(
                            format!("BPF map entries: {}", self.map_entries),
                            Style::default().fg(self.theme.surface2),
                        )));
                    }
                }

                // Kernel path section
                if let Some(path) = self.kernel_path {
                    // Separator
                    lines.push(Line::from(Span::styled(
                        "─".repeat(area.width.saturating_sub(2) as usize),
                        Style::default().fg(self.theme.surface1),
                    )));

                    // Path header
                    lines.push(Line::from(vec![
                        Span::styled(
                            " Kernel Path ",
                            Style::default()
                                .fg(self.theme.text)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!("({} hops, {})", path.hops.len(), path.total_time_str()),
                            Style::default().fg(self.theme.subtext0),
                        ),
                    ]));

                    // Hop list
                    for (i, hop) in path.hops.iter().enumerate() {
                        let color = self.subsystem_color(hop.subsystem());
                        let delta_str = if i == 0 {
                            "+0.0 us".to_string()
                        } else {
                            format!("+{}", crate::trace::path_model::format_ns(hop.delta_ns))
                        };

                        lines.push(Line::from(vec![
                            Span::styled(
                                format!("  {:2}. ", i + 1),
                                Style::default().fg(self.theme.subtext0),
                            ),
                            Span::styled(
                                format!("{:<30}", hop.func_name()),
                                Style::default().fg(color),
                            ),
                            Span::styled(
                                delta_str,
                                Style::default().fg(self.theme.subtext1),
                            ),
                        ]));
                    }
                } else if self.path_trace_state != PathTraceState::Inactive {
                    // Path tracing is active but no path for this packet
                    lines.push(Line::from(Span::styled(
                        "─".repeat(area.width.saturating_sub(2) as usize),
                        Style::default().fg(self.theme.surface1),
                    )));
                    lines.push(Line::from(Span::styled(
                        " No kernel path for this packet",
                        Style::default().fg(self.theme.subtext0),
                    )));
                }

                // Events lost indicator
                if self.events_lost > 0 {
                    lines.push(Line::from(Span::styled(
                        format!(" Events lost: {}", self.events_lost),
                        Style::default().fg(self.theme.red),
                    )));
                }

                lines
            }
        };

        let scroll = (self.scroll_offset as u16, 0);
        let paragraph = Paragraph::new(content).block(block).scroll(scroll);
        paragraph.render(area, buf);
    }
}

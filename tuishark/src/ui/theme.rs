use catppuccin::PALETTE;
use ratatui::style::Color;

use crate::dissect::model::Protocol;

pub struct Theme {
    pub base: Color,
    pub mantle: Color,
    pub surface0: Color,
    pub surface1: Color,
    pub surface2: Color,
    pub text: Color,
    pub subtext0: Color,
    pub subtext1: Color,
    pub overlay0: Color,
    pub blue: Color,
    pub green: Color,
    pub yellow: Color,
    pub red: Color,
    pub mauve: Color,
    pub peach: Color,
    pub pink: Color,
    pub flamingo: Color,
    pub teal: Color,
    pub lavender: Color,
}

fn cc(c: catppuccin::Color) -> Color {
    Color::Rgb(c.rgb.r, c.rgb.g, c.rgb.b)
}

impl Theme {
    pub fn mocha() -> Self {
        let m = PALETTE.mocha.colors;
        Self {
            base: cc(m.base),
            mantle: cc(m.mantle),
            surface0: cc(m.surface0),
            surface1: cc(m.surface1),
            surface2: cc(m.surface2),
            text: cc(m.text),
            subtext0: cc(m.subtext0),
            subtext1: cc(m.subtext1),
            overlay0: cc(m.overlay0),
            blue: cc(m.blue),
            green: cc(m.green),
            yellow: cc(m.yellow),
            red: cc(m.red),
            mauve: cc(m.mauve),
            peach: cc(m.peach),
            pink: cc(m.pink),
            flamingo: cc(m.flamingo),
            teal: cc(m.teal),
            lavender: cc(m.lavender),
        }
    }

    pub fn protocol_color(&self, protocol: &Protocol) -> Color {
        match protocol {
            Protocol::Tcp => self.blue,
            Protocol::Udp => self.green,
            Protocol::Dns => self.yellow,
            Protocol::Arp => self.mauve,
            Protocol::Http => self.peach,
            Protocol::Tls => self.pink,
            Protocol::Icmp | Protocol::Icmpv6 => self.flamingo,
            Protocol::Ipv4 | Protocol::Ipv6 => self.teal,
            Protocol::Ethernet => self.lavender,
            Protocol::Unknown(_) => self.subtext0,
        }
    }
}

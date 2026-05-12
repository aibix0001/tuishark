use catppuccin::PALETTE;
use ratatui::style::Color;

use crate::config::theme::CatppuccinFlavor;
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
    pub overlay1: Color,
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
    pub sky: Color,
    pub sapphire: Color,
    pub maroon: Color,
    pub rosewater: Color,
    pub flavor: CatppuccinFlavor,
}

fn cc(c: catppuccin::Color) -> Color {
    Color::Rgb(c.rgb.r, c.rgb.g, c.rgb.b)
}

impl Theme {
    fn from_palette(colors: catppuccin::FlavorColors, flavor: CatppuccinFlavor) -> Self {
        Self {
            base: cc(colors.base),
            mantle: cc(colors.mantle),
            surface0: cc(colors.surface0),
            surface1: cc(colors.surface1),
            surface2: cc(colors.surface2),
            text: cc(colors.text),
            subtext0: cc(colors.subtext0),
            subtext1: cc(colors.subtext1),
            overlay0: cc(colors.overlay0),
            overlay1: cc(colors.overlay1),
            blue: cc(colors.blue),
            green: cc(colors.green),
            yellow: cc(colors.yellow),
            red: cc(colors.red),
            mauve: cc(colors.mauve),
            peach: cc(colors.peach),
            pink: cc(colors.pink),
            flamingo: cc(colors.flamingo),
            teal: cc(colors.teal),
            lavender: cc(colors.lavender),
            sky: cc(colors.sky),
            sapphire: cc(colors.sapphire),
            maroon: cc(colors.maroon),
            rosewater: cc(colors.rosewater),
            flavor,
        }
    }

    pub fn mocha() -> Self {
        Self::from_palette(PALETTE.mocha.colors, CatppuccinFlavor::Mocha)
    }

    pub fn macchiato() -> Self {
        Self::from_palette(PALETTE.macchiato.colors, CatppuccinFlavor::Macchiato)
    }

    pub fn frappe() -> Self {
        Self::from_palette(PALETTE.frappe.colors, CatppuccinFlavor::Frappe)
    }

    pub fn latte() -> Self {
        Self::from_palette(PALETTE.latte.colors, CatppuccinFlavor::Latte)
    }

    pub fn from_flavor(flavor: CatppuccinFlavor) -> Self {
        match flavor {
            CatppuccinFlavor::Mocha => Self::mocha(),
            CatppuccinFlavor::Macchiato => Self::macchiato(),
            CatppuccinFlavor::Frappe => Self::frappe(),
            CatppuccinFlavor::Latte => Self::latte(),
        }
    }

    pub fn flavor_name(&self) -> &'static str {
        match self.flavor {
            CatppuccinFlavor::Mocha => "Mocha",
            CatppuccinFlavor::Macchiato => "Macchiato",
            CatppuccinFlavor::Frappe => "Frappé",
            CatppuccinFlavor::Latte => "Latte",
        }
    }

    pub fn protocol_color(&self, protocol: &Protocol) -> Color {
        match protocol {
            Protocol::Tcp => self.blue,
            Protocol::Udp => self.green,
            Protocol::Dns | Protocol::Mdns => self.yellow,
            Protocol::Arp => self.mauve,
            Protocol::Http => self.peach,
            Protocol::Tls => self.pink,
            Protocol::Ssh | Protocol::Telnet => self.sky,
            Protocol::Smtp | Protocol::Ftp => self.sapphire,
            Protocol::Bgp | Protocol::Ldap | Protocol::Rdp => self.maroon,
            Protocol::Dhcp | Protocol::Ntp => self.rosewater,
            Protocol::Snmp | Protocol::Syslog | Protocol::Tftp | Protocol::Radius => self.overlay1,
            Protocol::Icmp | Protocol::Icmpv6 => self.flamingo,
            Protocol::Ipv4 | Protocol::Ipv6 => self.teal,
            Protocol::Ethernet => self.lavender,
            Protocol::Pflog | Protocol::Enc => self.red,
            Protocol::Unknown(_) => self.subtext0,
        }
    }
}

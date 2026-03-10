mod app;
mod capture;
mod config;
mod dissect;
mod event;
mod export;
mod filter;
mod session;
mod store;
mod tui;
mod ui;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

use capture::live::list_interfaces;

#[derive(Parser, Debug)]
#[command(name = "tuishark", version, about = "Modern console-based packet analyzer")]
struct Cli {
    /// Path to a pcap/pcapng file to open
    file: Option<PathBuf>,

    /// Network interface to capture from (conflicts with file argument)
    #[arg(short = 'i', long = "interface", conflicts_with = "file")]
    interface: Option<String>,

    /// List available network interfaces and exit
    #[arg(long = "list-interfaces")]
    list_interfaces: bool,

    /// Disable deep dissection (tshark), use etherparse-only mode
    #[arg(long = "no-deep")]
    no_deep: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.list_interfaces {
        let interfaces = list_interfaces()?;
        if interfaces.is_empty() {
            println!("No interfaces found. Try running with elevated privileges.");
        } else {
            println!("{:<24} {}", "INTERFACE", "DESCRIPTION");
            println!("{}", "-".repeat(60));
            for iface in &interfaces {
                println!("{:<24} {}", iface.name, iface.description);
            }
        }
        return Ok(());
    }

    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = tui::restore();
        original_hook(info);
    }));

    let enable_deep = if cli.no_deep {
        false
    } else if dissect::deep::tshark_available() {
        true
    } else {
        eprintln!("Note: tshark not found — deep dissection unavailable. Install tshark for full protocol analysis.");
        false
    };

    let mut terminal = tui::init()?;
    let result = app::App::new(cli.file, cli.interface, enable_deep).run(&mut terminal);
    tui::restore()?;

    result
}

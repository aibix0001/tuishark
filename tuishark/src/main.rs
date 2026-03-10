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

#[derive(Parser, Debug)]
#[command(name = "tuishark", version, about = "Modern console-based packet analyzer")]
struct Cli {
    /// Path to a pcap/pcapng file to open
    file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut terminal = tui::init()?;
    let result = app::App::new(cli.file).run(&mut terminal).await;
    tui::restore()?;

    result
}

/// CLI mode: print packets to stdout without the TUI.
///
/// Supports live capture and pcap file reading with optional display filters,
/// multiple output formats (text, csv, json/NDJSON), and eBPF process tracing.

use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Result};
use clap::ValueEnum;

use crate::capture::file::load_pcap;
use crate::capture::live::LiveCapture;
use crate::dissect::model::PacketSummary;
use crate::filter::{ast::Expr, eval, parser};
use crate::trace::engine::TraceEngine;
use crate::trace::lookup::flow_key_from_summary;

/// Output format for CLI mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// One line per packet, tshark-style columns
    Text,
    /// Header row + one CSV row per packet
    Csv,
    /// NDJSON — one JSON object per line, pipeable to jq
    Json,
}

static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn sigint_handler(_sig: libc::c_int) {
    RUNNING.store(false, Ordering::SeqCst);
}

fn install_signal_handler() {
    // Reset RUNNING in case a previous invocation set it to false
    RUNNING.store(true, Ordering::SeqCst);
    unsafe {
        libc::signal(libc::SIGINT, sigint_handler as *const () as usize as libc::sighandler_t);
        libc::signal(libc::SIGTERM, sigint_handler as *const () as usize as libc::sighandler_t);
    }
}

pub fn run(
    file: Option<PathBuf>,
    interface: Option<String>,
    enable_trace: bool,
    filter_expr: Option<String>,
    output_format: OutputFormat,
    count: Option<usize>,
) -> Result<()> {
    let filter = filter_expr
        .as_ref()
        .map(|expr| parser::parse(expr).map_err(|e| anyhow::anyhow!("bad filter: {e}")))
        .transpose()?;

    let mut trace_engine = if enable_trace {
        match TraceEngine::new() {
            Ok(engine) => Some(engine),
            Err(e) => {
                eprintln!("Warning: eBPF tracing unavailable: {e}");
                None
            }
        }
    } else {
        None
    };

    if let Some(path) = file {
        run_file(&path, filter.as_ref(), &mut trace_engine, output_format, count)
    } else if let Some(iface) = interface {
        run_live(&iface, filter.as_ref(), &mut trace_engine, output_format, count)
    } else {
        bail!("CLI mode requires either a pcap file or -i <interface>");
    }
}

fn run_file(
    path: &std::path::Path,
    filter: Option<&Expr>,
    trace_engine: &mut Option<TraceEngine>,
    format: OutputFormat,
    count: Option<usize>,
) -> Result<()> {
    install_signal_handler();

    let (packets, _first_ts) = load_pcap(path)?;
    let mut out = BufWriter::new(io::stdout().lock());
    write_header(&mut out, format)?;

    let mut printed = 0usize;
    for (summary, _raw) in &packets {
        if !RUNNING.load(Ordering::SeqCst) {
            break;
        }
        if let Some(max) = count {
            if printed >= max {
                break;
            }
        }
        if let Some(f) = filter {
            if !eval::matches(f, summary) {
                continue;
            }
        }
        let proc_info = lookup_process(trace_engine, summary);
        if write_packet(&mut out, summary, proc_info.as_deref(), format).is_err() {
            break; // broken pipe
        }
        printed += 1;
    }

    let _ = out.flush();
    eprintln!("\n{printed} packets displayed.");
    Ok(())
}

fn run_live(
    interface: &str,
    filter: Option<&Expr>,
    trace_engine: &mut Option<TraceEngine>,
    format: OutputFormat,
    count: Option<usize>,
) -> Result<()> {
    install_signal_handler();

    let mut capture = LiveCapture::start(interface, 0)?;
    let mut out = BufWriter::new(io::stdout().lock());
    write_header(&mut out, format)?;

    let mut printed = 0usize;

    while RUNNING.load(Ordering::SeqCst) {
        if let Some(max) = count {
            if printed >= max {
                break;
            }
        }

        match capture.try_recv() {
            Some((summary, _raw)) => {
                if let Some(f) = filter {
                    if !eval::matches(f, &summary) {
                        continue;
                    }
                }
                let proc_info = lookup_process(trace_engine, &summary);
                if write_packet(&mut out, &summary, proc_info.as_deref(), format).is_err() {
                    break; // broken pipe
                }
                printed += 1;
            }
            None => {
                if !capture.is_running() {
                    if let Some(err) = capture.error() {
                        eprintln!("Capture error: {err}");
                    }
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
        }
    }

    capture.stop();
    let _ = out.flush();
    eprintln!("\n{printed} packets captured and displayed.");
    Ok(())
}

fn lookup_process(engine: &mut Option<TraceEngine>, summary: &PacketSummary) -> Option<String> {
    let engine = engine.as_mut()?;
    let key = flow_key_from_summary(summary)?;
    let info = engine.lookup(&key)?;
    Some(format!("[{}:{}]", info.pid, info.comm_str()))
}

fn write_header(out: &mut impl Write, format: OutputFormat) -> io::Result<()> {
    match format {
        OutputFormat::Csv => writeln!(out, "No,Time,Source,Destination,Protocol,Length,Info,Process"),
        _ => Ok(()), // text and json have no header
    }
}

fn write_packet(
    out: &mut impl Write,
    pkt: &PacketSummary,
    proc_info: Option<&str>,
    format: OutputFormat,
) -> io::Result<()> {
    let result = match format {
        OutputFormat::Csv => write_csv(out, pkt, proc_info),
        OutputFormat::Json => write_json(out, pkt, proc_info),
        OutputFormat::Text => write_text(out, pkt, proc_info),
    };
    match result {
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Err(e),
        Err(e) => {
            eprintln!("write error: {e}");
            Err(e)
        }
        Ok(()) => Ok(()),
    }
}

fn write_text(out: &mut impl Write, pkt: &PacketSummary, proc_info: Option<&str>) -> io::Result<()> {
    match proc_info {
        Some(p) => writeln!(
            out,
            "{:>6} {:>10.6} {:<39} {:<39} {:<8} {:>6} {} {}",
            pkt.index + 1,
            pkt.timestamp,
            pkt.source,
            pkt.destination,
            pkt.protocol,
            pkt.original_length,
            pkt.info,
            p,
        ),
        None => writeln!(
            out,
            "{:>6} {:>10.6} {:<39} {:<39} {:<8} {:>6} {}",
            pkt.index + 1,
            pkt.timestamp,
            pkt.source,
            pkt.destination,
            pkt.protocol,
            pkt.original_length,
            pkt.info,
        ),
    }
}

fn write_csv(out: &mut impl Write, pkt: &PacketSummary, proc_info: Option<&str>) -> io::Result<()> {
    writeln!(
        out,
        "{},{:.6},\"{}\",\"{}\",\"{}\",{},\"{}\",\"{}\"",
        pkt.index + 1,
        pkt.timestamp,
        csv_escape(&pkt.source),
        csv_escape(&pkt.destination),
        csv_escape(&pkt.protocol.to_string()),
        pkt.original_length,
        csv_escape(&pkt.info),
        csv_escape(proc_info.unwrap_or("")),
    )
}

fn csv_escape(s: &str) -> String {
    s.replace('"', "\"\"")
}

fn write_json(out: &mut impl Write, pkt: &PacketSummary, proc_info: Option<&str>) -> io::Result<()> {
    write!(
        out,
        "{{\"no\":{},\"time\":{:.6},\"src\":\"{}\",\"dst\":\"{}\",\"proto\":\"{}\",\"len\":{}",
        pkt.index + 1,
        pkt.timestamp,
        escape_json(&pkt.source),
        escape_json(&pkt.destination),
        escape_json(&pkt.protocol.to_string()),
        pkt.original_length,
    )?;
    write!(out, ",\"info\":\"{}\"", escape_json(&pkt.info))?;
    if let Some(p) = proc_info {
        write!(out, ",\"process\":\"{}\"", escape_json(p))?;
    }
    writeln!(out, "}}")
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as FmtWrite;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

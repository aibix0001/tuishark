/// CLI mode: print packets to stdout without the TUI.
///
/// Supports live capture and pcap file reading with optional display filters,
/// multiple output formats (text, csv, json), and eBPF process tracing.

use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Result};

use crate::capture::file::load_pcap;
use crate::capture::live::LiveCapture;
use crate::dissect::model::PacketSummary;
use crate::filter::{ast::Expr, eval, parser};
use crate::trace::engine::TraceEngine;
use crate::trace::lookup::flow_key_from_summary;

static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn sigint_handler(_sig: libc::c_int) {
    RUNNING.store(false, Ordering::Release);
}

fn install_signal_handler() {
    unsafe {
        libc::signal(libc::SIGINT, sigint_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, sigint_handler as *const () as libc::sighandler_t);
    }
}

pub fn run(
    file: Option<PathBuf>,
    interface: Option<String>,
    enable_trace: bool,
    filter_expr: Option<String>,
    output_format: &str,
    count: Option<usize>,
) -> Result<()> {
    let filter = match &filter_expr {
        Some(expr) => Some(parser::parse(expr).map_err(|e| anyhow::anyhow!("bad filter: {e}"))?),
        None => None,
    };

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
    format: &str,
    count: Option<usize>,
) -> Result<()> {
    let (packets, _first_ts) = load_pcap(path)?;
    let mut out = BufWriter::new(io::stdout().lock());
    write_header(&mut out, format, trace_engine.is_some())?;

    let mut printed = 0usize;
    for (summary, _raw) in &packets {
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
    format: &str,
    count: Option<usize>,
) -> Result<()> {
    install_signal_handler();

    let mut capture = LiveCapture::start(interface, 0)?;
    let mut out = BufWriter::new(io::stdout().lock());
    write_header(&mut out, format, trace_engine.is_some())?;

    let mut printed = 0usize;

    while RUNNING.load(Ordering::Acquire) {
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

fn write_header(out: &mut impl Write, format: &str, _has_trace: bool) -> io::Result<()> {
    match format {
        "csv" => writeln!(out, "No,Time,Source,Destination,Protocol,Length,Info,Process"),
        _ => Ok(()), // text and json have no header
    }
}

fn write_packet(
    out: &mut impl Write,
    pkt: &PacketSummary,
    proc_info: Option<&str>,
    format: &str,
) -> io::Result<()> {
    let result = match format {
        "csv" => write_csv(out, pkt, proc_info),
        "json" => write_json(out, pkt, proc_info),
        _ => write_text(out, pkt, proc_info),
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
    // Escape info field for CSV (may contain commas)
    let info_escaped = pkt.info.replace('"', "\"\"");
    writeln!(
        out,
        "{},{:.6},{},{},{},{},\"{}\",{}",
        pkt.index + 1,
        pkt.timestamp,
        pkt.source,
        pkt.destination,
        pkt.protocol,
        pkt.original_length,
        info_escaped,
        proc_info.unwrap_or(""),
    )
}

fn write_json(out: &mut impl Write, pkt: &PacketSummary, proc_info: Option<&str>) -> io::Result<()> {
    // Manual JSON to avoid serde_json::to_string overhead per packet
    write!(
        out,
        "{{\"no\":{},\"time\":{:.6},\"src\":\"{}\",\"dst\":\"{}\",\"proto\":\"{}\",\"len\":{}",
        pkt.index + 1,
        pkt.timestamp,
        escape_json(&pkt.source),
        escape_json(&pkt.destination),
        pkt.protocol,
        pkt.original_length,
    )?;
    // Info field needs escaping (may contain quotes, backslashes)
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
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

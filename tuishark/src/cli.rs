/// CLI mode: print packets to stdout without the TUI.
///
/// Supports live capture and pcap file reading with optional display filters,
/// multiple output formats (text, csv, json/NDJSON), and eBPF process tracing.
/// When `--trace-path` is active, polls perf buffers for kernel path events and
/// prints the path alongside each matched packet.

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
use crate::trace::model::FlowKey;
use crate::trace::path_aggregator::PathAggregator;
use crate::trace::path_model::PacketPath;

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
    enable_trace_path: bool,
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

    // Attach path tracing engine if requested
    let path_engine = if enable_trace_path {
        if let Some(ref mut engine) = trace_engine {
            match engine.attach_path_engine() {
                Ok(pe) => {
                    eprintln!("Kernel path tracing active.");
                    Some(pe)
                }
                Err(e) => {
                    eprintln!("Warning: path tracing unavailable: {e}");
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    if let Some(path) = file {
        run_file(&path, filter.as_ref(), &mut trace_engine, path_engine, output_format, count)
    } else if let Some(iface) = interface {
        run_live(&iface, filter.as_ref(), &mut trace_engine, path_engine, output_format, count)
    } else {
        bail!("CLI mode requires either a pcap file or -i <interface>");
    }
}

fn run_file(
    path: &std::path::Path,
    filter: Option<&Expr>,
    trace_engine: &mut Option<TraceEngine>,
    _path_engine: Option<crate::trace::path_engine::PathTraceEngine>,
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
        if write_packet(&mut out, summary, proc_info.as_deref(), None, format).is_err() {
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
    mut path_engine: Option<crate::trace::path_engine::PathTraceEngine>,
    format: OutputFormat,
    count: Option<usize>,
) -> Result<()> {
    install_signal_handler();

    let mut capture = LiveCapture::start(interface, 0)?;
    let mut out = BufWriter::new(io::stdout().lock());
    write_header(&mut out, format)?;

    let mut printed = 0usize;
    let mut path_aggregator = PathAggregator::new();
    // Recent flow keys for path matching: (packet_index, FlowKey)
    let mut recent_flow_keys: Vec<(usize, FlowKey)> = Vec::new();
    // Matched paths: packet_index -> PacketPath
    let mut matched_paths: std::collections::HashMap<usize, PacketPath> = std::collections::HashMap::new();
    let mut total_path_events = 0u64;
    let mut total_completed_paths = 0u64;
    let mut total_path_matches = 0u64;

    while RUNNING.load(Ordering::SeqCst) {
        if let Some(max) = count {
            if printed >= max {
                break;
            }
        }

        // Poll path events from perf buffer
        if let Some(ref mut pe) = path_engine {
            let events = pe.poll();
            if !events.is_empty() {
                total_path_events += events.len() as u64;
                path_aggregator.ingest(&events);
            }
            let completed = path_aggregator.drain_completed();
            if !completed.is_empty() {
                total_completed_paths += completed.len() as u64;
                let matches = PathAggregator::match_to_packets(&completed, &recent_flow_keys);
                total_path_matches += matches.len() as u64;
                for (pkt_idx, path) in matches {
                    matched_paths.insert(pkt_idx, path);
                }
                // Cap matched_paths to prevent unbounded growth from unmatched entries
                if matched_paths.len() > 2000 {
                    matched_paths.clear();
                }
            }
        }

        match capture.try_recv() {
            Some((summary, _raw)) => {
                if let Some(f) = filter {
                    if !eval::matches(f, &summary) {
                        continue;
                    }
                }
                let pkt_index = summary.index;
                let proc_info = lookup_process(trace_engine, &summary);

                // Try to extract a matching path directly from pending events.
                // Path events arrive before or simultaneously with the captured packet,
                // so we can often match immediately without waiting for expiry.
                let flow_key = if path_engine.is_some() {
                    flow_key_from_summary(&summary)
                } else {
                    None
                };

                let path = if let Some(ref fk) = flow_key {
                    // First check previously matched paths, then try pending extraction
                    matched_paths.remove(&pkt_index)
                        .or_else(|| path_aggregator.try_extract_pending(fk))
                } else {
                    matched_paths.remove(&pkt_index)
                };

                // Store flow key for fallback matching of late-completing paths
                if let Some(fk) = flow_key {
                    recent_flow_keys.push((pkt_index, fk));
                    if recent_flow_keys.len() > 2000 {
                        recent_flow_keys.drain(..1000);
                    }
                }

                if write_packet(&mut out, &summary, proc_info.as_deref(), path.as_ref(), format).is_err() {
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

    // Flush remaining path events
    if let Some(ref mut pe) = path_engine {
        let events = pe.poll();
        if !events.is_empty() {
            path_aggregator.ingest(&events);
        }
        path_aggregator.flush();
        let completed = path_aggregator.drain_completed();
        if !completed.is_empty() {
            eprintln!("{} path(s) completed after capture ended (not matched to packets).", completed.len());
        }
        eprintln!("Path events: {} raw, {} completed paths, {} matched to packets, {} lost",
            total_path_events, total_completed_paths, total_path_matches, pe.events_lost);
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

fn format_path(path: &PacketPath) -> String {
    let hops: Vec<String> = path.hops.iter().map(|h| {
        let name = h.func_name();
        if h.delta_ns == 0 {
            name.to_string()
        } else {
            format!("{name}(+{:.1}µs)", h.delta_ns as f64 / 1000.0)
        }
    }).collect();
    format!("path[{}]: {}", hops.len(), hops.join(" → "))
}

fn write_header(out: &mut impl Write, format: OutputFormat) -> io::Result<()> {
    match format {
        OutputFormat::Csv => writeln!(out, "No,Time,Source,Destination,Protocol,Length,Info,Process,Path"),
        _ => Ok(()), // text and json have no header
    }
}

fn write_packet(
    out: &mut impl Write,
    pkt: &PacketSummary,
    proc_info: Option<&str>,
    path: Option<&PacketPath>,
    format: OutputFormat,
) -> io::Result<()> {
    let result = match format {
        OutputFormat::Csv => write_csv(out, pkt, proc_info, path),
        OutputFormat::Json => write_json(out, pkt, proc_info, path),
        OutputFormat::Text => write_text(out, pkt, proc_info, path),
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

fn write_text(out: &mut impl Write, pkt: &PacketSummary, proc_info: Option<&str>, path: Option<&PacketPath>) -> io::Result<()> {
    write!(
        out,
        "{:>6} {:>10.6} {:<39} {:<39} {:<8} {:>6} {}",
        pkt.index + 1,
        pkt.timestamp,
        pkt.source,
        pkt.destination,
        pkt.protocol,
        pkt.original_length,
        pkt.info,
    )?;
    if let Some(p) = proc_info {
        write!(out, " {p}")?;
    }
    if let Some(path) = path {
        write!(out, " {}", format_path(path))?;
    }
    writeln!(out)
}

fn write_csv(out: &mut impl Write, pkt: &PacketSummary, proc_info: Option<&str>, path: Option<&PacketPath>) -> io::Result<()> {
    writeln!(
        out,
        "{},{:.6},\"{}\",\"{}\",\"{}\",{},\"{}\",\"{}\",\"{}\"",
        pkt.index + 1,
        pkt.timestamp,
        csv_escape(&pkt.source),
        csv_escape(&pkt.destination),
        csv_escape(&pkt.protocol.to_string()),
        pkt.original_length,
        csv_escape(&pkt.info),
        csv_escape(proc_info.unwrap_or("")),
        csv_escape(&path.map(|p| format_path(p)).unwrap_or_default()),
    )
}

fn csv_escape(s: &str) -> String {
    s.replace('"', "\"\"")
}

fn write_json(out: &mut impl Write, pkt: &PacketSummary, proc_info: Option<&str>, path: Option<&PacketPath>) -> io::Result<()> {
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
    if let Some(path) = path {
        write!(out, ",\"path\":\"{}\"", escape_json(&format_path(path)))?;
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

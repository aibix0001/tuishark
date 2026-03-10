use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use anyhow::Result;

use crate::dissect::fast::parse_packet;
use crate::dissect::model::PacketSummary;

/// Description of a network interface available for capture.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: String,
}

/// List all available network interfaces.
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>> {
    let devices = pcap::Device::list()?;
    let interfaces = devices
        .into_iter()
        .map(|d| InterfaceInfo {
            description: d.desc.unwrap_or_default(),
            name: d.name,
        })
        .collect();
    Ok(interfaces)
}

/// A live packet capture running on a background thread.
pub struct LiveCapture {
    pub receiver: Receiver<(PacketSummary, Vec<u8>)>,
    stop_flag: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl LiveCapture {
    /// Start capturing on the given interface in a background thread.
    /// Packets are sent through the channel as `(PacketSummary, raw_bytes)`.
    /// The `packet_offset` sets the starting index for packet numbering.
    pub fn start(interface: &str, packet_offset: usize) -> Result<Self> {
        let cap = pcap::Capture::from_device(interface)?
            .promisc(true)
            .snaplen(65535)
            .timeout(100) // 100ms poll timeout so we can check stop flag
            .open()?;

        let stop_flag = Arc::new(AtomicBool::new(false));
        let (tx, rx): (Sender<(PacketSummary, Vec<u8>)>, _) = mpsc::channel();

        let stop = stop_flag.clone();
        let handle = thread::spawn(move || {
            capture_loop(cap, tx, stop, packet_offset);
        });

        Ok(Self {
            receiver: rx,
            stop_flag,
            handle: Some(handle),
        })
    }

    /// Signal the capture thread to stop and wait for it to finish.
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }

    /// Check if the capture thread is still running.
    pub fn is_running(&self) -> bool {
        self.handle
            .as_ref()
            .is_some_and(|h| !h.is_finished())
    }
}

impl Drop for LiveCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

fn capture_loop(
    mut cap: pcap::Capture<pcap::Active>,
    tx: Sender<(PacketSummary, Vec<u8>)>,
    stop: Arc<AtomicBool>,
    packet_offset: usize,
) {
    let mut index = packet_offset;
    let mut first_ts: Option<f64> = None;

    while !stop.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(packet) => {
                let ts = packet.header.ts.tv_sec as f64
                    + packet.header.ts.tv_usec as f64 / 1_000_000.0;
                let relative_ts = match first_ts {
                    Some(first) => ts - first,
                    None => {
                        first_ts = Some(ts);
                        0.0
                    }
                };

                let raw = packet.data.to_vec();
                let summary = parse_packet(index, relative_ts, &raw);
                index += 1;

                if tx.send((summary, raw)).is_err() {
                    break; // receiver dropped
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                continue; // normal timeout, check stop flag and loop
            }
            Err(_) => {
                break; // capture error, stop thread
            }
        }
    }
}

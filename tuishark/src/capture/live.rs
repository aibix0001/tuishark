use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use anyhow::{Context, Result};

use crate::dissect::fast::parse_packet;
use crate::dissect::model::PacketSummary;

/// Channel capacity for packets between capture thread and UI.
const CHANNEL_CAPACITY: usize = 10_000;

/// Description of a network interface available for capture.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: String,
}

/// List all available network interfaces.
#[must_use = "result should be checked"]
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>> {
    let devices = pcap::Device::list().context("failed to list network interfaces (need root or CAP_NET_RAW?)")?;
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
    receiver: Receiver<(PacketSummary, Vec<u8>)>,
    stop_flag: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    error: Arc<std::sync::Mutex<Option<String>>>,
}

impl LiveCapture {
    /// Start capturing on the given interface in a background thread.
    /// The `packet_offset` sets the starting index for packet numbering.
    pub fn start(interface: &str, packet_offset: usize) -> Result<Self> {
        let cap = pcap::Capture::from_device(interface)
            .with_context(|| format!("cannot open interface '{interface}' (need root or CAP_NET_RAW?)"))?
            .promisc(true)
            .snaplen(65535)
            .timeout(100) // 100ms poll timeout so we can check stop flag
            .open()
            .with_context(|| format!("failed to start capture on '{interface}'"))?;

        // Check link type — we only support Ethernet (DLT_EN10MB = 1)
        let datalink = cap.get_datalink();
        if datalink != pcap::Linktype::ETHERNET {
            anyhow::bail!(
                "unsupported link type on '{interface}': {:?} (only Ethernet is supported)",
                datalink
            );
        }

        let stop_flag = Arc::new(AtomicBool::new(false));
        let error: Arc<std::sync::Mutex<Option<String>>> =
            Arc::new(std::sync::Mutex::new(None));
        let (tx, rx) = mpsc::sync_channel::<(PacketSummary, Vec<u8>)>(CHANNEL_CAPACITY);

        let stop = stop_flag.clone();
        let err = error.clone();
        let handle = thread::spawn(move || {
            capture_loop(cap, tx, stop, packet_offset, err);
        });

        Ok(Self {
            receiver: rx,
            stop_flag,
            handle: Some(handle),
            error,
        })
    }

    /// Try to receive the next packet without blocking.
    /// Returns `Some((summary, raw))` if a packet is available, `None` otherwise.
    pub fn try_recv(&self) -> Option<(PacketSummary, Vec<u8>)> {
        match self.receiver.try_recv() {
            Ok(packet) => Some(packet),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => None,
        }
    }

    /// Signal the capture thread to stop and wait for it to finish.
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }

    /// Check if the capture thread is still running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.handle
            .as_ref()
            .is_some_and(|h| !h.is_finished())
    }

    /// Return the error message if the capture thread exited due to an error.
    pub fn error(&self) -> Option<String> {
        self.error.lock().ok()?.clone()
    }
}

impl Drop for LiveCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

fn capture_loop(
    mut cap: pcap::Capture<pcap::Active>,
    tx: SyncSender<(PacketSummary, Vec<u8>)>,
    stop: Arc<AtomicBool>,
    packet_offset: usize,
    error: Arc<std::sync::Mutex<Option<String>>>,
) {
    let mut index = packet_offset;
    let mut first_ts: Option<f64> = None;

    while !stop.load(Ordering::Acquire) {
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

                // Bounded channel: if full, drop packet (backpressure)
                if tx.try_send((summary, raw)).is_err() {
                    continue;
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                continue;
            }
            Err(e) => {
                if let Ok(mut err) = error.lock() {
                    *err = Some(format!("capture error: {e}"));
                }
                break;
            }
        }
    }
}

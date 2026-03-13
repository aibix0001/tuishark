use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

use super::deep::DeepDissector;
use super::model::PacketDetail;

/// Request to deeply dissect a packet.
pub struct DissectRequest {
    /// Packet index — used to correlate with the currently selected packet.
    pub index: usize,
    /// Monotonically increasing sequence number to detect stale requests.
    pub seq: usize,
    /// Raw packet bytes.
    pub raw: Vec<u8>,
    /// Packet timestamp (seconds since epoch or relative).
    pub timestamp: f64,
}

/// Result of a deep dissection.
pub struct DissectResult {
    /// Packet index this result corresponds to.
    pub index: usize,
    /// Sequence number matching the request.
    pub seq: usize,
    /// Deep dissection detail, or None if dissection failed.
    pub detail: Option<PacketDetail>,
    /// Error message if dissection failed.
    pub error: Option<String>,
}

/// Background worker that processes deep dissection requests.
pub struct DissectWorker {
    request_tx: mpsc::Sender<DissectRequest>,
    result_rx: mpsc::Receiver<DissectResult>,
    latest_seq: Arc<AtomicUsize>,
    alive: Arc<AtomicBool>,
}

impl DissectWorker {
    /// Spawn a new background dissection worker thread.
    /// Returns `Err` with a description if tshark/DeepDissector fails to initialize.
    /// The `linktype` parameter specifies the pcap link-layer type (e.g., 1 for Ethernet).
    pub fn try_spawn(linktype: u32) -> Result<Self, String> {
        let (request_tx, request_rx) = mpsc::channel::<DissectRequest>();
        let (result_tx, result_rx) = mpsc::channel::<DissectResult>();
        let latest_seq = Arc::new(AtomicUsize::new(0));
        let alive = Arc::new(AtomicBool::new(true));

        let dissector = DeepDissector::new(linktype).map_err(|e| format!("{e:#}"))?;

        let seq_clone = latest_seq.clone();
        let alive_clone = alive.clone();
        thread::spawn(move || {
            worker_loop(dissector, request_rx, result_tx, seq_clone);
            alive_clone.store(false, Ordering::Release);
        });

        Ok(Self {
            request_tx,
            result_rx,
            latest_seq,
            alive,
        })
    }

    /// Send a dissection request to the worker.
    /// Takes ownership of the request to avoid an extra clone.
    /// Updates the latest sequence number so the worker can skip stale requests.
    pub fn request(&self, req: DissectRequest) {
        self.latest_seq.store(req.seq, Ordering::Release);
        // Ignore send errors — worker may have died
        let _ = self.request_tx.send(req);
    }

    /// Try to receive a completed dissection result (non-blocking).
    pub fn try_recv(&self) -> Option<DissectResult> {
        self.result_rx.try_recv().ok()
    }

    /// Check if the worker thread is still alive.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }
}

fn worker_loop(
    mut dissector: DeepDissector,
    request_rx: mpsc::Receiver<DissectRequest>,
    result_tx: mpsc::Sender<DissectResult>,
    latest_seq: Arc<AtomicUsize>,
) {
    while let Ok(req) = request_rx.recv() {
        // Skip stale requests — only process the latest
        if req.seq < latest_seq.load(Ordering::Acquire) {
            continue;
        }

        let (detail, error) = match dissector.dissect_packet(&req.raw, req.timestamp) {
            Ok(d) => (Some(d), None),
            Err(e) => (None, Some(format!("{e:#}"))),
        };

        let result = DissectResult {
            index: req.index,
            seq: req.seq,
            detail,
            error,
        };

        if result_tx.send(result).is_err() {
            break; // main thread dropped the receiver
        }
    }
}

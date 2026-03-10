use std::sync::mpsc;
use std::thread;

use super::deep::DeepDissector;
use super::model::PacketDetail;

/// Request to deeply dissect a packet.
pub struct DissectRequest {
    /// Packet index — used to correlate with the currently selected packet.
    pub index: usize,
    /// Raw packet bytes.
    pub raw: Vec<u8>,
    /// Packet timestamp (seconds since epoch or relative).
    pub timestamp: f64,
}

/// Result of a deep dissection.
pub struct DissectResult {
    /// Packet index this result corresponds to.
    pub index: usize,
    /// Deep dissection detail, or None if dissection failed.
    pub detail: Option<PacketDetail>,
}

/// Background worker that processes deep dissection requests.
pub struct DissectWorker {
    request_tx: mpsc::Sender<DissectRequest>,
    result_rx: mpsc::Receiver<DissectResult>,
}

impl DissectWorker {
    /// Spawn a new background dissection worker thread.
    /// Returns None if tshark/DeepDissector fails to initialize.
    pub fn spawn() -> Option<Self> {
        let (request_tx, request_rx) = mpsc::channel::<DissectRequest>();
        let (result_tx, result_rx) = mpsc::channel::<DissectResult>();

        // Try to create the dissector — if it fails, tshark isn't available
        let dissector = match DeepDissector::new() {
            Ok(d) => d,
            Err(_) => return None,
        };

        thread::spawn(move || {
            worker_loop(dissector, request_rx, result_tx);
        });

        Some(Self {
            request_tx,
            result_rx,
        })
    }

    /// Send a dissection request to the worker.
    pub fn request(&self, req: DissectRequest) {
        // Ignore send errors — worker may have died
        let _ = self.request_tx.send(req);
    }

    /// Try to receive a completed dissection result (non-blocking).
    pub fn try_recv(&self) -> Option<DissectResult> {
        self.result_rx.try_recv().ok()
    }
}

fn worker_loop(
    mut dissector: DeepDissector,
    request_rx: mpsc::Receiver<DissectRequest>,
    result_tx: mpsc::Sender<DissectResult>,
) {
    while let Ok(req) = request_rx.recv() {
        let detail = dissector
            .dissect_packet(&req.raw, req.timestamp)
            .ok();

        let result = DissectResult {
            index: req.index,
            detail,
        };

        if result_tx.send(result).is_err() {
            break; // main thread dropped the receiver
        }
    }
}

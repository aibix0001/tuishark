use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::config::ai::AiConfig;

use super::model::{
    AiRequest, AiResponse, ChatCompletionRequest, ChatCompletionResponse,
};

pub struct AiWorker {
    request_tx: mpsc::Sender<AiRequest>,
    result_rx: mpsc::Receiver<AiResponse>,
    latest_seq: Arc<AtomicUsize>,
    alive: Arc<AtomicBool>,
}

impl AiWorker {
    pub fn spawn(config: AiConfig) -> Self {
        let (request_tx, request_rx) = mpsc::channel::<AiRequest>();
        let (result_tx, result_rx) = mpsc::channel::<AiResponse>();
        let latest_seq = Arc::new(AtomicUsize::new(0));
        let alive = Arc::new(AtomicBool::new(true));

        let seq_clone = latest_seq.clone();
        let alive_clone = alive.clone();
        thread::spawn(move || {
            worker_loop(config, request_rx, result_tx, seq_clone);
            alive_clone.store(false, Ordering::Release);
        });

        Self {
            request_tx,
            result_rx,
            latest_seq,
            alive,
        }
    }

    pub fn request(&self, req: AiRequest) {
        self.latest_seq.store(req.seq, Ordering::Release);
        let _ = self.request_tx.send(req);
    }

    pub fn try_recv(&self) -> Option<AiResponse> {
        self.result_rx.try_recv().ok()
    }

    #[allow(dead_code)]
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }
}

fn worker_loop(
    config: AiConfig,
    request_rx: mpsc::Receiver<AiRequest>,
    result_tx: mpsc::Sender<AiResponse>,
    latest_seq: Arc<AtomicUsize>,
) {
    let agent = ureq::AgentBuilder::new()
        .timeout_read(Duration::from_millis(config.timeout_ms))
        .timeout_write(Duration::from_secs(10))
        .build();

    let url = format!(
        "{}/chat/completions",
        config.base_url.trim_end_matches('/')
    );

    while let Ok(req) = request_rx.recv() {
        if req.seq < latest_seq.load(Ordering::Acquire) {
            continue;
        }

        let result = execute_request(&agent, &url, &config, &req);

        let response = AiResponse {
            packet_index: req.packet_index,
            seq: req.seq,
            kind: req.kind,
            result,
        };

        if result_tx.send(response).is_err() {
            break;
        }
    }
}

fn execute_request(
    agent: &ureq::Agent,
    url: &str,
    config: &AiConfig,
    req: &AiRequest,
) -> Result<String, String> {
    let body = ChatCompletionRequest {
        model: config.model.clone(),
        messages: req.messages.clone(),
    };

    let mut http_req = agent.post(url);
    if !config.api_key.is_empty() {
        http_req = http_req.set(
            "Authorization",
            &format!("Bearer {}", config.api_key),
        );
    }

    let resp = http_req
        .send_json(&body)
        .map_err(|e| match e {
            ureq::Error::Status(code, resp) => {
                let body = resp.into_string().unwrap_or_default();
                format!("HTTP {code}: {body}")
            }
            ureq::Error::Transport(t) => format!("{t}"),
        })?;

    let parsed: ChatCompletionResponse = resp
        .into_json()
        .map_err(|e| format!("Invalid response: {e}"))?;

    parsed
        .choices
        .into_iter()
        .next()
        .map(|c| c.message.content)
        .ok_or_else(|| "No content in response".into())
}

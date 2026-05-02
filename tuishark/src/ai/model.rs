use std::collections::{HashMap, VecDeque};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiOverlayFocus {
    Left,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiRequestKind {
    WholePacket,
    Field { layer_index: usize, field_index: Option<usize> },
}

pub struct AiRequest {
    pub packet_index: usize,
    pub seq: usize,
    pub kind: AiRequestKind,
    pub messages: Vec<ChatMessage>,
}

pub struct AiResponse {
    pub packet_index: usize,
    pub seq: usize,
    pub kind: AiRequestKind,
    pub result: Result<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Serialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ChatCompletionResponse {
    pub choices: Vec<ChatChoice>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ChatChoice {
    pub message: ChatResponseMessage,
}

#[derive(Debug, serde::Deserialize)]
pub struct ChatResponseMessage {
    pub content: String,
}

#[derive(Debug)]
pub enum AiState {
    Idle,
    Loading { seq: usize },
    Ready(String),
    Error(String),
    Unconfigured,
}

pub struct PacketAiEntry {
    pub whole_packet: Option<String>,
    pub fields: HashMap<(usize, Option<usize>), String>,
}

impl PacketAiEntry {
    fn new() -> Self {
        Self {
            whole_packet: None,
            fields: HashMap::new(),
        }
    }
}

pub struct AiCache {
    entries: HashMap<usize, PacketAiEntry>,
    order: VecDeque<usize>,
    capacity: usize,
}

impl AiCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    fn touch(&mut self, packet_index: usize) {
        if let Some(pos) = self.order.iter().position(|&k| k == packet_index) {
            self.order.remove(pos);
        }
        self.order.push_back(packet_index);
    }

    fn evict_if_full(&mut self) {
        while self.entries.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
    }

    fn ensure_entry(&mut self, packet_index: usize) -> &mut PacketAiEntry {
        if !self.entries.contains_key(&packet_index) {
            self.evict_if_full();
            self.entries.insert(packet_index, PacketAiEntry::new());
        }
        self.touch(packet_index);
        self.entries.get_mut(&packet_index).unwrap()
    }

    pub fn get_whole(&mut self, packet_index: usize) -> Option<String> {
        if !self.entries.contains_key(&packet_index) {
            return None;
        }
        self.touch(packet_index);
        self.entries
            .get(&packet_index)
            .and_then(|e| e.whole_packet.clone())
    }

    pub fn get_field(
        &mut self,
        packet_index: usize,
        layer_index: usize,
        field_index: Option<usize>,
    ) -> Option<String> {
        if !self.entries.contains_key(&packet_index) {
            return None;
        }
        self.touch(packet_index);
        self.entries
            .get(&packet_index)
            .and_then(|e| e.fields.get(&(layer_index, field_index)).cloned())
    }

    pub fn insert_whole(&mut self, packet_index: usize, text: String) {
        let entry = self.ensure_entry(packet_index);
        entry.whole_packet = Some(text);
    }

    pub fn insert_field(
        &mut self,
        packet_index: usize,
        layer_index: usize,
        field_index: Option<usize>,
        text: String,
    ) {
        let entry = self.ensure_entry(packet_index);
        entry.fields.insert((layer_index, field_index), text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_insert_and_get_whole() {
        let mut cache = AiCache::new(4);
        cache.insert_whole(10, "explanation for packet 10".into());
        assert_eq!(cache.get_whole(10), Some("explanation for packet 10".into()));
    }

    #[test]
    fn cache_miss_returns_none() {
        let mut cache = AiCache::new(4);
        assert_eq!(cache.get_whole(99), None);
        assert_eq!(cache.get_field(99, 0, Some(0)), None);
    }

    #[test]
    fn cache_insert_and_get_field() {
        let mut cache = AiCache::new(4);
        cache.insert_field(10, 2, Some(1), "TCP flags explanation".into());
        assert_eq!(cache.get_field(10, 2, Some(1)), Some("TCP flags explanation".into()));
        assert_eq!(cache.get_field(10, 2, Some(0)), None);
    }

    #[test]
    fn cache_layer_level_field() {
        let mut cache = AiCache::new(4);
        cache.insert_field(10, 1, None, "IPv4 layer explanation".into());
        assert_eq!(cache.get_field(10, 1, None), Some("IPv4 layer explanation".into()));
    }

    #[test]
    fn cache_evicts_oldest_when_full() {
        let mut cache = AiCache::new(3);
        cache.insert_whole(1, "pkt 1".into());
        cache.insert_whole(2, "pkt 2".into());
        cache.insert_whole(3, "pkt 3".into());
        cache.insert_whole(4, "pkt 4".into());
        assert_eq!(cache.get_whole(1), None);
        assert_eq!(cache.get_whole(2), Some("pkt 2".into()));
        assert_eq!(cache.get_whole(4), Some("pkt 4".into()));
    }

    #[test]
    fn cache_access_refreshes_lru_order() {
        let mut cache = AiCache::new(3);
        cache.insert_whole(1, "pkt 1".into());
        cache.insert_whole(2, "pkt 2".into());
        cache.insert_whole(3, "pkt 3".into());
        let _ = cache.get_whole(1);
        cache.insert_whole(4, "pkt 4".into());
        assert_eq!(cache.get_whole(1), Some("pkt 1".into()));
        assert_eq!(cache.get_whole(2), None);
        assert_eq!(cache.get_whole(3), Some("pkt 3".into()));
        assert_eq!(cache.get_whole(4), Some("pkt 4".into()));
    }

    #[test]
    fn cache_whole_and_field_coexist() {
        let mut cache = AiCache::new(4);
        cache.insert_whole(5, "whole packet".into());
        cache.insert_field(5, 0, Some(1), "field 0.1".into());
        cache.insert_field(5, 1, None, "layer 1".into());
        assert_eq!(cache.get_whole(5), Some("whole packet".into()));
        assert_eq!(cache.get_field(5, 0, Some(1)), Some("field 0.1".into()));
        assert_eq!(cache.get_field(5, 1, None), Some("layer 1".into()));
    }

    #[test]
    fn chat_completion_request_serializes() {
        let req = ChatCompletionRequest {
            model: "test-model".into(),
            messages: vec![
                ChatMessage { role: "system".into(), content: "You are helpful.".into() },
                ChatMessage { role: "user".into(), content: "Explain this.".into() },
            ],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["model"], "test-model");
        assert_eq!(json["messages"][0]["role"], "system");
        assert_eq!(json["messages"][1]["role"], "user");
    }

    #[test]
    fn chat_completion_response_deserializes() {
        let json = r#"{"choices":[{"message":{"content":"This is a TCP SYN packet."}}]}"#;
        let resp: ChatCompletionResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.choices[0].message.content, "This is a TCP SYN packet.");
    }

    #[test]
    fn chat_completion_response_empty_choices() {
        let json = r#"{"choices":[]}"#;
        let resp: ChatCompletionResponse = serde_json::from_str(json).unwrap();
        assert!(resp.choices.is_empty());
    }
}

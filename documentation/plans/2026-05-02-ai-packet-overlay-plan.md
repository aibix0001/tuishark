---
title: "AI Packet Learning Overlay Implementation Plan"
date: 2026-05-02
author: agent
status: draft
related_issues: [41]
related_mrs: []
---

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Shift+I AI packet explanation overlay with OpenAI-compatible backend (#41)

**Architecture:** Two-column modal overlay (shared detail tree left, AI explanation right). Background `ureq` HTTP thread with mpsc channels (same pattern as DissectWorker). LRU cache (configurable size) across packets. Status dot indicator in right pane.

**Tech Stack:** ureq 2 (sync HTTP), serde/serde_json (serialization), std::thread + mpsc (concurrency), ratatui (UI)

---

## File Structure

### New Files

| File | Responsibility |
|------|---------------|
| `tuishark/src/config/ai.rs` | `AiConfig` struct with serde defaults |
| `tuishark/src/ai/mod.rs` | Module re-exports |
| `tuishark/src/ai/model.rs` | `AiState`, `AiCache`, `AiOverlayFocus`, request/response types |
| `tuishark/src/ai/context.rs` | Packet context JSON builder, system/user prompts |
| `tuishark/src/ai/worker.rs` | Background thread, ureq POST to `/chat/completions` |
| `tuishark/src/ui/dialogs/ai_overlay.rs` | Two-column overlay Widget |

### Modified Files

| File | Lines | Change |
|------|-------|--------|
| `tuishark/Cargo.toml` | 15-31 | Add `ureq` dependency |
| `tuishark/src/main.rs` | 1-15 | Add `mod ai;` |
| `tuishark/src/config/mod.rs` | 1-4, 14-25, 27-39 | Add `pub mod ai;`, `AiConfig` field, default |
| `tuishark/src/config/keys.rs` | 8-42, 54-89, 91-128, 141-174 | Add `AiPacketInfo` action + binding |
| `tuishark/src/ui/dialogs/mod.rs` | 1-10 | Add `pub mod ai_overlay;` |
| `tuishark/src/app.rs` | 112-233, 432-443, 888-995, 1042-1107 | State fields, drain, render, key handling |

---

### Task 1: Add ureq dependency and AI module scaffold

**Files:**
- Modify: `tuishark/Cargo.toml:15-31`
- Create: `tuishark/src/ai/mod.rs`
- Modify: `tuishark/src/main.rs:1-15`

- [ ] **Step 1: Add ureq to Cargo.toml**

Add after the `toml` line (line 28):

```toml
ureq = { version = "2", features = ["json"] }
```

- [ ] **Step 2: Create AI module scaffold**

Create `tuishark/src/ai/mod.rs`:

```rust
pub mod context;
pub mod model;
pub mod worker;
```

- [ ] **Step 3: Register AI module in main.rs**

Add `mod ai;` after `mod app;` (line 1 area):

```rust
mod ai;
```

- [ ] **Step 4: Verify it compiles**

Run: `cd tuishark && cargo check 2>&1 | head -20`

Expected: Compilation errors about missing `context`, `model`, `worker` modules. Create empty placeholder files:

Create `tuishark/src/ai/context.rs`:
```rust
```

Create `tuishark/src/ai/model.rs`:
```rust
```

Create `tuishark/src/ai/worker.rs`:
```rust
```

Run: `cd tuishark && cargo check 2>&1 | tail -5`

Expected: Compiles successfully (warnings about unused modules OK).

- [ ] **Step 5: Commit**

```bash
git add tuishark/Cargo.toml tuishark/Cargo.lock tuishark/src/main.rs tuishark/src/ai/
git commit -m "feat(ai): add ureq dependency and AI module scaffold (#41)"
```

---

### Task 2: AiConfig with tests

**Files:**
- Create: `tuishark/src/config/ai.rs`
- Modify: `tuishark/src/config/mod.rs:1-4, 6-11, 14-25, 27-39`

- [ ] **Step 1: Write failing test**

Create `tuishark/src/config/ai.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiConfig {
    pub enabled: bool,
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    pub timeout_ms: u64,
    pub max_raw_bytes: usize,
    pub cache_size: usize,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: "http://localhost:8100/v1".into(),
            api_key: String::new(),
            model: "mistralai/Ministral-3-8B-Instruct-2512".into(),
            timeout_ms: 30_000,
            max_raw_bytes: 512,
            cache_size: 32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values() {
        let config = AiConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.base_url, "http://localhost:8100/v1");
        assert_eq!(config.api_key, "");
        assert_eq!(config.timeout_ms, 30_000);
        assert_eq!(config.max_raw_bytes, 512);
        assert_eq!(config.cache_size, 32);
    }

    #[test]
    fn partial_toml_fills_defaults() {
        let toml = r#"
enabled = true
model = "gpt-4"
"#;
        let config: AiConfig = toml::from_str(toml).unwrap();
        assert!(config.enabled);
        assert_eq!(config.model, "gpt-4");
        assert_eq!(config.base_url, "http://localhost:8100/v1");
        assert_eq!(config.timeout_ms, 30_000);
        assert_eq!(config.cache_size, 32);
    }

    #[test]
    fn full_toml_parses() {
        let toml = r#"
enabled = true
base_url = "https://api.example.com/v1"
api_key = "sk-test"
model = "custom-model"
timeout_ms = 60000
max_raw_bytes = 1024
cache_size = 64
"#;
        let config: AiConfig = toml::from_str(toml).unwrap();
        assert!(config.enabled);
        assert_eq!(config.base_url, "https://api.example.com/v1");
        assert_eq!(config.api_key, "sk-test");
        assert_eq!(config.model, "custom-model");
        assert_eq!(config.timeout_ms, 60_000);
        assert_eq!(config.max_raw_bytes, 1024);
        assert_eq!(config.cache_size, 64);
    }

    #[test]
    fn empty_toml_uses_defaults() {
        let config: AiConfig = toml::from_str("").unwrap();
        assert!(!config.enabled);
        assert_eq!(config.cache_size, 32);
    }

    #[test]
    fn top_level_config_with_ai_section() {
        use crate::config::Config;
        let toml = r#"
[ai]
enabled = true
model = "test-model"
cache_size = 16
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.ai.enabled);
        assert_eq!(config.ai.model, "test-model");
        assert_eq!(config.ai.cache_size, 16);
        assert!(config.display.auto_scroll); // other defaults preserved
    }

    #[test]
    fn config_without_ai_section_uses_defaults() {
        use crate::config::Config;
        let config: Config = toml::from_str("").unwrap();
        assert!(!config.ai.enabled);
        assert_eq!(config.ai.cache_size, 32);
    }
}
```

- [ ] **Step 2: Wire AiConfig into Config**

In `tuishark/src/config/mod.rs`:

Add module declaration (after line 4 `pub mod theme;`):
```rust
pub mod ai;
```

Add import (after line 11 `use theme::ThemeConfig;`):
```rust
use ai::AiConfig;
```

Add field to Config struct (after line 24 `pub filters: Vec<FilterPreset>,`):
```rust
    pub ai: AiConfig,
```

Add to Default impl (after line 36 `filters: Vec::new(),`):
```rust
            ai: AiConfig::default(),
```

- [ ] **Step 3: Run tests**

Run: `cd tuishark && cargo test config::ai::tests -- --nocapture 2>&1 | tail -15`

Expected: All 6 tests pass.

- [ ] **Step 4: Commit**

```bash
git add tuishark/src/config/ai.rs tuishark/src/config/mod.rs
git commit -m "feat(ai): add AiConfig with TOML parsing and defaults (#41)"
```

---

### Task 3: Action::AiPacketInfo with key binding

**Files:**
- Modify: `tuishark/src/config/keys.rs:8-42, 54-89, 91-128, 141-174`

- [ ] **Step 1: Write failing test**

Add to `tuishark/src/config/keys.rs` in the `#[cfg(test)] mod tests` block (after the last test):

```rust
    #[test]
    fn shift_i_maps_to_ai_packet_info() {
        let config = KeyConfig::default();
        let bindings = KeyBindings::from_config(&config);
        let key = KeyEvent::new(KeyCode::Char('I'), KeyModifiers::SHIFT);
        assert_eq!(bindings.action_for(&key), Some(Action::AiPacketInfo));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd tuishark && cargo test config::keys::tests::shift_i_maps_to_ai_packet_info 2>&1 | tail -5`

Expected: FAIL — `AiPacketInfo` variant does not exist.

- [ ] **Step 3: Add AiPacketInfo to Action enum**

In `tuishark/src/config/keys.rs`, add after `ContainerInfo,` (line 41):

```rust
    AiPacketInfo,
```

- [ ] **Step 4: Add field to KeyConfig**

After `pub container_info: String,` (line 88):

```rust
    pub ai_packet_info: String,
```

- [ ] **Step 5: Add default binding**

In the `Default for KeyConfig` impl, after `container_info: "c".into(),` (line 125):

```rust
            ai_packet_info: "Shift+I".into(),
```

- [ ] **Step 6: Add to KeyBindings entries**

In `KeyBindings::from_config`, add to the entries array after the `ContainerInfo` line (line 173):

```rust
            (Action::AiPacketInfo, &config.ai_packet_info, &defaults.ai_packet_info),
```

- [ ] **Step 7: Run tests**

Run: `cd tuishark && cargo test config::keys::tests -- --nocapture 2>&1 | tail -15`

Expected: All tests pass including the new one.

- [ ] **Step 8: Commit**

```bash
git add tuishark/src/config/keys.rs
git commit -m "feat(ai): add AiPacketInfo action with Shift+I default binding (#41)"
```

---

### Task 4: AI model types with cache tests

**Files:**
- Create: `tuishark/src/ai/model.rs`

- [ ] **Step 1: Write model types and tests**

Write `tuishark/src/ai/model.rs`:

```rust
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
        assert_eq!(
            cache.get_whole(10),
            Some("explanation for packet 10".into())
        );
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
        assert_eq!(
            cache.get_field(10, 2, Some(1)),
            Some("TCP flags explanation".into())
        );
        assert_eq!(cache.get_field(10, 2, Some(0)), None);
    }

    #[test]
    fn cache_layer_level_field() {
        let mut cache = AiCache::new(4);
        cache.insert_field(10, 1, None, "IPv4 layer explanation".into());
        assert_eq!(
            cache.get_field(10, 1, None),
            Some("IPv4 layer explanation".into())
        );
    }

    #[test]
    fn cache_evicts_oldest_when_full() {
        let mut cache = AiCache::new(3);
        cache.insert_whole(1, "pkt 1".into());
        cache.insert_whole(2, "pkt 2".into());
        cache.insert_whole(3, "pkt 3".into());

        // Cache is full. Inserting 4 should evict 1.
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

        // Access packet 1 to refresh it
        let _ = cache.get_whole(1);

        // Insert packet 4 — should evict packet 2 (oldest untouched)
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
                ChatMessage {
                    role: "system".into(),
                    content: "You are helpful.".into(),
                },
                ChatMessage {
                    role: "user".into(),
                    content: "Explain this.".into(),
                },
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
```

- [ ] **Step 2: Run tests**

Run: `cd tuishark && cargo test ai::model::tests -- --nocapture 2>&1 | tail -20`

Expected: All 10 tests pass.

- [ ] **Step 3: Commit**

```bash
git add tuishark/src/ai/model.rs
git commit -m "feat(ai): add AI model types with LRU cache (#41)"
```

---

### Task 5: AI context builder with tests

**Files:**
- Create: `tuishark/src/ai/context.rs`

- [ ] **Step 1: Write context builder and tests**

Write `tuishark/src/ai/context.rs`:

```rust
use serde_json::{json, Value};

use crate::dissect::model::{
    EncMeta, Layer, LinkMeta, PacketDetail, PacketSummary, PflogMeta,
};
use crate::trace::model::ProcessInfo;
use crate::trace::container_store::ContainerInfo;

use super::model::ChatMessage;

const SYSTEM_PROMPT: &str = "\
You are a network packet analysis tutor embedded in TuiShark.\n\
Explain only from the supplied packet context.\n\
Be accurate, concise, and educational.\n\
Prefer protocol facts over speculation.\n\
If information is missing or ambiguous, say what cannot be determined.\n\
Do not invent payload contents that are not present in the supplied fields or bytes.\n\
Connect general networking knowledge to the concrete selected packet.\n\
Structure the answer for a terminal UI.";

const WHOLE_PACKET_PROMPT: &str = "\
Explain this packet at a high level for someone learning networking.\n\
\n\
Answer these questions:\n\
1. What protocol stack and packet type does this represent?\n\
2. What are the source and destination endpoints?\n\
3. What important flags, codes, ports, lengths, or header fields stand out?\n\
4. What does this packet likely mean in the flow?\n\
5. Are there any warnings, anomalies, retransmissions, resets, fragmentation, \
truncation, private/public address notes, or security-relevant observations?";

const FIELD_PROMPT: &str = "\
Explain the selected packet field for someone learning networking.\n\
\n\
Cover:\n\
1. What this field means generally.\n\
2. How to interpret this packet's value.\n\
3. How this field relates to the current packet and connection.\n\
4. Whether the value is normal, suspicious, or context-dependent.";

pub fn build_packet_context(
    summary: &PacketSummary,
    raw: Option<&[u8]>,
    detail: Option<&PacketDetail>,
    max_raw_bytes: usize,
    trace_info: Option<&ProcessInfo>,
    container_info: Option<&ContainerInfo>,
    link_type_name: &str,
) -> Value {
    let mut ctx = json!({
        "index": summary.index,
        "timestamp": summary.timestamp,
        "link_type": link_type_name,
        "source": summary.source,
        "destination": summary.destination,
        "protocol": summary.protocol.to_string(),
        "length": summary.length,
        "original_length": summary.original_length,
        "info": summary.info,
    });

    if let Some(port) = summary.src_port {
        ctx["src_port"] = json!(port);
    }
    if let Some(port) = summary.dst_port {
        ctx["dst_port"] = json!(port);
    }

    if let Some(ref meta) = summary.link_meta {
        match meta {
            LinkMeta::Pflog(pf) => {
                ctx["link_meta"] = json!({
                    "type": "pflog",
                    "action": pf.action.to_string(),
                    "direction": pf.direction.to_string(),
                    "interface": pf.ifname,
                    "rule_number": pf.rule_number,
                });
            }
            LinkMeta::Enc(enc) => {
                ctx["link_meta"] = json!({
                    "type": "enc",
                    "spi": format!("0x{:08x}", enc.spi),
                    "flags": crate::dissect::model::enc_flags_str(enc.flags),
                    "address_family": enc.address_family,
                });
            }
        }
    }

    if let Some(raw_bytes) = raw {
        let cap = raw_bytes.len().min(max_raw_bytes);
        let hex: String = raw_bytes[..cap]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        ctx["raw_hex"] = json!(hex);
        if cap < raw_bytes.len() {
            ctx["raw_hex_truncated"] = json!(true);
        }
    }

    if let Some(detail) = detail {
        let layers: Vec<Value> = detail
            .layers
            .iter()
            .map(|layer| serialize_layer(layer))
            .collect();
        ctx["layers"] = json!(layers);
    }

    if let Some(info) = trace_info {
        ctx["trace"] = json!({
            "process": info.comm_str(),
            "pid": info.pid,
            "uid": info.uid,
        });
    }

    if let Some(ci) = container_info {
        ctx["container"] = json!({
            "netns": ci.netns_inum,
            "device": ci.dev_name_str(),
            "tcp_state": ci.tcp_state_str(),
        });
    }

    ctx
}

fn serialize_layer(layer: &Layer) -> Value {
    let fields: Vec<Value> = layer
        .fields
        .iter()
        .map(|f| {
            json!({
                "name": f.name,
                "value": f.value,
            })
        })
        .collect();
    json!({
        "name": layer.name,
        "fields": fields,
    })
}

pub fn build_field_context(
    detail: &PacketDetail,
    layer_index: usize,
    field_index: Option<usize>,
) -> Value {
    let Some(layer) = detail.layers.get(layer_index) else {
        return json!({});
    };

    let mut ctx = json!({
        "selected_layer": layer.name,
    });

    if let Some(fi) = field_index {
        if let Some(field) = layer.fields.get(fi) {
            ctx["selected_field"] = json!({
                "name": field.name,
                "value": field.value,
            });
        }
    }

    ctx
}

pub fn build_whole_packet_messages(context_json: &str) -> Vec<ChatMessage> {
    vec![
        ChatMessage {
            role: "system".into(),
            content: SYSTEM_PROMPT.into(),
        },
        ChatMessage {
            role: "user".into(),
            content: format!(
                "{WHOLE_PACKET_PROMPT}\n\nPacket context:\n{context_json}"
            ),
        },
    ]
}

pub fn build_field_messages(
    field_context_json: &str,
    packet_context_json: &str,
) -> Vec<ChatMessage> {
    vec![
        ChatMessage {
            role: "system".into(),
            content: SYSTEM_PROMPT.into(),
        },
        ChatMessage {
            role: "user".into(),
            content: format!(
                "{FIELD_PROMPT}\n\nSelected field context:\n{field_context_json}\n\n\
                 Full packet context:\n{packet_context_json}"
            ),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::model::{LayerField, Protocol};

    fn test_summary() -> PacketSummary {
        PacketSummary {
            index: 42,
            timestamp: 1714650000.123456,
            source: "192.168.1.100".into(),
            destination: "93.184.216.34".into(),
            protocol: Protocol::Tcp,
            length: 74,
            original_length: 74,
            info: "54321 → 443 [SYN] Seq=0 Win=65535".into(),
            src_port: Some(54321),
            dst_port: Some(443),
            link_meta: None,
        }
    }

    fn test_detail() -> PacketDetail {
        PacketDetail {
            layers: vec![
                Layer {
                    name: "Ethernet II".into(),
                    fields: vec![
                        LayerField {
                            name: "Source".into(),
                            value: "aa:bb:cc:dd:ee:ff".into(),
                            byte_range: Some((6, 12)),
                        },
                    ],
                },
                Layer {
                    name: "TCP".into(),
                    fields: vec![
                        LayerField {
                            name: "Flags".into(),
                            value: "SYN".into(),
                            byte_range: None,
                        },
                        LayerField {
                            name: "Seq".into(),
                            value: "0".into(),
                            byte_range: None,
                        },
                    ],
                },
            ],
        }
    }

    #[test]
    fn packet_context_basic_fields() {
        let summary = test_summary();
        let ctx = build_packet_context(&summary, None, None, 512, None, None, "Ethernet");
        assert_eq!(ctx["index"], 42);
        assert_eq!(ctx["source"], "192.168.1.100");
        assert_eq!(ctx["protocol"], "TCP");
        assert_eq!(ctx["src_port"], 54321);
        assert_eq!(ctx["dst_port"], 443);
        assert_eq!(ctx["link_type"], "Ethernet");
    }

    #[test]
    fn packet_context_with_layers() {
        let summary = test_summary();
        let detail = test_detail();
        let ctx = build_packet_context(&summary, None, Some(&detail), 512, None, None, "Ethernet");
        let layers = ctx["layers"].as_array().unwrap();
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0]["name"], "Ethernet II");
        assert_eq!(layers[1]["fields"][0]["name"], "Flags");
        assert_eq!(layers[1]["fields"][0]["value"], "SYN");
    }

    #[test]
    fn raw_bytes_capped() {
        let summary = test_summary();
        let raw = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let ctx = build_packet_context(&summary, Some(&raw), None, 3, None, None, "Ethernet");
        assert_eq!(ctx["raw_hex"], "aabbcc");
        assert_eq!(ctx["raw_hex_truncated"], true);
    }

    #[test]
    fn raw_bytes_not_truncated_when_within_limit() {
        let summary = test_summary();
        let raw = vec![0x01, 0x02];
        let ctx = build_packet_context(&summary, Some(&raw), None, 512, None, None, "Ethernet");
        assert_eq!(ctx["raw_hex"], "0102");
        assert!(ctx.get("raw_hex_truncated").is_none());
    }

    #[test]
    fn field_context_with_field() {
        let detail = test_detail();
        let ctx = build_field_context(&detail, 1, Some(0));
        assert_eq!(ctx["selected_layer"], "TCP");
        assert_eq!(ctx["selected_field"]["name"], "Flags");
        assert_eq!(ctx["selected_field"]["value"], "SYN");
    }

    #[test]
    fn field_context_layer_only() {
        let detail = test_detail();
        let ctx = build_field_context(&detail, 0, None);
        assert_eq!(ctx["selected_layer"], "Ethernet II");
        assert!(ctx.get("selected_field").is_none());
    }

    #[test]
    fn whole_packet_messages_structure() {
        let msgs = build_whole_packet_messages("{}");
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].role, "system");
        assert!(msgs[0].content.contains("network packet analysis tutor"));
        assert_eq!(msgs[1].role, "user");
        assert!(msgs[1].content.contains("protocol stack"));
    }

    #[test]
    fn field_messages_structure() {
        let msgs = build_field_messages("{\"selected_layer\":\"TCP\"}", "{}");
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].role, "system");
        assert_eq!(msgs[1].role, "user");
        assert!(msgs[1].content.contains("selected_layer"));
    }

    #[test]
    fn packet_context_no_ports() {
        let mut summary = test_summary();
        summary.src_port = None;
        summary.dst_port = None;
        summary.protocol = Protocol::Icmp;
        let ctx = build_packet_context(&summary, None, None, 512, None, None, "Ethernet");
        assert!(ctx.get("src_port").is_none());
        assert!(ctx.get("dst_port").is_none());
    }

    #[test]
    fn packet_context_with_trace_info() {
        let summary = test_summary();
        let mut info = ProcessInfo {
            pid: 1234,
            uid: 1000,
            comm: [0u8; 16],
        };
        info.comm[..4].copy_from_slice(b"curl");
        let ctx = build_packet_context(&summary, None, None, 512, Some(&info), None, "Ethernet");
        assert_eq!(ctx["trace"]["process"], "curl");
        assert_eq!(ctx["trace"]["pid"], 1234);
        assert_eq!(ctx["trace"]["uid"], 1000);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cd tuishark && cargo test ai::context::tests -- --nocapture 2>&1 | tail -20`

Expected: All 10 tests pass.

- [ ] **Step 3: Commit**

```bash
git add tuishark/src/ai/context.rs
git commit -m "feat(ai): add packet context builder with prompts (#41)"
```

---

### Task 6: AI worker

**Files:**
- Create: `tuishark/src/ai/worker.rs`

- [ ] **Step 1: Write the AI worker**

Write `tuishark/src/ai/worker.rs`:

```rust
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
```

- [ ] **Step 2: Verify it compiles**

Run: `cd tuishark && cargo check 2>&1 | tail -5`

Expected: Compiles successfully.

- [ ] **Step 3: Commit**

```bash
git add tuishark/src/ai/worker.rs
git commit -m "feat(ai): add background AI worker with ureq HTTP client (#41)"
```

---

### Task 7: AI overlay widget

**Files:**
- Create: `tuishark/src/ui/dialogs/ai_overlay.rs`
- Modify: `tuishark/src/ui/dialogs/mod.rs:1-10`

- [ ] **Step 1: Add module declaration**

In `tuishark/src/ui/dialogs/mod.rs`, add after the last `pub mod` line:

```rust
pub mod ai_overlay;
```

- [ ] **Step 2: Write the overlay widget**

Create `tuishark/src/ui/dialogs/ai_overlay.rs`:

```rust
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Widget, Wrap},
};

use crate::ai::model::{AiOverlayFocus, AiState};
use crate::dissect::model::PacketDetail;
use crate::ui::theme::Theme;
use crate::ui::widgets::detail_tree::DetailTree;

pub struct AiOverlay<'a> {
    detail: Option<&'a PacketDetail>,
    expanded: &'a [bool],
    selected_layer: Option<usize>,
    selected_field: Option<usize>,
    detail_scroll_offset: usize,
    focus: AiOverlayFocus,
    ai_state: &'a AiState,
    right_scroll: usize,
    theme: &'a Theme,
}

impl<'a> AiOverlay<'a> {
    pub fn new(
        detail: Option<&'a PacketDetail>,
        expanded: &'a [bool],
        selected_layer: Option<usize>,
        selected_field: Option<usize>,
        detail_scroll_offset: usize,
        focus: AiOverlayFocus,
        ai_state: &'a AiState,
        right_scroll: usize,
        theme: &'a Theme,
    ) -> Self {
        Self {
            detail,
            expanded,
            selected_layer,
            selected_field,
            detail_scroll_offset,
            focus,
            ai_state,
            right_scroll,
            theme,
        }
    }
}

impl Widget for AiOverlay<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let width = (area.width as u32 * 90 / 100) as u16;
        let height = (area.height as u32 * 90 / 100) as u16;
        let width = width.max(40).min(area.width);
        let height = height.max(10).min(area.height);
        let x = area.x + area.width.saturating_sub(width) / 2;
        let y = area.y + area.height.saturating_sub(height) / 2;
        let dialog_area = Rect::new(x, y, width, height);

        Clear.render(dialog_area, buf);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.overlay))
            .title(" AI Packet Info ")
            .title_style(Style::default().fg(self.theme.blue).add_modifier(Modifier::BOLD))
            .style(Style::default().bg(self.theme.base));

        let inner = block.inner(dialog_area);
        block.render(dialog_area, buf);

        if inner.height < 3 || inner.width < 20 {
            return;
        }

        // Split: main content + help bar
        let vert = Layout::vertical([
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(inner);

        let content_area = vert[0];
        let help_area = vert[1];

        // Split content: left (detail tree) | right (explanation)
        let horiz = Layout::horizontal([
            Constraint::Percentage(40),
            Constraint::Percentage(60),
        ])
        .split(content_area);

        let left_area = horiz[0];
        let right_area = horiz[1];

        // Left pane: detail tree
        let left_focused = matches!(self.focus, AiOverlayFocus::Left);
        let left_block = Block::default()
            .borders(Borders::RIGHT)
            .border_style(Style::default().fg(self.theme.surface1))
            .style(Style::default().bg(self.theme.base));
        let left_inner = left_block.inner(left_area);
        left_block.render(left_area, buf);

        let detail_tree = DetailTree::new(
            self.detail,
            self.expanded,
            self.selected_layer,
            self.selected_field,
            self.theme,
            left_focused,
            self.detail_scroll_offset,
        );
        detail_tree.render(left_inner, buf);

        // Right pane: explanation + status
        let right_focused = matches!(self.focus, AiOverlayFocus::Right);
        let right_vert = Layout::vertical([
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(right_area);

        let explanation_area = right_vert[0];
        let status_area = right_vert[1];

        // Explanation text
        let (text, text_style) = match self.ai_state {
            AiState::Idle => ("".to_string(), Style::default().fg(self.theme.subtext0)),
            AiState::Loading { .. } => (
                "Requesting explanation...".to_string(),
                Style::default().fg(self.theme.subtext0),
            ),
            AiState::Ready(ref s) => (s.clone(), Style::default().fg(self.theme.text)),
            AiState::Error(ref s) => (
                s.clone(),
                Style::default().fg(self.theme.red),
            ),
            AiState::Unconfigured => (
                "AI not configured.\n\nAdd [ai] section to ~/.config/tuishark/config.toml:\n\n\
                 [ai]\n\
                 enabled = true\n\
                 base_url = \"http://localhost:8100/v1\"\n\
                 model = \"your-model\""
                    .to_string(),
                Style::default().fg(self.theme.yellow),
            ),
        };

        let highlight = if right_focused {
            Style::default().fg(self.theme.blue)
        } else {
            Style::default().fg(self.theme.surface1)
        };

        let right_block = Block::default()
            .borders(Borders::NONE)
            .style(Style::default().bg(self.theme.base));

        let para = Paragraph::new(text)
            .style(text_style)
            .block(right_block)
            .wrap(Wrap { trim: false })
            .scroll((self.right_scroll as u16, 0));
        para.render(explanation_area, buf);

        // Status dot
        let (dot_color, status_text) = match self.ai_state {
            AiState::Idle => (self.theme.surface1, ""),
            AiState::Loading { .. } => (self.theme.green, "Requesting..."),
            AiState::Ready(_) => (self.theme.green, "Explanation ready"),
            AiState::Error(_) => (self.theme.red, "Request failed"),
            AiState::Unconfigured => (self.theme.red, "AI not configured"),
        };

        let status_line = Line::from(vec![
            Span::styled(" ● ", Style::default().fg(dot_color)),
            Span::styled(status_text, Style::default().fg(self.theme.subtext0)),
        ]);
        buf.set_line(status_area.x, status_area.y, &status_line, status_area.width);

        // Help bar
        let left_hl = if left_focused { self.theme.blue } else { self.theme.subtext0 };
        let right_hl = if right_focused { self.theme.blue } else { self.theme.subtext0 };

        let help_line = Line::from(vec![
            Span::styled(" Space", Style::default().fg(self.theme.lavender)),
            Span::styled(": explain  ", Style::default().fg(self.theme.subtext0)),
            Span::styled("Enter", Style::default().fg(self.theme.lavender)),
            Span::styled(": expand  ", Style::default().fg(self.theme.subtext0)),
            Span::styled("←", Style::default().fg(left_hl)),
            Span::styled("/", Style::default().fg(self.theme.subtext0)),
            Span::styled("→", Style::default().fg(right_hl)),
            Span::styled(": pane  ", Style::default().fg(self.theme.subtext0)),
            Span::styled("ö/ä", Style::default().fg(self.theme.lavender)),
            Span::styled(": packet  ", Style::default().fg(self.theme.subtext0)),
            Span::styled("Esc", Style::default().fg(self.theme.lavender)),
            Span::styled(": close", Style::default().fg(self.theme.subtext0)),
        ]);
        buf.set_line(help_area.x, help_area.y, &help_line, help_area.width);
    }
}
```

- [ ] **Step 3: Check if DetailTree::new exists or if direct construction is needed**

The current `DetailTree` struct has pub fields. Check if there is a `new()` constructor.

Run: `grep -n "pub fn new\|impl.*DetailTree" tuishark/src/ui/widgets/detail_tree.rs | head -5`

If no `new()` exists, add one to `tuishark/src/ui/widgets/detail_tree.rs`:

```rust
impl<'a> DetailTree<'a> {
    pub fn new(
        detail: Option<&'a PacketDetail>,
        expanded: &'a [bool],
        selected_layer: Option<usize>,
        selected_field: Option<usize>,
        theme: &'a Theme,
        focused: bool,
        scroll_offset: usize,
    ) -> Self {
        Self {
            detail,
            expanded,
            selected_layer,
            selected_field,
            theme,
            focused,
            scroll_offset,
        }
    }
}
```

If a `new()` already exists with a different signature, adapt the `AiOverlay` to match.

- [ ] **Step 4: Verify it compiles**

Run: `cd tuishark && cargo check 2>&1 | tail -10`

Expected: Compiles (may have warnings about unused imports — these will resolve when app.rs integrates).

- [ ] **Step 5: Commit**

```bash
git add tuishark/src/ui/dialogs/ai_overlay.rs tuishark/src/ui/dialogs/mod.rs tuishark/src/ui/widgets/detail_tree.rs
git commit -m "feat(ai): add AI overlay dialog widget (#41)"
```

---

### Task 8: App integration — state, key handling, drain, render

**Files:**
- Modify: `tuishark/src/app.rs`

This is the largest task. It wires everything together.

- [ ] **Step 1: Add imports to app.rs**

Add these imports near the top of `app.rs` (after the existing `use crate::` imports, around line 56):

```rust
use crate::ai::model::{AiCache, AiOverlayFocus, AiRequest, AiRequestKind, AiState};
use crate::ai::context::{build_packet_context, build_field_context, build_whole_packet_messages, build_field_messages};
use crate::ai::worker::AiWorker;
use crate::ui::dialogs::ai_overlay::AiOverlay;
```

- [ ] **Step 2: Add state fields to App struct**

Add after the `container_store: ContainerStore,` field (around line 210):

```rust
    // AI packet info overlay (#41)
    show_ai_overlay: bool,
    ai_overlay_focus: AiOverlayFocus,
    ai_right_scroll: usize,
    ai_state: AiState,
    ai_cache: AiCache,
    ai_worker: Option<AiWorker>,
    ai_seq: usize,
```

- [ ] **Step 3: Initialize fields in App::new()**

In the `App::new()` constructor, add initialization for the new fields. Find where other fields are initialized (look for `container_store: ContainerStore::default(),`) and add after:

```rust
            show_ai_overlay: false,
            ai_overlay_focus: AiOverlayFocus::Left,
            ai_right_scroll: 0,
            ai_state: AiState::Idle,
            ai_cache: AiCache::new(config.ai.cache_size),
            ai_worker: None,
            ai_seq: 0,
```

- [ ] **Step 4: Add drain_ai_results() to main loop**

In the `run()` method, after `self.drain_ipinfo_results();` (line 443), add:

```rust
            self.drain_ai_results();
```

- [ ] **Step 5: Implement drain_ai_results()**

Add this method to `impl App` (place near other `drain_*` methods):

```rust
    fn drain_ai_results(&mut self) {
        let Some(ref worker) = self.ai_worker else {
            return;
        };
        while let Some(resp) = worker.try_recv() {
            let is_current = self.selected_packet == Some(resp.packet_index);
            match resp.result {
                Ok(text) => {
                    match &resp.kind {
                        AiRequestKind::WholePacket => {
                            self.ai_cache.insert_whole(resp.packet_index, text.clone());
                            if is_current {
                                self.ai_state = AiState::Ready(text);
                                self.ai_right_scroll = 0;
                            }
                        }
                        AiRequestKind::Field { layer_index, field_index } => {
                            self.ai_cache.insert_field(
                                resp.packet_index,
                                *layer_index,
                                *field_index,
                                text.clone(),
                            );
                            if is_current {
                                self.ai_state = AiState::Ready(text);
                                self.ai_right_scroll = 0;
                            }
                        }
                    }
                }
                Err(msg) => {
                    if is_current {
                        self.ai_state = AiState::Error(msg);
                    }
                }
            }
        }
    }
```

- [ ] **Step 6: Add AI overlay to key handling priority chain**

In `handle_key()`, add the AI overlay check **after** the `show_container_dialog` block (after line 1066) and **before** the `show_export_dialog` block:

```rust
        if self.show_ai_overlay {
            self.handle_ai_overlay_key(key);
            return;
        }
```

- [ ] **Step 7: Implement handle_ai_overlay_key()**

Add this method to `impl App`:

```rust
    fn handle_ai_overlay_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.show_ai_overlay = false;
            }
            KeyCode::Left => {
                self.ai_overlay_focus = AiOverlayFocus::Left;
            }
            KeyCode::Right => {
                self.ai_overlay_focus = AiOverlayFocus::Right;
            }
            KeyCode::Up => match self.ai_overlay_focus {
                AiOverlayFocus::Left => {
                    self.handle_detail_tree_action(Action::MoveUp);
                }
                AiOverlayFocus::Right => {
                    self.ai_right_scroll = self.ai_right_scroll.saturating_sub(1);
                }
            },
            KeyCode::Down => match self.ai_overlay_focus {
                AiOverlayFocus::Left => {
                    self.handle_detail_tree_action(Action::MoveDown);
                }
                AiOverlayFocus::Right => {
                    self.ai_right_scroll = self.ai_right_scroll.saturating_add(1);
                }
            },
            KeyCode::PageUp => {
                if matches!(self.ai_overlay_focus, AiOverlayFocus::Right) {
                    self.ai_right_scroll = self.ai_right_scroll.saturating_sub(10);
                }
            }
            KeyCode::PageDown => {
                if matches!(self.ai_overlay_focus, AiOverlayFocus::Right) {
                    self.ai_right_scroll = self.ai_right_scroll.saturating_add(10);
                }
            }
            KeyCode::Enter => {
                if matches!(self.ai_overlay_focus, AiOverlayFocus::Left) {
                    self.handle_detail_tree_action(Action::ToggleExpand);
                }
            }
            KeyCode::Char(' ') => {
                self.fire_ai_request();
            }
            _ => {
                if let Some(action) = self.key_bindings.action_for(&key) {
                    match action {
                        Action::NextPacket => {
                            self.handle_packet_table_action(Action::MoveDown);
                            self.on_ai_packet_changed();
                        }
                        Action::PrevPacket => {
                            self.handle_packet_table_action(Action::MoveUp);
                            self.on_ai_packet_changed();
                        }
                        _ => {}
                    }
                }
            }
        }
    }
```

- [ ] **Step 8: Add AiPacketInfo action to the global shortcut match**

In `handle_key()`, find the global action match block (around line 1110). Add a case for `AiPacketInfo` alongside the other dialog toggles (e.g., after `Action::ContainerInfo`):

```rust
                Action::AiPacketInfo => {
                    self.open_ai_overlay();
                    return;
                }
```

- [ ] **Step 9: Implement open_ai_overlay(), fire_ai_request(), on_ai_packet_changed()**

Add these methods to `impl App`:

```rust
    fn open_ai_overlay(&mut self) {
        if !self.config.ai.enabled {
            self.ai_state = AiState::Unconfigured;
            self.show_ai_overlay = true;
            self.ai_overlay_focus = AiOverlayFocus::Left;
            return;
        }

        if self.ai_worker.is_none() {
            self.ai_worker = Some(AiWorker::spawn(self.config.ai.clone()));
        }

        self.show_ai_overlay = true;
        self.ai_overlay_focus = AiOverlayFocus::Left;
        self.ai_right_scroll = 0;

        // Check cache or auto-request for current packet
        self.on_ai_packet_changed();
    }

    fn on_ai_packet_changed(&mut self) {
        let Some(packet_index) = self.selected_packet else {
            self.ai_state = AiState::Idle;
            return;
        };

        if let Some(text) = self.ai_cache.get_whole(packet_index) {
            self.ai_state = AiState::Ready(text);
            self.ai_right_scroll = 0;
            return;
        }

        // Auto-request whole-packet explanation
        self.fire_ai_whole_packet(packet_index);
    }

    fn fire_ai_request(&mut self) {
        let Some(packet_index) = self.selected_packet else {
            return;
        };

        if !self.config.ai.enabled {
            self.ai_state = AiState::Unconfigured;
            return;
        }

        if self.ai_worker.is_none() {
            self.ai_worker = Some(AiWorker::spawn(self.config.ai.clone()));
        }

        let kind = match (self.selected_layer, self.selected_field) {
            (Some(layer), field) => AiRequestKind::Field {
                layer_index: layer,
                field_index: field,
            },
            _ => AiRequestKind::WholePacket,
        };

        // Check cache
        match &kind {
            AiRequestKind::WholePacket => {
                if let Some(text) = self.ai_cache.get_whole(packet_index) {
                    self.ai_state = AiState::Ready(text);
                    self.ai_right_scroll = 0;
                    return;
                }
            }
            AiRequestKind::Field { layer_index, field_index } => {
                if let Some(text) = self.ai_cache.get_field(
                    packet_index,
                    *layer_index,
                    *field_index,
                ) {
                    self.ai_state = AiState::Ready(text);
                    self.ai_right_scroll = 0;
                    return;
                }
            }
        }

        // Build context and send
        let context_json = self.build_ai_context(packet_index);
        let messages = match &kind {
            AiRequestKind::WholePacket => {
                build_whole_packet_messages(&context_json)
            }
            AiRequestKind::Field { layer_index, field_index } => {
                let field_ctx = self.detail.as_ref().map(|d| {
                    build_field_context(d, *layer_index, *field_index)
                });
                let field_json = field_ctx
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "{}".into());
                build_field_messages(&field_json, &context_json)
            }
        };

        self.ai_seq += 1;
        let seq = self.ai_seq;

        if let Some(ref worker) = self.ai_worker {
            worker.request(AiRequest {
                packet_index,
                seq,
                kind,
                messages,
            });
        }

        self.ai_state = AiState::Loading { seq };
        self.ai_right_scroll = 0;
    }

    fn fire_ai_whole_packet(&mut self, packet_index: usize) {
        if self.ai_worker.is_none() {
            return;
        }

        let context_json = self.build_ai_context(packet_index);
        let messages = build_whole_packet_messages(&context_json);

        self.ai_seq += 1;
        let seq = self.ai_seq;

        if let Some(ref worker) = self.ai_worker {
            worker.request(AiRequest {
                packet_index,
                seq,
                kind: AiRequestKind::WholePacket,
                messages,
            });
        }

        self.ai_state = AiState::Loading { seq };
        self.ai_right_scroll = 0;
    }

    fn build_ai_context(&self, packet_index: usize) -> String {
        let summary = self.store.get(packet_index);
        let raw = self.store.get_raw(packet_index);
        let trace_info = self.trace_store.get(packet_index);
        let container_info = self.container_store.get(packet_index);
        let link_type_name = format!("{:?}", self.store.link_type());

        if let Some(summary) = summary {
            let ctx = build_packet_context(
                summary,
                raw,
                self.detail.as_ref(),
                self.config.ai.max_raw_bytes,
                trace_info,
                container_info,
                &link_type_name,
            );
            ctx.to_string()
        } else {
            "{}".into()
        }
    }
```

- [ ] **Step 10: Add AI overlay rendering**

In the `render()` method, add after the trace overlay rendering (after line 890 `}`) and **before** the dialog overlay chain comment:

```rust
        if self.show_ai_overlay {
            let overlay = AiOverlay::new(
                self.detail.as_ref(),
                &self.expanded_layers,
                self.selected_layer,
                self.selected_field,
                self.detail_scroll_offset,
                self.ai_overlay_focus,
                &self.ai_state,
                self.ai_right_scroll,
                &self.theme,
            );
            frame.render_widget(overlay, frame.area());
        }
```

Note: Position this so the AI overlay renders **above** the trace overlay but **below** the dialog overlays (help, quit_confirm, stats, etc.) in the priority chain. Place it right before the dialog overlay block that starts with `if self.show_help_dialog`.

- [ ] **Step 11: Verify it compiles**

Run: `cd tuishark && cargo check 2>&1 | tail -10`

Fix any compilation errors. Common issues:
- Missing `use` for `AiOverlayFocus` in the right place
- `container_store.get()` may return a different type — match the actual signature
- DetailTree `new()` constructor signature may need adjustment

- [ ] **Step 12: Run all tests**

Run: `cd tuishark && cargo test 2>&1 | tail -20`

Expected: All existing tests still pass + new AI tests pass.

- [ ] **Step 13: Commit**

```bash
git add tuishark/src/app.rs
git commit -m "feat(ai): integrate AI overlay into app — state, keys, drain, render (#41)"
```

---

### Task 9: Manual testing and polish

**Files:** None (testing only)

- [ ] **Step 1: Build release**

Run: `cd tuishark && cargo build 2>&1 | tail -5`

Expected: Builds successfully.

- [ ] **Step 2: Test without AI config**

Run tuishark on a pcap file. Press `Shift+I`.

Expected: Overlay opens showing "AI not configured" with red dot. `Esc` closes it.

- [ ] **Step 3: Test with AI config**

Create/update `~/.config/tuishark/config.toml`:

```toml
[ai]
enabled = true
base_url = "http://localhost:8100/v1"
model = "mistralai/Ministral-3-8B-Instruct-2512"
```

Run tuishark on a pcap file. Select a packet. Press `Shift+I`.

Expected:
- Overlay opens with two-column layout
- Left pane shows packet detail tree
- Right pane shows "Requesting..." with green dot
- After response: explanation text with green "Explanation ready" dot

- [ ] **Step 4: Test overlay navigation**

In the overlay:
- `Left`/`Right` switches focus (visual highlight changes)
- `Up`/`Down` in left pane navigates detail tree
- `Up`/`Down` in right pane scrolls explanation
- `Enter` in left pane expands/collapses layers
- `Space` fires AI request for selected field
- `ö`/`ä` navigates to prev/next packet, triggers new explanation
- `Esc` closes overlay

- [ ] **Step 5: Test cache**

- Open overlay, get explanation for packet N
- Navigate away with `ä`, get explanation for packet N+1
- Navigate back with `ö` — packet N should show cached result instantly (no request)

- [ ] **Step 6: Test error states**

- Stop the AI server, press `Space` — should show red dot with error message
- Set invalid `base_url`, press `Shift+I` — should show red dot with connection error

- [ ] **Step 7: Commit any polish fixes**

```bash
git add -u
git commit -m "fix(ai): polish AI overlay after manual testing (#41)"
```

---

## Post-Implementation

After all tasks complete:
1. Run `doc-writer` to document the AI overlay feature
2. Run `gitlab-workflow` to create branch, commit, and MR
3. Three-reviewer MR review per project workflow

---
title: "AI Packet Learning Overlay Design"
date: 2026-05-02
author: agent
status: draft
related_issues: [41]
related_mrs: []
---

## Overview

`Shift+I` opens a two-column modal overlay for AI-assisted packet explanation. Left pane shows the shared detail tree (layers/fields). Right pane shows AI explanation text with a status indicator at the bottom. Uses an OpenAI-compatible `/chat/completions` endpoint via `ureq` in a background thread.

Not a free-form chat. Provides contextual explanations for the selected packet and, on demand, for selected fields/layers.

## Configuration

Add `[ai]` section to `~/.config/tuishark/config.toml`:

```toml
[ai]
enabled = false
base_url = "http://localhost:8100/v1"
api_key = ""
model = "mistralai/Ministral-3-8B-Instruct-2512"
timeout_ms = 30000
max_raw_bytes = 512
cache_size = 32
```

- `AiConfig` struct in `config/ai.rs` with `#[serde(default)]` for all fields.
- `api_key` may be empty for local models.
- `cache_size` controls LRU cache capacity (number of packets whose explanations are retained).

## Module Structure

```
tuishark/src/
  config/ai.rs          — AiConfig struct with serde defaults
  ai/
    mod.rs              — re-exports
    context.rs          — packet context JSON builder (whole-packet + field-level)
    worker.rs           — background thread, ureq POST, mpsc channels
    model.rs            — AiRequest, AiResponse, AiState, AiCache (LRU)
  ui/dialogs/
    ai_overlay.rs       — two-column Widget, status dot rendering
```

## Threading Model

Same pattern as `DissectWorker`:

- `mpsc::channel<AiRequest>` for outbound requests (packet context JSON + prompt type).
- `mpsc::channel<AiResponse>` for inbound responses (text or error string).
- `Arc<AtomicUsize>` monotonic sequence number for stale request skipping.
- Worker thread loops on `request_rx.recv()`, skips stale seq, calls `ureq::post()` (blocks worker thread only), sends result.
- Main loop calls `drain_ai_results()` alongside existing drains (capture, deep dissect, path, ipinfo).

## HTTP Client

`ureq` (sync, blocking) — lightweight, no async runtime needed. Runs inside the worker thread. Single POST per request to `/chat/completions`. Timeout set from `AiConfig::timeout_ms`.

## State Management

### App State

- `show_ai_overlay: bool` — overlay visibility.
- `ai_overlay_focus: AiOverlayFocus` — enum `Left | Right`, which pane has focus.
- `ai_right_scroll: usize` — scroll offset for right pane.
- `ai_state: AiState` — current right-pane state.
- `ai_cache: AiCache` — LRU cache of explanations.
- `ai_worker: Option<AiWorker>` — spawned on first use when `ai.enabled = true`.

### Detail Tree State (shared)

The overlay left pane shares the app's existing detail tree state: `selected_layer`, `selected_field`, `expanded`, `scroll_offset`. No duplication. Closing the overlay preserves the user's position. Packet navigation via `ö`/`ä` updates shared state (same precedent as eBPF trace overlay).

### AiState Enum

```
Idle          — no request in flight, no result to show
Loading(seq)  — request in flight, show "Requesting explanation..."
Ready(String) — explanation text received
Error(String) — request failed, timeout, or invalid response
Unconfigured  — AI not enabled in config
```

### AiCache (LRU)

- `HashMap<usize, PacketAiEntry>` — keyed by packet store index.
- `VecDeque<usize>` — access order for LRU eviction.
- `PacketAiEntry`: whole-packet explanation (`Option<String>`) + field explanations (`HashMap<(usize, usize), String>` keyed by `(layer_index, field_index)`).
- Max capacity from `AiConfig::cache_size` (default 32).
- On cache hit: move entry to back of VecDeque, return cached text.
- On cache miss: evict front of VecDeque if at capacity, insert new entry.

## Key Handling

### New Action

`Action::AiPacketInfo` — default binding `Shift+I`, configurable in `[keys]`.

### Overlay Key Dispatch

When `show_ai_overlay == true`, key handling is intercepted before global dispatch:

| Key | Behavior |
|-----|----------|
| `Esc` | Close overlay |
| `Left` / `Right` | Switch `ai_overlay_focus` between Left and Right |
| `Up` / `Down` | If Left focused: navigate detail tree (shared state). If Right focused: scroll explanation text. |
| `Enter` | If Left focused: expand/collapse layer (unchanged behavior). |
| `Space` | Fire AI request for currently selected layer or field. |
| `ö` / `ä` | Navigate to prev/next packet (shared state, triggers cache lookup or new request). |

`Up`/`Down` in overlay never walk the outer packet list.

### Dialog Priority

Insert after `container_dialog`:

```
help > quit_confirm > stats > ipinfo > container > ai_overlay > export > save > open > preset > interface
```

## Overlay Layout

Two-column modal, sized to ~90% of terminal area:

```
+--[ AI Packet Info ]----------------------------------------------+
|                          |                                        |
|  Layer: Ethernet II      |  This is a TCP SYN packet initiating   |
|    Source: aa:bb:cc...   |  a three-way handshake from ...        |
|    Dest: dd:ee:ff...     |                                        |
|  Layer: IPv4             |  The source 192.168.1.100 is a         |
|  > Layer: TCP            |  private RFC1918 address ...            |
|    Source Port: 54321    |                                        |
|    Dest Port: 443        |  Notable fields:                       |
|    Flags: SYN            |  - Window size 65535 suggests ...      |
|    Seq: 0                |                                        |
|    ...                   |                                        |
|                          |                                        |
|                          |  ● Explanation ready                   |
+------------------------------------------------------------------+
|  Space: explain  Enter: expand  ←→: switch pane  Esc: close      |
+------------------------------------------------------------------+
```

- Left pane: reuses `DetailTree` widget rendering with shared state.
- Right pane: `Paragraph` widget with scroll, plus status line at bottom.
- Status line: green `●` for ok/loading states, red `●` for error/unconfigured states.
- Help bar at bottom showing available keys.

## Right Pane Status Indicator

Bottom line of right pane:

| State | Dot | Text |
|-------|-----|------|
| `Idle` | — | (empty) |
| `Loading` | green `●` | "Requesting explanation..." |
| `Ready` | green `●` | "Explanation ready" |
| `Error(msg)` | red `●` | Error message (e.g., "Connection refused", "Timeout after 30s") |
| `Unconfigured` | red `●` | "AI not configured — add [ai] section to config.toml" |

## Packet Context (Sent to Model)

JSON object built from available data:

```json
{
  "index": 42,
  "timestamp": 1714650000.123456,
  "link_type": "Ethernet",
  "source": "192.168.1.100",
  "destination": "93.184.216.34",
  "protocol": "TCP",
  "length": 74,
  "original_length": 74,
  "info": "54321 → 443 [SYN] Seq=0 Win=65535",
  "src_port": 54321,
  "dst_port": 443,
  "link_meta": null,
  "layers": [
    {
      "name": "Ethernet II",
      "fields": [
        {"name": "Source", "value": "aa:bb:cc:dd:ee:ff"},
        {"name": "Destination", "value": "11:22:33:44:55:66"}
      ]
    }
  ],
  "raw_hex": "aabbccdd...",
  "trace": {
    "process": "curl",
    "pid": 1234,
    "uid": 1000
  }
}
```

- `layers` populated from deep dissection when available, otherwise from fast dissection.
- `raw_hex` capped at `max_raw_bytes` bytes.
- `trace` included when eBPF trace data is available for this packet.
- `link_meta` included for pflog/enc packets.

### Field-Level Context

When `Space` is pressed on a specific field, add:

```json
{
  "selected_layer": "TCP",
  "selected_field": {"name": "Flags", "value": "SYN"}
}
```

## Prompts

### System Prompt

```
You are a network packet analysis tutor embedded in TuiShark.
Explain only from the supplied packet context.
Be accurate, concise, and educational.
Prefer protocol facts over speculation.
If information is missing or ambiguous, say what cannot be determined.
Do not invent payload contents that are not present in the supplied fields or bytes.
Connect general networking knowledge to the concrete selected packet.
Structure the answer for a terminal UI.
```

### Whole-Packet Prompt

```
Explain this packet at a high level for someone learning networking.

Answer these questions:
1. What protocol stack and packet type does this represent?
2. What are the source and destination endpoints?
3. What important flags, codes, ports, lengths, or header fields stand out?
4. What does this packet likely mean in the flow?
5. Are there any warnings, anomalies, retransmissions, resets, fragmentation, truncation, private/public address notes, or security-relevant observations?

Packet context:
{packet_context_json}
```

### Field-Level Prompt

```
Explain the selected packet field for someone learning networking.

Cover:
1. What this field means generally.
2. How to interpret this packet's value.
3. How this field relates to the current packet and connection.
4. Whether the value is normal, suspicious, or context-dependent.

Selected field context:
{selected_field_context_json}

Full packet context:
{packet_context_json}
```

## Dependency

Add to `tuishark/Cargo.toml`:

```toml
ureq = { version = "2", features = ["json"] }
```

## Acceptance Criteria

Per issue #41:

- `[ai]` config parses with defaults, remains optional.
- `Shift+I` configurable under `[keys]`.
- Overlay with AI disabled shows unconfigured state (red dot).
- Overlay with AI enabled starts non-blocking whole-packet request.
- Left/Right switches modal focus.
- Up/Down operates within focused pane only.
- `Space` on layer/field starts non-blocking field-level request.
- `ö`/`ä` navigate packets (shared state).
- Overlay Up/Down does not walk outer packet list.
- Failures, timeouts, invalid responses, unconfigured state visible via status dot.
- Raw bytes capped by `max_raw_bytes`.
- LRU cache of size `cache_size` avoids redundant requests.

## Test Plan

- Unit test `[ai]` TOML defaults and partial config parsing.
- Unit test `Shift+I` key parsing and action dispatch.
- Unit test packet context JSON for whole-packet requests.
- Unit test selected-field context JSON for field-level requests.
- Unit test raw-byte cap behavior.
- Unit test OpenAI-compatible response parsing and error formatting.
- Unit test LRU cache insert, hit, eviction.
- UI/input tests for overlay focus, pane-local Up/Down, Space request, Esc close.
- Regression test that overlay Up/Down does not change selected packet.
- Manual test against `http://localhost:8100/v1` with model `mistralai/Ministral-3-8B-Instruct-2512`.

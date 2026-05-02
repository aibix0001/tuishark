---
title: "AI Packet Learning Overlay"
date: 2026-05-02
author: agent
status: active
related_issues: [41]
related_mrs: []
---

## Overview

Optional AI-assisted packet explanation overlay. Press `Shift+I` on a selected packet to open a two-column modal showing the packet detail tree on the left and an AI-generated explanation on the right. Uses any OpenAI-compatible `/chat/completions` endpoint.

## Important Notice

AI-generated explanations are produced by the language model and inference endpoint configured by the user. TuiShark does not ship, host, or endorse any AI model or inference service.

**AI models can hallucinate.** Explanations may contain inaccuracies, fabricated protocol details, or incorrect interpretations. The quality and accuracy of explanations depend entirely on the capabilities of the model you configure. Always verify AI-generated analysis against authoritative protocol documentation when accuracy matters.

Packet metadata (headers, fields, bounded raw bytes) is sent to the configured endpoint. No data is sent to any third-party service unless you explicitly configure an external endpoint.

## Usage

### Opening the overlay

1. Select a packet in the packet list
2. Press `Shift+I` (configurable via `[keys].ai_packet_info`)
3. The overlay opens and automatically requests a whole-packet explanation

### Navigation inside the overlay

| Key | Action |
|-----|--------|
| `Left` / `Right` | Switch focus between detail tree and explanation pane |
| `Up` / `Down` | Navigate detail tree (left pane) or scroll explanation (right pane) |
| `Enter` | Expand/collapse layer in detail tree |
| `Space` | Request AI explanation for selected layer or field |
| `oe` / `ae` | Navigate to previous/next packet (triggers new explanation) |
| `PageUp` / `PageDown` | Scroll explanation pane by 10 lines |
| `Esc` | Close overlay |

### Status indicator

A colored dot at the bottom of the right pane shows request status:

| Dot | Meaning |
|-----|---------|
| (none) | Idle |
| Green | Requesting or explanation ready |
| Red | Error or AI not configured |

## Configuration

Add an `[ai]` section to `~/.config/tuishark/config.toml`:

```toml
[ai]
enabled = true
base_url = "http://localhost:8100/v1"
api_key = ""
model = "mistralai/Ministral-3-8B-Instruct-2512"
timeout_ms = 30000
max_raw_bytes = 512
cache_size = 32
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable AI features |
| `base_url` | `http://localhost:8100/v1` | OpenAI-compatible API base URL |
| `api_key` | `""` | Bearer token (empty for local models) |
| `model` | `mistralai/Ministral-3-8B-Instruct-2512` | Model identifier |
| `timeout_ms` | `30000` | HTTP read timeout in milliseconds |
| `max_raw_bytes` | `512` | Max raw packet bytes sent to model (hex-encoded) |
| `cache_size` | `32` | Number of packets whose explanations are cached (LRU) |

The `[ai]` section is entirely optional. Without it, pressing `Shift+I` shows a setup guide.

## Technical Details

### Architecture

- **Config:** `config/ai.rs` — `AiConfig` struct with `#[serde(default)]` for partial TOML
- **Types:** `ai/model.rs` — `AiState` enum, `AiCache` (LRU), request/response types, OpenAI-compatible structs
- **Context:** `ai/context.rs` — builds JSON packet context from summary, raw bytes, detail layers, trace info, container info. Contains system/user prompts.
- **Worker:** `ai/worker.rs` — background `std::thread` with `ureq` HTTP client. Same pattern as `DissectWorker` (mpsc channels, atomic seq for stale-request skipping).
- **UI:** `ui/dialogs/ai_overlay.rs` — two-column ratatui `Widget`. Left pane reuses `DetailTree` widget with shared app state.

### Request flow

1. User presses `Shift+I` or `Space`
2. App checks LRU cache for existing explanation
3. On cache miss: builds packet context JSON, constructs chat messages, sends `AiRequest` via mpsc channel
4. Worker thread POSTs to `/chat/completions`, returns `AiResponse` via result channel
5. Main loop drains results in `drain_ai_results()`, updates cache and `AiState`
6. Overlay renders current `AiState` (Loading/Ready/Error)

### Packet context sent to model

JSON object with: index, timestamp, link_type, source, destination, protocol, length, original_length, info, ports, link metadata (pflog/enc), deep dissection layers/fields, raw hex (capped), trace process info, container info.

### Caching

LRU cache keyed by packet index. Each entry stores one whole-packet explanation plus any field-level explanations. Navigating back to a recently explained packet shows the cached result instantly. Cache size configurable via `[ai].cache_size`.

### Dependencies

- `ureq` 2.x with `json` feature (sync HTTP client, no async runtime needed)

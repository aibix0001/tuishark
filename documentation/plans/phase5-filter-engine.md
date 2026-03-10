---
title: "Phase 5: Display Filter Engine"
date: 2026-03-10
author: agent
status: active
related_issues: [8]
related_mrs: []
---

## Overview

Wireshark-style display filter engine for TuiShark. Users type filter expressions in a persistent filter bar to narrow the packet list to matching packets. The filter operates as a view layer over PacketStore — no packets are deleted, just hidden from display.

## Architecture

### Filter Engine (`filter/`)

Three-module design with no external dependencies:

- **`ast.rs`** — AST types: `Expr` (Compare/Contains/And/Or/Not), `Field`, `CompareOp`, `Value`
- **`parser.rs`** — Tokenizer splits input into tokens, recursive descent parser builds AST. Grammar: `or_expr → and_expr → not_expr → primary (comparison | contains | parenthesized)`
- **`eval.rs`** — Walks AST against `PacketSummary` fields, returns bool match

### Supported Filter Fields

| Field | Type | Description |
|-------|------|-------------|
| `ip.src` | string | Source IP address |
| `ip.dst` | string | Destination IP address |
| `ip.addr` | string | Either source or destination IP |
| `port.src` | integer | Source port (TCP/UDP) |
| `port.dst` | integer | Destination port (TCP/UDP) |
| `port` | integer | Either source or destination port |
| `proto` | string | Protocol name (case-insensitive) |
| `len` | integer | Packet length in bytes |
| `info` | string | Info column text |

### Operators

- Comparison: `==`, `!=`, `>`, `<`, `>=`, `<=`
- String: `contains` (case-insensitive substring)
- Boolean: `and`/`&&`, `or`/`||`, `not`/`!`
- Grouping: parentheses `()`

### UI Integration

- **Filter bar**: New 1-line row between header and packet table in `AppLayout`
- **Activation**: `/` key enters filter edit mode
- **Visual feedback**: Green label when filter active, red on error, blue when editing
- **Status bar**: Shows `FILTER: matched/total` badge when filter is active

### Filtered View Layer

- `filtered_indices: Option<Vec<usize>>` maps display positions to store indices
- Navigation (j/k/g/G/PageUp/PageDown) works in display-position space
- `select_packet()` uses store indices for dissection (deep dissection unaffected)
- Live capture: new packets checked incrementally against active filter
- Filter cleared on file open

## Data Model Changes

- `PacketSummary` gains `src_port: Option<u16>` and `dst_port: Option<u16>` — populated during fast dissection for TCP/UDP packets
- `Protocol` gains `PartialEq` derive and `matches_str()` method for case-insensitive name matching

## Test Coverage

- 14 parser tests: simple comparisons, boolean logic, parentheses, error cases
- 13 evaluator tests: all field types, boolean combinations, edge cases (no-port packets)
- All 57 tests pass including pre-existing tests

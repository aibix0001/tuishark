---
title: "ADR: Technology Stack Selection"
date: 2026-03-10
author: agent
status: active
related_issues: ["#1"]
related_mrs: []
---

## Context

TuiShark needs a technology stack that supports high-performance packet analysis in a terminal environment, with single-binary distribution.

## Decision

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | Rust | Performance, safety, single binary |
| TUI | ratatui + crossterm | Dominant Rust TUI framework, mouse support, async |
| Packet Capture | pcap crate | Mature libpcap bindings, cross-platform |
| Packet Parsing | etherparse (fast) + rtshark (deep, Phase 3) | Zero-copy native parsing for speed, Wireshark-grade dissection on-demand |
| Theme | catppuccin crate | Native ratatui color support |
| Async | tokio | Required for concurrent capture/trace tasks |
| CLI | clap | Standard Rust CLI parsing |

### Two-tier Dissection Strategy

- **Fast path (etherparse)**: Zero-copy parsing for summary fields on every packet
- **Deep path (rtshark, Phase 3)**: Full protocol dissection via tshark subprocess, on-demand per selected packet

## Consequences

- Requires libpcap-dev system dependency for building
- etherparse provides limited protocol support compared to Wireshark; deep dissection deferred to rtshark
- Single binary distribution simplified by Rust's static linking model

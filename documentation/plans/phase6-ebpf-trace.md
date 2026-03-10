---
title: "Phase 6: eBPF Kernel Tracing"
date: 2026-03-10
author: agent
status: draft
related_issues: ["#10"]
related_mrs: []
---

## Overview

Add per-packet kernel-level visibility using eBPF to map network packets to the processes (PID, process name, UID) that sent or received them. The existing "Kernel Trace" placeholder pane (bottom-right) displays process ownership for the selected packet. Works during live capture only.

## Technical Approach

### Why Aya

- Pure Rust eBPF framework — no libbpf/clang dependency at build time
- eBPF programs compile as a separate workspace member (`tuishark-ebpf`)
- Bytecode embedded into main binary via `include_bytes!()`
- Userspace side (`aya` crate) works on stable Rust; eBPF crate needs nightly

### eBPF Programs

Four kprobes for socket-to-process correlation:

| Kprobe | Purpose |
|--------|---------|
| `tcp_sendmsg` | Map outbound TCP to PID/comm |
| `tcp_recvmsg` | Map inbound TCP to PID/comm |
| `udp_sendmsg` | Map outbound UDP to PID/comm |
| `udp_recvmsg` | Map inbound UDP to PID/comm |

Each handler extracts the 5-tuple from `struct sock *` and process info via `bpf_get_current_pid_tgid()` / `bpf_get_current_comm()`, then writes to a shared LRU hash map.

### BPF Map Design

- Type: `BPF_MAP_TYPE_LRU_HASH` (auto-evicting)
- Key: `FlowKey { src_addr: u32, dst_addr: u32, src_port: u16, dst_port: u16, protocol: u8 }`
- Value: `ProcessInfo { pid: u32, uid: u32, comm: [u8; 16] }`
- Max entries: 65536
- IPv4 only in Phase 6; IPv6 as follow-up

### Data Flow

```
Kernel:
  kprobe fires → extract 5-tuple + PID/comm → write to LRU HashMap

Userspace:
  pcap captures packet → etherparse extracts 5-tuple
  → lookup in BPF map → store ProcessInfo in TraceStore
  → Kernel Trace pane renders for selected packet
```

## New Files

### `tuishark-ebpf/` (workspace member)

| File | Purpose |
|------|---------|
| `Cargo.toml` | `bpfel-unknown-none` target, depends on `aya-ebpf` |
| `src/main.rs` | Kprobe handlers, LRU hash map definition |

### `tuishark/src/trace/`

| File | Purpose |
|------|---------|
| `mod.rs` | Public API, `TraceState` enum, re-exports |
| `engine.rs` | `TraceEngine`: load eBPF, attach probes, own map handle |
| `lookup.rs` | `FlowKey` from PacketSummary, map lookup |
| `model.rs` | `FlowKey`, `ProcessInfo` types |
| `store.rs` | `TraceStore`: `HashMap<usize, ProcessInfo>` |

### `tuishark/src/ui/widgets/trace_view.rs`

Renders process info in the Kernel Trace pane.

## Dependencies

### Cargo feature flag

```toml
[features]
default = []
trace = ["aya"]

[dependencies]
aya = { version = "0.13", optional = true }
```

### Build requirements

- `bpf-linker` for compiling eBPF crate
- Nightly Rust for eBPF crate only (main crate stays stable)
- Minimum kernel: 5.8

## CLI Changes

```
--trace       Enable eBPF kernel tracing (requires root or CAP_BPF)
--no-trace    Disable kernel tracing (default)
```

## Integration Points

- `app.rs`: add `trace_engine: Option<TraceEngine>`, `trace_store: TraceStore`, `trace_enabled: bool`
- `app.rs drain_capture_packets()`: lookup 5-tuple in BPF map after each packet
- `app.rs render()`: replace placeholder with `TraceView` widget
- `Pane` enum: add `KernelTrace` variant for Tab navigation
- `main.rs`: add `--trace` flag, init `TraceEngine` with permission check

## Graceful Fallback

1. `--trace` not passed → "Kernel tracing disabled (use --trace)"
2. `--trace` but no permissions → "eBPF unavailable: {reason}", app continues
3. Some kprobes fail → partial mode, show active probes in pane header
4. File mode → "N/A (file mode)"
5. Built without `trace` feature → "Not compiled with eBPF support"

## Kernel Trace Pane Content

```
 Kernel Trace
 PID:      1234
 Process:  curl
 UID:      1000
 Direction: Outbound (sendmsg)
```

When no info: "No process info for this packet (non-TCP/UDP or map entry expired)"

## Acceptance Criteria

- [ ] `cargo build` succeeds without `trace` feature
- [ ] `cargo build --features trace` compiles with eBPF support
- [ ] `--trace -i eth0` (as root) shows PID/process for TCP/UDP packets
- [ ] Without `--trace`, pane shows disabled message
- [ ] Without root, shows permission error, app continues
- [ ] File mode shows "N/A" regardless of `--trace`
- [ ] Tab cycles through all panes including Kernel Trace
- [ ] BPF map lookup < 1us per packet
- [ ] `cargo test` passes on any system (non-eBPF tests)
- [ ] Existing 57+ tests unaffected

## Risks

| Risk | Mitigation |
|------|------------|
| Nightly for eBPF crate | Pre-compile bytecode; ship `.o` in repo |
| Root required | Graceful fallback, clear messages |
| Old kernel | Runtime version check |
| IPv6 not covered | Follow-up enhancement |
| 5-tuple collision (NAT) | Acceptable for Phase 6; timestamp correlation later |

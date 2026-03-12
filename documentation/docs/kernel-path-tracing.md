---
title: Kernel Packet Path Tracing
date: 2026-03-12
author: Claude
status: implemented
related_issues:
  - "#18"
related_mrs: []
---

## Overview

TuiShark supports pwru-style kernel packet path tracing, showing the sequence of kernel
functions each packet passes through as it traverses the Linux networking stack. This
extends the existing eBPF process-info tracing with a push-based event stream via
PerfEventArray.

## Architecture

### Process Info (existing, unchanged)

```
kprobe(tcp_sendmsg) -> FLOW_MAP[5-tuple] = {pid, uid, comm}
userspace: lookup FLOW_MAP on packet select
```

### Path Tracing (new, additive)

```
kprobe(ip_rcv, tcp_v4_rcv, ...) -> extract 5-tuple from sk_buff -> emit PathEvent to PATH_EVENTS
userspace: poll perf buffer -> aggregate by skb_ptr -> match to packets -> display timeline
```

## Activation Modes

### `--trace-path` flag

Attaches all 24 path kprobes at startup, traces all flows. Every captured packet gets
its kernel path stored. Higher overhead but provides full history.

```bash
sudo ./target/release/tuishark --trace-path -i eth0
```

### `Shift+P` keybinding (on-demand)

When running with `--trace`:
- First press: attaches path kprobes and filters to the selected flow's 5-tuple
- Second press: detaches path kprobes

When running with `--trace-path`:
- First press: narrows BPF filter to the selected flow only
- Second press: widens back to all flows

## Traced Kernel Functions

| Subsystem | Functions | UI Color |
|-----------|-----------|----------|
| Ingress | `netif_receive_skb`, `__netif_receive_skb_core`, `ip_rcv`, `ip_rcv_finish`, `ip_local_deliver`, `ip_local_deliver_finish` | Green |
| Netfilter | `nf_hook_slow`, `nf_conntrack_in` | Yellow |
| TCP rx | `tcp_v4_rcv`, `tcp_rcv_established`, `tcp_data_queue` | Blue |
| UDP rx | `udp_rcv`, `udp_queue_rcv_skb` | Blue |
| Socket | `sock_sendmsg`, `sock_recvmsg` | Lavender |
| TCP tx | `tcp_sendmsg`, `tcp_write_xmit` | Blue |
| UDP tx | `udp_sendmsg` | Blue |
| IP out | `ip_output`, `ip_finish_output` | Peach |
| Forward | `ip_forward`, `ip_forward_finish` | Mauve |
| Egress | `dev_queue_xmit`, `dev_hard_start_xmit` | Red |

## UI Display

The Kernel Trace pane shows both process info (top) and path timeline (bottom):

```
+- Kernel Trace -----------------------------------------+
| PID: 1234   Process: curl   UID: 1000                  |
|---------------------------------------------------------|
| Kernel Path (4 hops, 42.3 us)                          |
|  1. netif_receive_skb         +0.0 us                   |
|  2. ip_rcv                    +1.2 us                   |
|  3. tcp_v4_rcv               +12.3 us                   |
|  4. dev_queue_xmit           +42.3 us                   |
+---------------------------------------------------------+
```

The pane supports scrolling with `j`/`k` when focused.

## Implementation Details

### eBPF Side

- `PathEvent` struct emitted per kprobe hit via `PerfEventArray`
- `TraceFilter` array map allows userspace to set a 5-tuple filter
- `handle_skb()` reads IP/transport headers from `sk_buff` linear data
- sk_buff offsets hardcoded for Linux 6.x (64-bit); CO-RE/BTF planned

### Userspace Side

- `PathTraceEngine`: manages per-CPU perf buffers, non-blocking poll
- `PathAggregator`: groups events by `skb_ptr` into `PacketPath`, expires after 100ms
- `PathStore`: caches `packet_index -> PacketPath` like existing `TraceStore`
- Matching: completed paths matched to captured packets by 5-tuple (forward + reverse)

### sk_buff Offsets (Linux 6.x)

```
transport_header: offset 184 (u16)
network_header:   offset 186 (u16)
head:             offset 224 (pointer)
```

These are validated for typical distro configs on Linux 6.x (x86_64/aarch64).
Future work: CO-RE/BTF for cross-version portability.

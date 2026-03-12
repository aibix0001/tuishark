---
title: Container Context Overlay
date: 2026-03-12
author: Claude Opus 4.6
status: implemented
related_issues:
  - "#25"
related_mrs: []
---

## Overview

The Container Context overlay displays per-packet kernel context extracted via eBPF, showing network namespace, network device, TCP connection state, and cgroup ID. This is essential for visibility into containerized and multi-interface environments. It is accessible via the `c` keybinding from any pane.

## Usage

1. Start a capture with `--trace` to enable eBPF tracing
2. Select a packet in the packet table
3. Press `c` to open the container context dialog
4. View network namespace, device, TCP state, and cgroup for the selected packet
5. Use `ö`/`ä` to navigate between packets while the dialog stays open
6. Press `Esc`, `q`, or `c` to close

## Information Displayed

### Network Namespace

The network namespace inode number (`ns.inum`) extracted from `sk_buff->dev->nd_net->net->ns.inum`. The default host namespace (init_net) is labeled with "(default)" alongside its inode number (typically 4026531840).

### Network Device

The name and interface index of the device the packet traverses, extracted from `sk_buff->dev`. Displayed as `name (#index)`, e.g., `eth0 (#2)` or `docker0 (#5)`. This reveals which interface handles the packet — critical for multi-homed hosts, bridge networks, and container veth pairs.

### TCP Connection State

For TCP packets (protocol 6), the socket state is read from `sk_buff->sk->__sk_common.skc_state`. The state is color-coded:

- **ESTABLISHED** (green, bold): Active connection
- **SYN_SENT / SYN_RECV** (yellow): Connection setup
- **LISTEN** (blue, bold): Server listening
- **FIN_WAIT1/2, LAST_ACK, CLOSING, CLOSE_WAIT** (peach): Teardown
- **TIME_WAIT** (dim): Post-close wait
- **CLOSE** (red): Fully closed

For UDP packets, the field shows "N/A (UDP)".

### cgroup ID

The cgroup ID from `bpf_get_current_cgroup_id()`, which maps to the container runtime cgroup (Docker, Podman, Kubernetes pod). Combined with the network namespace ID, this uniquely identifies a container.

## Technical Details

### eBPF Data Collection

Container context is captured by the same kprobes used for kernel path tracing. When `handle_skb()` fires on any of the 24 path-tracing kprobes, it additionally reads:

- `sk_buff->dev` (offset 16): Pointer to `net_device`
- `net_device->ifindex` (offset 224), `net_device->name` (offset 288)
- `net_device->nd_net` (offset 264) -> `struct net` -> `ns.inum` (offset 176)
- `sk_buff->sk` (offset 24) -> `sock_common.skc_state` (offset 18)
- `bpf_get_current_cgroup_id()` for cgroup

Data is stored in `CONTAINER_MAP`, an LRU hash map keyed by the 5-tuple flow key (65536 max entries).

### Userspace Flow

1. During packet capture, `TraceEngine::lookup_container()` queries the BPF map
2. Results are cached in `ContainerStore` (per-packet HashMap)
3. The `ContainerDialog` widget renders the cached data for the selected packet

### Kernel Struct Offsets

All offsets are validated against Linux 6.19.3 via `pahole`:

| Field | Offset | Size |
|---|---|---|
| `sk_buff->dev` | 16 | 8 (ptr) |
| `sk_buff->sk` | 24 | 8 (ptr) |
| `net_device->ifindex` | 224 | 4 |
| `net_device->nd_net` | 264 | 8 |
| `net_device->name` | 288 | 16 |
| `net->ns.inum` | 176 | 4 |
| `sock_common->skc_state` | 18 | 1 |

## Configuration

The keybinding is configurable in `~/.config/tuishark/config.toml`:

```toml
[keys]
container_info = "c"
```

Note: The interface picker was moved from `c` to `n` (NIC) to free this keybinding.

## Requirements

- `--trace` flag must be active (eBPF tracing enabled)
- Path tracing kprobes must be attached (container data piggybacks on path trace kprobes)
- Root privileges or appropriate capabilities for eBPF

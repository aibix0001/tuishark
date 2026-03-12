# Plan: Packet Header Fields in Trace Pane

## Context

The kernel trace pane has significant unused horizontal space to the right of hop lines when zoomed. The eBPF `handle_skb()` already computes pointers to the IP header (`iphdr`) and transport header (`thdr`) but only reads protocol, addresses, and ports. Five additional packet header fields can be extracted with trivial reads from those same pointers: TTL, IP total length, DSCP/ECN, TCP flags, and TCP window size. These are **packet-level** values (same for all hops of a single sk_buff) and should be displayed as a summary line in the path header, not repeated per hop.

## Target UI (zoomed trace pane)

```
 Kernel Path (8 hops, 42.3 us)
 TTL: 64   Len: 1500   DSCP: CS0  ECN: 0   Flags: [SYN,ACK]   Win: 65535
  1. netif_receive_skb              +0.0 us
  2. ip_rcv                         +1.2 us
  ...
```

## Approach: Extend PathEvent struct

Add the 5 fields to PathEvent (eBPF → userspace perf buffer). The aggregator captures them from the first event and stores them in PacketPath. No per-hop changes needed.

### PathEvent layout change

Current: 32 bytes (1 byte padding)
New fields: ttl (u8), ip_len (u16), dscp_ecn (u8), tcp_flags (u8), tcp_win (u16) = 7 bytes
New total: 32 - 1 (old pad) + 7 + 2 (new pad for 8-byte align) = 40 bytes

```
PathEvent {
    skb_ptr: u64,        // 8
    timestamp_ns: u64,   // 8
    src_addr: u32,       // 4
    dst_addr: u32,       // 4
    func_id: u16,        // 2
    src_port: u16,       // 2
    dst_port: u16,       // 2
    ip_len: u16,         // 2  [NEW]
    tcp_win: u16,        // 2  [NEW]
    protocol: u8,        // 1
    ttl: u8,             // 1  [NEW]
    dscp_ecn: u8,        // 1  [NEW]
    tcp_flags: u8,       // 1  [NEW]
}                        // 40 bytes, no padding needed
```

### eBPF reads (all pointers already available)

| Field | Read | Offset | Conversion |
|-------|------|--------|------------|
| TTL | `iphdr.add(8)` | +8 from IP hdr | none (u8) |
| IP Length | `iphdr.add(2)` | +2 from IP hdr | `u16::from_be()` |
| DSCP/ECN | `iphdr.add(1)` | +1 from IP hdr | none (u8, split later in userspace) |
| TCP Flags | `thdr.add(13)` | +13 from transport hdr | none (u8, lower 8 flag bits) |
| TCP Window | `thdr.add(14)` | +14 from transport hdr | `u16::from_be()` |

TCP flags and window: only read when `protocol == 6` and `trans_off != 0xFFFF`, else 0.

### Files to modify

1. **`tuishark-ebpf/src/main.rs`** — PathEvent struct + 5 new reads in handle_skb()
2. **`tuishark/src/trace/path_model.rs`** — PathEvent struct (mirror), size assertion (40), add fields to PacketPath, helper methods (dscp_class_str, tcp_flags_str, etc.)
3. **`tuishark/src/trace/path_aggregator.rs`** — Copy new fields from first PathEvent into PacketPath in `build_path()`
4. **`tuishark/src/ui/widgets/trace_view.rs`** — Add summary line between path header and hop list
5. **`tuishark/ebpf/tuishark-ebpf`** — Rebuilt binary

### Helper methods on PacketPath

- `dscp_class(&self) -> &str` — map DSCP value to class name (CS0-CS7, AF11-AF43, EF, etc.)
- `ecn_str(&self) -> &str` — "Not-ECT", "ECT(0)", "ECT(1)", "CE"
- `tcp_flags_str(&self) -> String` — "[SYN,ACK]" style display
- `ttl`, `ip_len`, `tcp_win` — stored as plain fields on PacketPath

### Display logic

- Always show: TTL, Len, DSCP, ECN
- TCP only (protocol == 6): Flags, Win
- UDP: skip Flags/Win fields
- Non-zoomed (8-row pane): summary line may be hidden by scroll — acceptable since user can zoom with `z`

## Verification

1. `cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release` (eBPF)
2. `cargo build --features trace` (userspace)
3. `cargo test --features trace` (all tests pass)
4. Manual: run with `--trace`, enable path tracing (Shift+P), zoom trace pane (4 then z), verify header fields appear on the summary line
5. Test with TCP and UDP packets to verify conditional display

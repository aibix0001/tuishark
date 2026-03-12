#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_get_current_comm, bpf_get_current_cgroup_id, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_kernel_buf},
    macros::{kprobe, map},
    maps::{Array, LruHashMap, PerfEventArray},
    programs::ProbeContext,
};

/// 5-tuple flow key — must match the userspace FlowKey layout exactly.
#[repr(C)]
struct FlowKey {
    src_addr: u32,
    dst_addr: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    _pad: [u8; 3],
}

/// Process info — must match the userspace ProcessInfo layout exactly.
#[repr(C)]
struct ProcessInfo {
    pid: u32,
    uid: u32,
    comm: [u8; 16],
}

/// Path event — must match the userspace PathEvent layout exactly.
/// Emitted by path-tracing kprobes to the PATH_EVENTS perf buffer.
///
/// Fields ordered to avoid implicit padding: u64s first, then u32s, then u16s, then u8.
#[repr(C)]
struct PathEvent {
    skb_ptr: u64,
    timestamp_ns: u64,
    src_addr: u32,
    dst_addr: u32,
    func_id: u16,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    _pad: [u8; 1],
}

/// Container context info — populated by path-tracing kprobes for container/netns enrichment.
/// Must match the userspace ContainerInfo layout exactly.
///
/// Fields ordered to avoid implicit padding: u64 first, then u32s, then byte arrays.
#[repr(C)]
struct ContainerInfo {
    cgroup_id: u64,
    netns_inum: u32,
    ifindex: u32,
    dev_name: [u8; 16],
    tcp_state: u8,
    _pad: [u8; 7],
}

/// Filter for path tracing — written by userspace to narrow tracing to a specific flow.
#[repr(C)]
struct TraceFilter {
    src_addr: u32,
    dst_addr: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    active: u8,
    _pad: [u8; 2],
}

const AF_INET: u16 = 2;

// ─── sk_buff struct offsets for Linux 6.x (x86_64/aarch64, 64-bit) ────────
//
// These are hardcoded offsets into `struct sk_buff`. They are stable across
// the Linux 6.x series on 64-bit with typical distro configs.
//
// TODO: Migrate to CO-RE/BTF for kernel-version-independent access.
//
// Validated against pahole output for Linux 6.19.3:
//   sk_buff->transport_header : offset 182, size 2 (__u16)
//   sk_buff->network_header   : offset 184, size 2 (__u16)
//   sk_buff->mac_header       : offset 186, size 2 (__u16)
//   sk_buff->head             : offset 200, size 8 (unsigned char *)
//
// NOTE: These offsets vary across kernel versions. If path tracing produces
// zero events, re-validate with: pahole -C sk_buff /sys/kernel/btf/vmlinux
//
// struct iphdr offsets (standard, all architectures):
//   iphdr->protocol : offset 9, size 1
//   iphdr->saddr    : offset 12, size 4
//   iphdr->daddr    : offset 16, size 4
//
// TCP/UDP header (first 4 bytes are source/dest port on both):
//   tcphdr/udphdr->source : offset 0, size 2 (network byte order)
//   tcphdr/udphdr->dest   : offset 2, size 2 (network byte order)

const SKB_OFF_DEV: usize = 16;
const SKB_OFF_SK: usize = 24;
const SKB_OFF_TRANSPORT_HEADER: usize = 182;
const SKB_OFF_NETWORK_HEADER: usize = 184;
const SKB_OFF_HEAD: usize = 200;

// ─── net_device struct offsets for Linux 6.x (x86_64/aarch64, 64-bit) ────
//
// These are hardcoded offsets into `struct net_device`. They vary across
// kernel versions and configs (PREEMPT_RT, lockdep, debug options shift layout).
//
// TODO: Migrate to CO-RE/BTF for kernel-version-independent access.
//
// Validated against pahole output for Linux 6.19.3:
//   net_device->ifindex  : offset 224, size 4 (int)
//   net_device->nd_net   : offset 264, size 8 (possible_net_t containing struct net *)
//   net_device->name     : offset 288, size 16 (char[IFNAMSIZ])
//
// NOTE: net_device layout is LESS stable than sk_buff across kernel configs.
// If container info shows garbage device names, re-validate with:
//   pahole -C net_device /sys/kernel/btf/vmlinux
const NETDEV_OFF_IFINDEX: usize = 224;
const NETDEV_OFF_ND_NET: usize = 264;
const NETDEV_OFF_NAME: usize = 288;

// struct net -> ns_common offset, then ns_common->inum:
//   net->ns         : offset 152 (struct ns_common)
//   ns_common->inum : offset 24 (unsigned int)
//
// Validated against pahole output for Linux 6.19.3:
//   pahole -C net /sys/kernel/btf/vmlinux
//   pahole -C ns_common /sys/kernel/btf/vmlinux
const NET_OFF_NS_INUM: usize = 152 + 24;

// sock_common->skc_state : offset 18, size 1 (volatile unsigned char)
// This offset is stable across Linux 6.x (sock_common is densely packed).
const SKC_OFF_STATE: usize = 18;

const IPHDR_OFF_PROTOCOL: usize = 9;
const IPHDR_OFF_SADDR: usize = 12;
const IPHDR_OFF_DADDR: usize = 16;

// ─── BPF maps ──────────────────────────────────────────────────────────────

/// LRU hash map shared between all kprobes and userspace (existing process info).
#[map]
static FLOW_MAP: LruHashMap<FlowKey, ProcessInfo> = LruHashMap::with_max_entries(65536, 0);

/// LRU hash map for container context (netns, device, TCP state, cgroup).
#[map]
static CONTAINER_MAP: LruHashMap<FlowKey, ContainerInfo> = LruHashMap::with_max_entries(65536, 0);

/// Perf event array for streaming path events to userspace.
#[map]
static PATH_EVENTS: PerfEventArray<PathEvent> = PerfEventArray::new(0);

/// Single-element array holding the active trace filter (written by userspace).
#[map]
static TRACE_FILTER: Array<TraceFilter> = Array::with_max_entries(1, 0);

// ─── Existing process-info tracing (unchanged) ────────────────────────────

/// Extract the 5-tuple from a `struct sock *` and store process info.
/// The sock pointer is the first argument to tcp_sendmsg/tcp_recvmsg/udp_sendmsg/udp_recvmsg.
///
/// ## Kernel struct offsets (validated on Linux 6.x)
///
/// `struct sock` starts with `struct sock_common __sk_common` at offset 0.
/// `struct sock_common` layout (Linux 6.x):
///   offset  0: skc_daddr      (__be32)  — destination IPv4 address
///   offset  4: skc_rcv_saddr  (__be32)  — source IPv4 address
///   offset  8: skc_hash       (u32)
///   offset 12: skc_dport      (__be16)  — destination port (network byte order)
///   offset 14: skc_num        (__u16)   — source port (host byte order)
///   offset 16: skc_family     (__u16)   — address family (AF_INET=2, AF_INET6=10)
///
/// TODO: Migrate to CO-RE/BTF (vmlinux bindings) for kernel-version-independent offsets.
#[inline(always)]
unsafe fn handle_sock(ctx: &ProbeContext, protocol: u8) -> Result<(), i64> {
    // First argument: struct sock *sk
    let sk: *const u8 = ctx.arg(0).ok_or(1i64)?;

    // __sk_common starts at offset 0 of struct sock
    let skc = sk;

    // Check address family — only handle IPv4 (AF_INET)
    let family: u16 = bpf_probe_read_kernel(skc.add(16) as *const u16)?;
    if family != AF_INET {
        return Ok(());
    }

    let dst_addr: u32 = bpf_probe_read_kernel(skc.add(0) as *const u32)?;
    let src_addr: u32 = bpf_probe_read_kernel(skc.add(4) as *const u32)?;
    let dst_port: u16 = bpf_probe_read_kernel(skc.add(12) as *const u16)?;
    let src_port: u16 = bpf_probe_read_kernel(skc.add(14) as *const u16)?;

    // dst_port is in network byte order, src_port (skc_num) is in host byte order
    let dst_port = u16::from_be(dst_port);

    // Skip if no meaningful connection (all zeros)
    if src_addr == 0 && dst_addr == 0 {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;

    let comm = bpf_get_current_comm()?;

    let key = FlowKey {
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        protocol,
        _pad: [0; 3],
    };

    let value = ProcessInfo {
        pid,
        uid,
        comm,
    };

    let _ = FLOW_MAP.insert(&key, &value, 0);

    Ok(())
}

macro_rules! kprobe_handler {
    ($name:ident, $proto:expr) => {
        #[kprobe]
        pub fn $name(ctx: ProbeContext) -> u32 {
            match unsafe { handle_sock(&ctx, $proto) } {
                Ok(()) | Err(_) => 0,
            }
        }
    };
}

kprobe_handler!(trace_tcp_sendmsg, 6);
kprobe_handler!(trace_tcp_recvmsg, 6);
kprobe_handler!(trace_udp_sendmsg, 17);
kprobe_handler!(trace_udp_recvmsg, 17);

// ─── Path tracing: sk_buff extraction + event emission ────────────────────

/// Extract 5-tuple from an `sk_buff *`, check against TRACE_FILTER,
/// and emit a PathEvent to the PATH_EVENTS perf buffer.
///
/// `skb_arg` selects which kprobe argument holds the `sk_buff *` pointer:
///   arg 0: netif_receive_skb, ip_rcv, ip_local_deliver, nf_hook_slow,
///          tcp_v4_rcv, udp_rcv, ip_forward, dev_queue_xmit, dev_hard_start_xmit
///   arg 1: nf_conntrack_in(priv, skb, state), tcp_rcv_established(sk, skb),
///          tcp_data_queue(sk, skb), udp_queue_rcv_skb(sk, skb)
///   arg 2: ip_rcv_finish(net, sk, skb), ip_local_deliver_finish(net, sk, skb),
///          ip_output(net, sk, skb), ip_finish_output(net, sk, skb),
///          ip_forward_finish(net, sk, skb)
#[inline(always)]
unsafe fn handle_skb(ctx: &ProbeContext, func_id: u16, skb_arg: usize) -> Result<(), i64> {
    let skb: *const u8 = ctx.arg(skb_arg).ok_or(1i64)?;

    // Read sk_buff->head (pointer to linear data buffer)
    let head: *const u8 = bpf_probe_read_kernel(skb.add(SKB_OFF_HEAD) as *const *const u8)?;

    // Read sk_buff->network_header (u16 offset from head)
    let net_off: u16 = bpf_probe_read_kernel(skb.add(SKB_OFF_NETWORK_HEADER) as *const u16)?;

    // Read sk_buff->transport_header (u16 offset from head)
    let trans_off: u16 = bpf_probe_read_kernel(skb.add(SKB_OFF_TRANSPORT_HEADER) as *const u16)?;

    // Bail if headers not set (offset 0xFFFF means "not set" in the kernel)
    if net_off == 0xFFFF {
        return Ok(());
    }

    // Compute IP header pointer
    let iphdr = head.add(net_off as usize);

    // Check IP version nibble — only handle IPv4 (version 4)
    let version_ihl: u8 = bpf_probe_read_kernel(iphdr as *const u8)?;
    if (version_ihl >> 4) != 4 {
        return Ok(());
    }

    // Read IP fields
    let protocol: u8 = bpf_probe_read_kernel(iphdr.add(IPHDR_OFF_PROTOCOL) as *const u8)?;
    let src_addr: u32 = bpf_probe_read_kernel(iphdr.add(IPHDR_OFF_SADDR) as *const u32)?;
    let dst_addr: u32 = bpf_probe_read_kernel(iphdr.add(IPHDR_OFF_DADDR) as *const u32)?;

    // Only trace TCP (6) and UDP (17)
    if protocol != 6 && protocol != 17 {
        return Ok(());
    }

    // Read ports from transport header (both TCP and UDP have ports at offset 0 and 2)
    let (src_port, dst_port) = if trans_off != 0xFFFF {
        let thdr = head.add(trans_off as usize);
        let sp: u16 = bpf_probe_read_kernel(thdr as *const u16)?;
        let dp: u16 = bpf_probe_read_kernel(thdr.add(2) as *const u16)?;
        (u16::from_be(sp), u16::from_be(dp))
    } else {
        (0u16, 0u16)
    };

    // Check against TRACE_FILTER
    if let Some(filter) = TRACE_FILTER.get(0) {
        if filter.active != 0 {
            // Filter is active — check if this packet matches.
            // Match forward or reverse direction.
            let fwd_match = src_addr == filter.src_addr
                && dst_addr == filter.dst_addr
                && src_port == filter.src_port
                && dst_port == filter.dst_port
                && protocol == filter.protocol;

            let rev_match = src_addr == filter.dst_addr
                && dst_addr == filter.src_addr
                && src_port == filter.dst_port
                && dst_port == filter.src_port
                && protocol == filter.protocol;

            if !fwd_match && !rev_match {
                return Ok(());
            }
        }
    }

    // ─── Extract container context from sk_buff ────────────────────────
    // Read sk_buff->dev (struct net_device *)
    let dev_ptr: *const u8 = bpf_probe_read_kernel(skb.add(SKB_OFF_DEV) as *const *const u8)
        .unwrap_or(core::ptr::null());

    if !dev_ptr.is_null() {
        // net_device->ifindex
        let ifindex: u32 = bpf_probe_read_kernel(dev_ptr.add(NETDEV_OFF_IFINDEX) as *const u32)
            .unwrap_or(0);

        // net_device->name (char[16])
        let mut dev_name = [0u8; 16];
        let name_ptr = dev_ptr.add(NETDEV_OFF_NAME);
        let _ = bpf_probe_read_kernel_buf(name_ptr, &mut dev_name);

        // net_device->nd_net.net (struct net *)
        let net_ptr: *const u8 = bpf_probe_read_kernel(
            dev_ptr.add(NETDEV_OFF_ND_NET) as *const *const u8
        ).unwrap_or(core::ptr::null());

        let netns_inum: u32 = if !net_ptr.is_null() {
            bpf_probe_read_kernel(net_ptr.add(NET_OFF_NS_INUM) as *const u32).unwrap_or(0)
        } else {
            0
        };

        // TCP state: read from sk_buff->sk->__sk_common.skc_state
        let sk_ptr: *const u8 = bpf_probe_read_kernel(skb.add(SKB_OFF_SK) as *const *const u8)
            .unwrap_or(core::ptr::null());
        let tcp_state: u8 = if !sk_ptr.is_null() && protocol == 6 {
            bpf_probe_read_kernel(sk_ptr.add(SKC_OFF_STATE) as *const u8).unwrap_or(0)
        } else {
            0
        };

        // cgroup ID from current task context.
        // NOTE: bpf_get_current_cgroup_id() returns the cgroup of the currently
        // executing task. On the RX path (softirq context, func_ids 0-12), the
        // "current" task is whatever was interrupted — NOT the connection owner.
        // We only populate cgroup_id for TX-path func_ids (18-23) where the
        // calling process is the actual sender. For RX, we store 0.
        let cgroup_id = if func_id >= 18 {
            bpf_get_current_cgroup_id()
        } else {
            0
        };

        let container_info = ContainerInfo {
            cgroup_id,
            netns_inum,
            ifindex,
            dev_name,
            tcp_state,
            _pad: [0; 7],
        };

        let flow = FlowKey {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            protocol,
            _pad: [0; 3],
        };

        let _ = CONTAINER_MAP.insert(&flow, &container_info, 0);
    }

    let event = PathEvent {
        skb_ptr: skb as u64,
        timestamp_ns: bpf_ktime_get_ns(),
        src_addr,
        dst_addr,
        func_id,
        src_port,
        dst_port,
        protocol,
        _pad: [0; 1],
    };

    PATH_EVENTS.output(ctx, &event, 0);

    Ok(())
}

/// Macro for path-tracing kprobe handlers.
/// Each handler calls handle_skb with the appropriate func_id and skb argument index.
macro_rules! path_kprobe {
    ($name:ident, $func_id:expr, $skb_arg:expr) => {
        #[kprobe]
        pub fn $name(ctx: ProbeContext) -> u32 {
            match unsafe { handle_skb(&ctx, $func_id, $skb_arg) } {
                Ok(()) | Err(_) => 0,
            }
        }
    };
}

// Ingress — sk_buff * is arg 0
path_kprobe!(path_netif_receive_skb, 0, 0);
// __netif_receive_skb_core takes sk_buff **, not sk_buff * — skipped (func_id 1)
path_kprobe!(path_ip_rcv, 2, 0);               // ip_rcv(skb, dev, pt, orig_dev)
path_kprobe!(path_ip_rcv_finish, 3, 2);         // ip_rcv_finish(net, sk, skb)
path_kprobe!(path_ip_local_deliver, 4, 0);      // ip_local_deliver(skb)
path_kprobe!(path_ip_local_deliver_finish, 5, 2); // ip_local_deliver_finish(net, sk, skb)
// Netfilter
path_kprobe!(path_nf_hook_slow, 6, 0);          // nf_hook_slow(skb, state, ...)
path_kprobe!(path_nf_conntrack_in, 7, 1);       // nf_conntrack_in(priv, skb, state)
// TCP rx
path_kprobe!(path_tcp_v4_rcv, 8, 0);            // tcp_v4_rcv(skb)
path_kprobe!(path_tcp_rcv_established, 9, 1);   // tcp_rcv_established(sk, skb)
path_kprobe!(path_tcp_data_queue, 10, 1);        // tcp_data_queue(sk, skb)
// UDP rx
path_kprobe!(path_udp_rcv, 11, 0);              // udp_rcv(skb)
path_kprobe!(path_udp_queue_rcv_skb, 12, 1);    // udp_queue_rcv_skb(sk, skb)
// Socket (13-14): sock_sendmsg/sock_recvmsg take struct socket *, not sk_buff * — skipped.
// TX socket layer (15-17): tcp_sendmsg, tcp_write_xmit, udp_sendmsg take struct sock *,
// not sk_buff * — the sk_buff is created internally. Skipped.
// IP out — sk_buff * is arg 2: fn(net, sk, skb)
path_kprobe!(path_ip_output, 18, 2);            // ip_output(net, sk, skb)
path_kprobe!(path_ip_finish_output, 19, 2);     // ip_finish_output(net, sk, skb)
// Forward
path_kprobe!(path_ip_forward, 20, 0);           // ip_forward(skb)
path_kprobe!(path_ip_forward_finish, 21, 2);    // ip_forward_finish(net, sk, skb)
// Egress — sk_buff * is arg 0
path_kprobe!(path_dev_queue_xmit, 22, 0);       // dev_queue_xmit(skb)
path_kprobe!(path_dev_hard_start_xmit, 23, 0);  // dev_hard_start_xmit(skb, dev, txq)

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

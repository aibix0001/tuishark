#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_get_current_comm, bpf_probe_read_kernel},
    macros::{kprobe, map},
    maps::LruHashMap,
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

/// LRU hash map shared between all kprobes and userspace.
#[map]
static FLOW_MAP: LruHashMap<FlowKey, ProcessInfo> = LruHashMap::with_max_entries(65536, 0);

/// Extract the 5-tuple from a `struct sock *` and store process info.
/// The sock pointer is the first argument to tcp_sendmsg/tcp_recvmsg/udp_sendmsg/udp_recvmsg.
#[inline(always)]
unsafe fn handle_sock(ctx: &ProbeContext, protocol: u8) -> Result<(), i64> {
    // First argument: struct sock *sk
    let sk: *const u8 = ctx.arg(0).ok_or(1i64)?;

    // Read sock fields using kernel struct offsets.
    // These offsets are for the `struct sock_common` embedded at the start of `struct sock`.
    // __sk_common.skc_daddr (destination IP): offset 0 in inet_sock after sock_common
    // __sk_common.skc_rcv_saddr (source IP): offset 4
    // For TCP/UDP sockets on Linux 5.x+:
    //   skc_daddr at offset 0x00 from __sk_common
    //   skc_rcv_saddr at offset 0x04 from __sk_common
    //   skc_dport at offset 0x0c from __sk_common
    //   skc_num (local port) at offset 0x0e from __sk_common

    // __sk_common starts at offset 0 of struct sock
    let skc = sk;

    let dst_addr: u32 = bpf_probe_read_kernel(skc.add(0) as *const u32).map_err(|e| e)?;
    let src_addr: u32 = bpf_probe_read_kernel(skc.add(4) as *const u32).map_err(|e| e)?;
    let dst_port: u16 = bpf_probe_read_kernel(skc.add(12) as *const u16).map_err(|e| e)?;
    let src_port: u16 = bpf_probe_read_kernel(skc.add(14) as *const u16).map_err(|e| e)?;

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

    let comm = bpf_get_current_comm().map_err(|e| e)?;

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

#[kprobe]
pub fn trace_tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match unsafe { handle_sock(&ctx, 6) } {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn trace_tcp_recvmsg(ctx: ProbeContext) -> u32 {
    match unsafe { handle_sock(&ctx, 6) } {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn trace_udp_sendmsg(ctx: ProbeContext) -> u32 {
    match unsafe { handle_sock(&ctx, 17) } {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn trace_udp_recvmsg(ctx: ProbeContext) -> u32 {
    match unsafe { handle_sock(&ctx, 17) } {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

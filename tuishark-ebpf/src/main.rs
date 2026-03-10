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

const AF_INET: u16 = 2;

/// LRU hash map shared between all kprobes and userspace.
#[map]
static FLOW_MAP: LruHashMap<FlowKey, ProcessInfo> = LruHashMap::with_max_entries(65536, 0);

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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

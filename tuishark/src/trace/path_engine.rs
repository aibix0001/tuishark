#[cfg(feature = "trace")]
use super::model::FlowKey;
use super::path_model::{PathEvent, PathTraceState};
#[cfg(feature = "trace")]
use super::path_model::TraceFilter;

#[cfg(feature = "trace")]
use aya::{
    maps::{Array, PerfEventArray, perf::PerfEventArrayBuffer, MapData},
    programs::KProbe,
    util::online_cpus,
    Ebpf,
};

#[cfg(feature = "trace")]
use bytes::BytesMut;

#[cfg(feature = "trace")]
use std::mem;

/// Manages path-tracing kprobes and the perf event buffer.
///
/// Separate from TraceEngine to avoid regressions in existing process-info tracing.
/// Shares the same loaded eBPF binary but attaches different kprobes.
#[cfg(feature = "trace")]
pub struct PathTraceEngine {
    /// Per-CPU perf buffers for reading PathEvents.
    // Uses 'static lifetime through owned MapData via Arc inside PerfEventArray
    perf_buffers: Vec<PerfEventArrayBuffer<MapData>>,
    /// Reusable read buffer (one per poll call).
    read_bufs: Vec<BytesMut>,
    /// Running count of lost events across all buffers.
    pub events_lost: u64,
    /// Current state.
    pub state: PathTraceState,
}

#[cfg(feature = "trace")]
impl PathTraceEngine {
    /// The mapping from eBPF program name to kernel function name and func_id.
    /// Matches the path_kprobe! macro invocations in the eBPF program.
    const PATH_PROBES: &[(&str, &str, u16)] = &[
        // Ingress — sk_buff * is arg 0
        ("path_netif_receive_skb", "netif_receive_skb", 0),
        // __netif_receive_skb_core takes sk_buff **, not sk_buff * — skipped (func_id 1)
        ("path_ip_rcv", "ip_rcv", 2),
        ("path_ip_rcv_finish", "ip_rcv_finish", 3),         // arg 2: (net, sk, skb)
        ("path_ip_local_deliver", "ip_local_deliver", 4),
        ("path_ip_local_deliver_finish", "ip_local_deliver_finish", 5), // arg 2
        // Netfilter
        ("path_nf_hook_slow", "nf_hook_slow", 6),
        ("path_nf_conntrack_in", "nf_conntrack_in", 7),     // arg 1: (priv, skb, state)
        // TCP rx
        ("path_tcp_v4_rcv", "tcp_v4_rcv", 8),
        ("path_tcp_rcv_established", "tcp_rcv_established", 9),   // arg 1: (sk, skb)
        ("path_tcp_data_queue", "tcp_data_queue", 10),            // arg 1: (sk, skb)
        // UDP rx
        ("path_udp_rcv", "udp_rcv", 11),
        ("path_udp_queue_rcv_skb", "udp_queue_rcv_skb", 12),     // arg 1: (sk, skb)
        // func_ids 13-14: sock_sendmsg/sock_recvmsg — skipped (struct socket *, not sk_buff *)
        // func_ids 15-17: tcp_sendmsg/tcp_write_xmit/udp_sendmsg — skipped (struct sock *, no sk_buff)
        // IP out — arg 2: (net, sk, skb)
        ("path_ip_output", "ip_output", 18),
        ("path_ip_finish_output", "ip_finish_output", 19),
        // Forward
        ("path_ip_forward", "ip_forward", 20),
        ("path_ip_forward_finish", "ip_forward_finish", 21),     // arg 2
        // Egress — arg 0
        ("path_dev_queue_xmit", "dev_queue_xmit", 22),
        ("path_dev_hard_start_xmit", "dev_hard_start_xmit", 23),
    ];

    /// Attach all path-tracing kprobes and open perf buffers.
    ///
    /// The `bpf` reference must be the same Ebpf instance that was loaded by TraceEngine.
    /// This method loads and attaches the path kprobe programs that are present in the
    /// same eBPF object file.
    pub fn attach(bpf: &mut Ebpf) -> Result<Self, String> {
        // Attach path kprobes — skip those whose kernel function doesn't exist
        let mut attached = 0;
        let mut skipped = Vec::new();
        for &(prog_name, fn_name, _func_id) in Self::PATH_PROBES {
            let program = match bpf.program_mut(prog_name) {
                Some(p) => p,
                None => {
                    skipped.push(fn_name);
                    continue;
                }
            };
            let kprobe: &mut KProbe = program
                .try_into()
                .map_err(|e| format!("Failed to get kprobe '{prog_name}': {e}"))?;
            kprobe
                .load()
                .map_err(|e| format!("Failed to load kprobe '{prog_name}': {e}"))?;
            match kprobe.attach(fn_name, 0) {
                Ok(_) => attached += 1,
                Err(_) => {
                    // Kernel function may not exist (e.g., nf_conntrack_in without netfilter)
                    skipped.push(fn_name);
                }
            }
        }

        if attached == 0 {
            return Err("No path-tracing kprobes could be attached".into());
        }

        // Take ownership of the PATH_EVENTS map (removes it from Ebpf instance).
        // This is required because PerfEventArray::open needs owned MapData for
        // the returned buffers to be self-contained without lifetime constraints.
        let perf_map = bpf.take_map("PATH_EVENTS")
            .ok_or("PATH_EVENTS map not found in eBPF program")?;
        let mut perf_array = PerfEventArray::try_from(perf_map)
            .map_err(|e| format!("Failed to create PerfEventArray: {e}"))?;

        let cpus = online_cpus()
            .map_err(|(_, e)| format!("Failed to get online CPUs: {e}"))?;
        let mut perf_buffers = Vec::with_capacity(cpus.len());
        for cpu_id in cpus {
            let buf = perf_array
                .open(cpu_id, Some(64)) // 64 pages = 256KB per CPU
                .map_err(|e| format!("Failed to open perf buffer for CPU {cpu_id}: {e}"))?;
            perf_buffers.push(buf);
        }

        // Pre-allocate read buffers (batch of 64 events per poll)
        let event_size = mem::size_of::<PathEvent>();
        let read_bufs: Vec<BytesMut> = (0..64)
            .map(|_| BytesMut::with_capacity(event_size + 64))
            .collect();

        Ok(Self {
            perf_buffers,
            read_bufs,
            events_lost: 0,
            state: PathTraceState::Active,
        })
    }

    /// Poll all per-CPU perf buffers and return collected PathEvents.
    ///
    /// Non-blocking: returns immediately if no events are available.
    pub fn poll(&mut self) -> Vec<PathEvent> {
        let mut events = Vec::new();
        let event_size = mem::size_of::<PathEvent>();

        for buf in &mut self.perf_buffers {
            if !buf.readable() {
                continue;
            }

            // Reset read buffers for reuse
            for rb in &mut self.read_bufs {
                rb.clear();
                rb.reserve(event_size + 64);
            }

            match buf.read_events(&mut self.read_bufs) {
                Ok(result) => {
                    self.events_lost += result.lost as u64;
                    for i in 0..result.read {
                        let data = &self.read_bufs[i];
                        if data.len() >= event_size {
                            // SAFETY: PathEvent is #[repr(C)] with only primitive fields.
                            // The perf buffer guarantees the data was written as PathEvent.
                            let event: PathEvent = unsafe {
                                core::ptr::read_unaligned(data.as_ptr() as *const PathEvent)
                            };
                            events.push(event);
                        }
                    }
                }
                Err(_) => {
                    // Transient read errors are expected (e.g., buffer wrap)
                }
            }
        }

        events
    }

    /// Set the BPF-side filter to trace only a specific flow.
    pub fn set_filter(bpf: &mut Ebpf, flow_key: &FlowKey) -> Result<(), String> {
        let filter = TraceFilter {
            src_addr: flow_key.src_addr,
            dst_addr: flow_key.dst_addr,
            src_port: flow_key.src_port,
            dst_port: flow_key.dst_port,
            protocol: flow_key.protocol,
            active: 1,
            _pad: [0; 2],
        };
        Self::write_filter(bpf, &filter)
    }

    /// Clear the BPF-side filter (trace all flows).
    pub fn clear_filter(bpf: &mut Ebpf) -> Result<(), String> {
        let filter = TraceFilter::default();
        Self::write_filter(bpf, &filter)
    }

    fn write_filter(bpf: &mut Ebpf, filter: &TraceFilter) -> Result<(), String> {
        let map = bpf.map_mut("TRACE_FILTER")
            .ok_or("TRACE_FILTER map not found")?;
        let mut array: Array<_, TraceFilter> = map.try_into()
            .map_err(|e| format!("Failed to access TRACE_FILTER: {e}"))?;
        array.set(0, *filter, 0)
            .map_err(|e| format!("Failed to write TRACE_FILTER: {e}"))?;
        Ok(())
    }
}

/// Stub when the trace feature is not compiled.
#[cfg(not(feature = "trace"))]
#[allow(dead_code)]
pub struct PathTraceEngine {
    pub events_lost: u64,
    pub state: PathTraceState,
}

#[cfg(not(feature = "trace"))]
impl PathTraceEngine {
    pub fn poll(&mut self) -> Vec<PathEvent> {
        Vec::new()
    }
}

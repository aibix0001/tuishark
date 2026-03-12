use super::model::{FlowKey, ProcessInfo};

#[cfg(feature = "trace")]
use aya::{
    maps::HashMap as BpfHashMap,
    programs::KProbe,
    Ebpf,
};

/// Manages the eBPF programs and provides map lookup for process info.
///
/// Note: We cannot cache a `BpfHashMap` handle because it borrows from `Ebpf`.
/// The `map_mut()` call is cheap after the first time since aya caches the fd internally.
#[cfg(feature = "trace")]
pub struct TraceEngine {
    bpf: Ebpf,
}

#[cfg(feature = "trace")]
impl TraceEngine {
    /// Load and attach eBPF programs.
    /// Returns Err if eBPF cannot be loaded (permissions, kernel, etc.).
    pub fn new() -> Result<Self, String> {
        let ebpf_bytes = include_bytes!(concat!(env!("OUT_DIR"), "/tuishark-ebpf"));

        let mut bpf = Ebpf::load(ebpf_bytes).map_err(|e| format!("Failed to load eBPF: {e}"))?;

        // Attach kprobes
        let probes = [
            ("trace_tcp_sendmsg", "tcp_sendmsg"),
            ("trace_tcp_recvmsg", "tcp_recvmsg"),
            ("trace_udp_sendmsg", "udp_sendmsg"),
            ("trace_udp_recvmsg", "udp_recvmsg"),
        ];

        for (prog_name, fn_name) in &probes {
            let program: &mut KProbe = bpf
                .program_mut(prog_name)
                .ok_or_else(|| format!("eBPF program '{prog_name}' not found in object"))?
                .try_into()
                .map_err(|e| format!("Failed to get kprobe '{prog_name}': {e}"))?;
            program
                .load()
                .map_err(|e| format!("Failed to load kprobe '{prog_name}': {e}"))?;
            program
                .attach(fn_name, 0)
                .map_err(|e| format!("Failed to attach kprobe to '{fn_name}': {e}"))?;
        }

        // Verify the map exists at load time
        if bpf.map_mut("FLOW_MAP").is_none() {
            return Err("FLOW_MAP not found in eBPF program".into());
        }

        Ok(Self { bpf })
    }

    /// Look up process info for a flow in the BPF map.
    /// Tries the forward key first, then the reverse (for received packets).
    ///
    /// Uses map_mut() which requires &mut self — aya needs mutable access
    /// even for read-only map operations.
    pub fn lookup(&mut self, key: &FlowKey) -> Option<ProcessInfo> {
        let map = self.bpf.map_mut("FLOW_MAP")?;
        let hash_map: BpfHashMap<_, FlowKey, ProcessInfo> = map.try_into().ok()?;

        // Try forward direction first
        if let Ok(info) = hash_map.get(key, 0) {
            return Some(info);
        }

        // Try reverse (the packet may have been captured on the receive path,
        // so src/dst are swapped relative to the kprobe's perspective)
        let rev = key.reverse();
        hash_map.get(&rev, 0).ok()
    }

    /// Return the number of entries currently in the BPF flow map.
    pub fn map_entry_count(&mut self) -> usize {
        let Some(map) = self.bpf.map_mut("FLOW_MAP") else {
            return 0;
        };
        let Ok(hash_map): Result<BpfHashMap<_, FlowKey, ProcessInfo>, _> = map.try_into() else {
            return 0;
        };
        hash_map.keys().count()
    }

}

/// Stub engine when the trace feature is not compiled.
#[cfg(not(feature = "trace"))]
pub struct TraceEngine;

#[cfg(not(feature = "trace"))]
impl TraceEngine {
    pub fn new() -> Result<Self, String> {
        Err("Not compiled with eBPF support (build with --features trace)".into())
    }

    pub fn lookup(&mut self, _key: &FlowKey) -> Option<ProcessInfo> {
        None
    }

    pub fn map_entry_count(&mut self) -> usize {
        0
    }
}

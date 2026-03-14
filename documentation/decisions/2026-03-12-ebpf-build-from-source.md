---
title: "ADR: Build eBPF from source in build.rs instead of precompiled blob"
date: 2026-03-12
author: agent
status: active
related_issues:
  - "#26"
  - "#34"
  - "#35"
related_mrs:
  - "!26"
  - "!34"
  - "!35"
---

## Context

The eBPF program was compiled once via `tuishark-ebpf/build.sh`, committed as a binary blob at `tuishark/ebpf/tuishark-ebpf`, and embedded via `include_bytes!()` in `build.rs`. This worked on x86_64 where the blob was originally built.

When running on aarch64, eBPF tracing silently failed: kprobes attached and fired (confirmed via `bpf_stats_enabled` run counts), but the BPF flow map stayed empty. The root cause is that `aya-ebpf`'s build script determines `bpf_target_arch` from the `HOST` environment variable at compile time. This controls which `pt_regs` struct is used for `ctx.arg()` — x86_64 uses `pt_regs` with rdi/rsi/rdx register offsets, while aarch64 uses `user_pt_regs` with regs[0]/regs[1] offsets. A blob compiled on x86_64 reads from the wrong register position on aarch64, causing `handle_sock()` to read garbage and bail silently.

Notably, the kernel struct offsets (sock_common, sk_buff) were verified identical on both architectures via BTF — only the pt_regs register layout differs.

## Decision

Modify `tuishark/build.rs` to compile the eBPF crate from source during `cargo build --features trace`, instead of copying a precompiled blob.

The build script:

1. Locates `tuishark-ebpf/` source relative to `CARGO_MANIFEST_DIR`
2. Runs `ensure_ebpf_toolchain()` to verify nightly, rust-src, and bpf-linker are available. If `TUISHARK_AUTO_INSTALL_DEPS=1` is set, missing prerequisites are installed automatically; otherwise the function returns `false` with actionable warning messages and the build falls back to the precompiled blob
3. Invokes `cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release`
4. Clears inherited `CARGO_*` environment variables to prevent nested-build conflicts (including for `cargo install bpf-linker` when auto-installing)
5. Falls back to the precompiled blob with a `cargo:warning` if from-source build fails
6. **Rejects precompiled blobs at build time** if the blob's architecture (from `ebpf/tuishark-ebpf.arch` sidecar) doesn't match the host's `CARGO_CFG_TARGET_ARCH` — panics with clear remediation steps instead of silently using a broken blob. Skips the check when either arch is `"unknown"` (backward compat / unavailable metadata)
7. Tracks `rerun-if-changed` on eBPF source files, Cargo.toml/lock, and the precompiled blob + sidecar for incremental rebuilds

The precompiled blob and `build.sh` are retained for environments without nightly (CI, distribution builds).

## Consequences

**Easier:**

- Switching between x86_64 and aarch64 just works — `cargo build --features trace` produces correct eBPF for the host
- eBPF source changes are picked up automatically (no manual `build.sh` step)
- No risk of stale precompiled blobs causing silent failures

**Harder:**

- Building with `--features trace` now requires nightly toolchain, rust-src component, and bpf-linker on the build machine (was previously only needed for eBPF development). Set `TUISHARK_AUTO_INSTALL_DEPS=1` to have `build.rs` install these automatically
- Build time increases slightly (eBPF compilation adds ~1s, cached rebuilds are fast)
- The fallback path (precompiled blob) records its target architecture in a sidecar file (`tuishark-ebpf.arch`). Mismatched blobs are now **rejected at build time** (panic with remediation steps) in addition to the runtime check in `TraceEngine::new()`

**Remaining risks:**

- The hardcoded `sk_buff` struct offsets (transport_header=182, network_header=184, head=200) are validated against Linux 6.19.3 but are **config-dependent, not just version-dependent**. Kernel config options like `CONFIG_NET_SCHED`, `CONFIG_NET_CLS_ACT`, and `CONFIG_XFRM` add or remove fields before the header offsets, which can shift them on a different distro kernel even on the same architecture. Path tracing will silently produce zero events on kernels with different offsets. Migration to CO-RE/BTF is tracked as a follow-up issue and is the long-term fix.
- The `sock_common` offsets (0, 4, 12, 14, 16) have been stable since Linux 2.6 and are effectively ABI. Low risk.
- The eBPF build targets `bpfel-unknown-none` (little-endian BPF), which covers x86_64 and aarch64. Big-endian hosts (s390x, MIPS BE) would need `bpfeb-unknown-none`.

## Changelog

- 2026-03-14: Added build-time arch rejection (#34), opt-in auto-install via `TUISHARK_AUTO_INSTALL_DEPS=1`, `ensure_ebpf_toolchain()` returns bool for proper failure propagation, cleaned env vars for bpf-linker install (#35)

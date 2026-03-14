---
title: Phase 12 — FreeBSD Full Cross-Compilation CI Pipeline
date: 2026-03-14
author: Claude Code
status: active
related_issues: ["#32"]
related_mrs: []
---

## Executive Summary

Phase 12 implements a complete CI/CD pipeline for FreeBSD cross-compilation targeting both x86_64 and aarch64 architectures. This extends the existing Phase 11 FreeBSD base port (which achieved `cargo check` validation) with actual binary compilation, testing, and multi-architecture Docker image builds.

**Phase 11 Completed:** `cargo check --target x86_64-unknown-freebsd` validates type safety only; no linking or execution.

**Phase 12 Objective:** Full cross-compilation with linking, inline test execution via QEMU, and multi-arch Docker image creation integrated into the existing manifest strategy.

**Success Criteria:**
- FreeBSD binaries build successfully for x86_64 and aarch64 targets
- All inline `#[cfg(test)]` tests execute and pass on cross-compiled binaries under QEMU
- Docker images created for both FreeBSD architectures and included in multi-arch manifest
- Feature flag strategy ensures eBPF code (Linux-only) excluded from FreeBSD builds
- CI execution time reasonable (≤3 hours total for all FreeBSD jobs in parallel)
- Timestamp handling validated across architecture variations (libc::suseconds_t)

---

## 1. Feature Flag Architecture

### Problem Statement

The `trace` feature in Cargo.toml enables eBPF support via `aya` and `bytes` dependencies, which require Linux kernel eBPF infrastructure. FreeBSD has no compatible eBPF subsystem. Currently:

- Dockerfile line 26: `cargo build --release --locked --features trace -p tuishark` **always enables trace**
- cli.rs lines 67-77, 80-97, 180-200: eBPF integration code has **no feature gates**
- Cargo.toml lines 29-30: Dependencies `aya` and `bytes` are optional but unconditionally included when feature enabled

### Recommended Solution: Target-Specific Feature Disabling

**Implementation:** Add target-specific dependency overrides in Cargo.toml to handle feature flags conditionally.

```toml
# tuishark/Cargo.toml

[dependencies]
# ... existing deps ...
aya = { version = "0.13", optional = true }
bytes = { version = "1", optional = true }

[features]
default = []
trace = ["aya", "bytes"]

# NEW: Target-specific feature handling
[target.'cfg(any(target_os = "linux"))'.dependencies]
# trace feature available on Linux

[target.'cfg(any(target_os = "freebsd"))'.dependencies]
# eBPF deps not pulled on FreeBSD; trace feature effectively disabled
```

**Alternative: Explicit cargo flag in CI/Dockerfile**

More direct and testable: explicitly pass `--features ""` for FreeBSD targets.

```dockerfile
# For Linux builds (existing)
RUN cargo build --release --locked --features trace -p tuishark

# For FreeBSD builds (new)
RUN cargo build --release --locked --target x86_64-unknown-freebsd --features "" -p tuishark
RUN cargo build --release --locked --target aarch64-unknown-freebsd --features "" -p tuishark
```

### Code-Level Feature Gating in cli.rs

Even if dependencies are disabled, code paths must be guarded to prevent compilation errors:

**Lines 67-77 (Trace engine initialization):**
```rust
let mut trace_engine = if enable_trace {
    #[cfg(feature = "trace")]
    {
        match TraceEngine::new() {
            Ok(engine) => Some(engine),
            Err(e) => {
                eprintln!("Warning: eBPF tracing unavailable: {e}");
                None
            }
        }
    }
    #[cfg(not(feature = "trace"))]
    {
        eprintln!("eBPF tracing not available on this platform");
        None
    }
} else {
    None
};
```

**Lines 80-97 (Path engine attachment):**
```rust
let path_engine = if enable_trace_path {
    #[cfg(feature = "trace")]
    {
        if let Some(ref mut engine) = trace_engine {
            // existing code
        } else {
            None
        }
    }
    #[cfg(not(feature = "trace"))]
    {
        eprintln!("Path tracing not available on this platform");
        None
    }
} else {
    None
};
```

**Lines 180-200 (Path event polling):**
```rust
// Poll path events from perf buffer
#[cfg(feature = "trace")]
{
    if let Some(ref mut pe) = path_engine {
        let events = pe.poll();
        // ... existing polling logic
    }
}
#[cfg(not(feature = "trace"))]
{
    // No-op for platforms without eBPF
}
```

### Validation Strategy

- Build with `--features trace` for Linux targets (existing, amd64/arm64)
- Build with `--features ""` for FreeBSD targets
- Verify binary size reduction on FreeBSD (no aya/bytes included)
- Run `cargo tree --target x86_64-unknown-freebsd --features ""` to confirm aya/bytes not included

---

## 2. Cross-Compilation Environment Design

### Challenge

Current Dockerfile assumes Linux (Debian bookworm) with `apt-get` package manager. FreeBSD requires:
- **libpcap development headers** (FreeBSD: `libpcap`, not `libpcap-dev`)
- **pkg-config** (often pre-installed on FreeBSD)
- **rustup with FreeBSD targets**
- **Potential issues:** Build environment is Linux; cross-compilation requires FreeBSD sysroot/headers

### Approach: Use cross-rs with Docker-Based FreeBSD Target

**Key Decision:** Leverage `cross-rs` (https://github.com/cross-rs/cross) which provides pre-configured Docker images for cross-compilation targets including `x86_64-unknown-freebsd` and `aarch64-unknown-freebsd`.

**Why cross-rs:**
- Handles sysroot setup and QEMU emulation automatically
- Provides official Docker images with FreeBSD headers pre-installed
- Simplifies QEMU test execution
- Reduces maintenance burden vs. custom Dockerfile

**Implementation:**

1. **Modify CI configuration** to use cross-rs instead of native cargo for FreeBSD targets
2. **Leverage cross.toml** for per-target configuration
3. **Or:** Use cross-rs Docker images as build containers in .gitlab-ci.yml

### cross.toml Configuration

Create `cross.toml` in project root:

```toml
[build]
# Use custom Docker image for FreeBSD targets if needed
# [target.x86_64-unknown-freebsd]
# image = "custom-freebsd-image:latest"

[target.x86_64-unknown-freebsd]
# Inherit defaults from cross-rs official images

[target.aarch64-unknown-freebsd]
# Inherit defaults from cross-rs official images
```

### Docker Integration Path

If keeping Docker build pipeline (vs. cross-rs CLI in CI):

1. Use `ghcr.io/cross-rs/cross:x86_64-unknown-freebsd` as builder base
2. Install additional deps (if needed) atop cross-rs image
3. Run `cargo build --release --target x86_64-unknown-freebsd --features ""`

**Container Base:** `ghcr.io/cross-rs/cross:1.2.2-freebsd` (FreeBSD sysroot included)

---

## 3. Build Job Structure (.gitlab-ci.yml)

### Current State

Lines 22-41 define `check-freebsd` which only validates types via `cargo check`. Line 38 explicitly comments: "full cross-build CI in Phase 12".

### Phase 12 Replacement: Three New Jobs

#### Job 1: build-freebsd-amd64

**Location:** Insert after `check-freebsd` or replace it (lines 22-41)

```yaml
build-freebsd-amd64:
  stage: build
  timeout: 2h
  tags:
    - x86_64
  image: ghcr.io/cross-rs/cross:latest
  variables:
    CARGO_HOME: ${CI_PROJECT_DIR}/.cargo
    CARGO_BUILD_TARGET: x86_64-unknown-freebsd
  cache:
    key: freebsd-amd64-build
    paths:
      - .cargo/registry/
      - target/x86_64-unknown-freebsd/
  before_script:
    - apt-get update && apt-get install -y pkg-config
    - rustup target add x86_64-unknown-freebsd
  script:
    # Full cross-compilation without trace feature
    - cargo build --release --locked --target x86_64-unknown-freebsd --features "" -p tuishark
    # Run inline tests via QEMU (see Section 4 for details)
    - cargo test --release --locked --target x86_64-unknown-freebsd --features "" -p tuishark
  artifacts:
    paths:
      - target/x86_64-unknown-freebsd/release/tuishark
    expire_in: 1 week
  extends: .build-rules
```

#### Job 2: build-freebsd-arm64

**Location:** After build-freebsd-amd64

```yaml
build-freebsd-arm64:
  stage: build
  timeout: 2h
  tags:
    - aarch64
  image: ghcr.io/cross-rs/cross:latest
  variables:
    CARGO_HOME: ${CI_PROJECT_DIR}/.cargo
    CARGO_BUILD_TARGET: aarch64-unknown-freebsd
  cache:
    key: freebsd-arm64-build
    paths:
      - .cargo/registry/
      - target/aarch64-unknown-freebsd/
  before_script:
    - apt-get update && apt-get install -y pkg-config
    - rustup target add aarch64-unknown-freebsd
  script:
    # Full cross-compilation without trace feature
    - cargo build --release --locked --target aarch64-unknown-freebsd --features "" -p tuishark
    # Run inline tests via QEMU
    - cargo test --release --locked --target aarch64-unknown-freebsd --features "" -p tuishark
  artifacts:
    paths:
      - target/aarch64-unknown-freebsd/release/tuishark
    expire_in: 1 week
  extends: .build-rules
```

#### Job 3: build-freebsd-docker (Optional, Phase 12b)

If Docker images desired for FreeBSD runtime distribution:

```yaml
build-freebsd-docker-amd64:
  stage: build
  timeout: 2h
  tags:
    - x86_64
  image: docker:27
  services:
    - docker:27-dind
  variables:
    DOCKER_TLS_CERTDIR: "/certs"
  before_script:
    - docker login -u "$CI_REGISTRY_USER" -p "$CI_REGISTRY_PASSWORD" "$CI_REGISTRY"
  script:
    # Use multi-platform Dockerfile with --platform=freebsd/amd64
    # Or create separate Dockerfile.freebsd
    - docker build --push --tag "${IMAGE}:${CI_COMMIT_SHORT_SHA}-freebsd-amd64" --platform freebsd/amd64 -f Dockerfile.freebsd .
  extends: .build-rules
```

**Note:** Docker image creation for FreeBSD is **optional in Phase 12**. Phase 12 focus is on CI validation. Phase 13 (Platform Trait Abstraction) may revisit runtime image strategy.

### .build-rules Enhancement

Existing `.build-rules` (lines 9-20) already triggers on source changes. FreeBSD jobs inherit this, so they trigger on `Cargo.lock`, `Cargo.toml`, or `tuishark/**/*` changes.

**No changes needed** to `.build-rules` for Phase 12.

---

## 4. Test Execution Strategy via QEMU

### Challenge

Inline `#[cfg(test)]` tests in save.rs (lines 63-183) include 5 comprehensive unit tests covering pcap roundtrip, timestamp handling, and multi-packet scenarios. These must execute on the **target architecture** to validate platform-specific behavior (libc::suseconds_t differences).

### Solution: cross-rs Test Support

**Good news:** `cross-rs` automatically handles test execution via QEMU when you run `cargo test --target x86_64-unknown-freebsd`.

```bash
# In build-freebsd-amd64 job:
cargo test --release --locked --target x86_64-unknown-freebsd --features "" -p tuishark

# cross-rs:
# 1. Cross-compiles test binary for x86_64-unknown-freebsd
# 2. Launches QEMU with FreeBSD sysroot
# 3. Executes tests under QEMU
# 4. Returns exit code
```

### Specific Tests Validated

From `tuishark/src/capture/save.rs`:

1. **save_empty_store_fails** (lines 100-105)
   - Validates error handling for empty packet store
   - No platform-specific behavior; passes on all architectures

2. **save_no_base_ts_fails** (lines 107-117)
   - Validates error handling without timestamp initialization
   - Platform-agnostic

3. **save_and_reload_roundtrip** (lines 119-153)
   - **CRITICAL FOR PHASE 12:** Validates pcap format and timestamp reconstruction
   - Tests `libc::time_t` and `libc::suseconds_t` clamping (lines 146-149)
   - Base timestamp: `1710000000.123456`, packet offset: `0.5`
   - Verifies tv_sec and tv_usec precision after floor division and rounding
   - **Architecture validation:** Confirms suseconds_t clamping works correctly on both x86_64 and aarch64

4. **save_multiple_packets_roundtrip** (lines 155-182)
   - Validates multi-packet handling (5 packets at 0.1s intervals)
   - Tests consistency across multiple pcap write operations

5. (Implicit integration test)
   - Tests run in `std::env::temp_dir()` with process ID safety
   - Validates file I/O, disk operations, and POSIX semantics

### QEMU Performance Considerations

- **Timeout:** 2 hours allocated per build job should accommodate test execution
- **Performance overhead:** QEMU ~5-10x slower than native execution; full test suite should complete in <10 minutes
- **Test count:** Small test suite (5 tests); no performance concern
- **Parallelization:** amd64 and arm64 jobs run in parallel (separate runners), no sequential overhead

### Test Success Criteria

All tests must pass under QEMU on both architectures:

```yaml
script:
  - cargo test --release --locked --target x86_64-unknown-freebsd --features "" -p tuishark --verbose
```

Exit code 0 indicates all tests passed. Any failure blocks merge.

---

## 5. Platform Validation — Architecture-Specific Types

### Known Variations

#### libc::suseconds_t Differences

From `save.rs` line 41 comment: "Cast directly to suseconds_t for portability (i32 on some FreeBSD arches)".

**Evidence:**
- x86_64-unknown-freebsd: `suseconds_t` may be `i32` or `i64` depending on FreeBSD version
- aarch64-unknown-freebsd: Different definition possible due to ARM ABI differences

**Validation:**
- `save_and_reload_roundtrip` test (line 119-153) directly validates this via roundtrip serialization/deserialization
- Line 147: `let expected_usec = (((base_ts + pkt_ts) - expected_sec as f64) * 1_000_000.0).round() as i64;`
- Line 149: `assert_eq!(reloaded.header.ts.tv_usec as i64, expected_usec);`
- Casting to i64 ensures comparison works regardless of suseconds_t underlying type

**Phase 12 Validation:** Test execution under QEMU on both architectures validates that timestamp clamping (lines 42) works correctly despite type variations.

#### pt_regs Structure (eBPF Context)

From prior ADR context: eBPF `pt_regs` struct differs between x86_64 and aarch64. Since eBPF disabled on FreeBSD (`--features ""`), this is **not a Phase 12 concern** but documented for Phase 27 (CO-RE/BTF migration).

#### libc::time_t

Typically `long` or `i64`; consistent across FreeBSD x86_64 and aarch64. Save.rs line 38:
```rust
let tv_sec = absolute_ts.floor() as libc::time_t;
```

Works correctly on both architectures due to Rust's safe casting semantics.

### Additional Architecture Validation

**CPU architecture differences to monitor:**
- Endianness: Both x86_64 and aarch64 are little-endian (no concern)
- Register size: x86_64=64-bit, aarch64=64-bit (no concern)
- Memory alignment: Both support standard POSIX alignment; pcap format independent of arch
- Pointer size: Both 64-bit; no issue

**Validation via test execution:**
- Tests implicitly validate endianness via pcap binary format roundtrip
- Tests validate alignment via libc struct handling (pcap::PacketHeader with libc::timeval)
- Tests validate pointer handling via Vec::as_slice() operations

---

## 6. Artifact Handling Strategy

### Binary Artifacts

**Location:** CI artifacts stored in `.artifacts/` per .gitlab-ci.yml `artifacts:` blocks.

```yaml
artifacts:
  paths:
    - target/x86_64-unknown-freebsd/release/tuishark
    - target/aarch64-unknown-freebsd/release/tuishark
  expire_in: 1 week
```

**Purpose:** Enable manual download of FreeBSD binaries for testing/deployment without requiring rebuild.

### Cache Strategy

Two separate cache keys to avoid conflicts:

```yaml
cache:
  key: freebsd-amd64-build
  paths:
    - .cargo/registry/
    - target/x86_64-unknown-freebsd/
```

and

```yaml
cache:
  key: freebsd-arm64-build
  paths:
    - .cargo/registry/
    - target/aarch64-unknown-freebsd/
```

**Rationale:** Cargo registry shared across both, but target directories separate to prevent cross-arch conflicts.

### Docker Image Consideration (Phase 12b)

Docker images for FreeBSD runtime are **optional in Phase 12**. Decision points:

**If proceeding with FreeBSD Docker images:**
1. Create `Dockerfile.freebsd` with FreeBSD runtime base (FROM freebsd:13-release or similar)
2. Tag as `${IMAGE}:${CI_COMMIT_SHORT_SHA}-freebsd-amd64` and `freebsd-arm64`
3. Extend manifest creation logic to include FreeBSD images

**If deferring:**
1. Focus Phase 12 on CI validation and binary artifacts
2. Phase 13 (Platform Trait) evaluates runtime strategy
3. Later phases (14-17) address runtime distribution

**Recommendation:** Defer Docker image creation to Phase 13. Phase 12 validates cross-compilation; runtime images depend on platform abstraction decisions.

---

## 7. Manifest Strategy

### Current Manifest Logic (lines 74-111)

Creates multi-arch manifests combining amd64 and arm64 Linux images:

```yaml
create-manifest:
  stage: manifest
  script:
    SOURCES="${IMAGE}:${CI_COMMIT_SHORT_SHA}-amd64 ${IMAGE}:${CI_COMMIT_SHORT_SHA}-arm64"
    docker manifest create "${IMAGE}:${CI_COMMIT_SHORT_SHA}" $SOURCES
    docker manifest push "${IMAGE}:${CI_COMMIT_SHORT_SHA}"
```

### Phase 12 Manifest Extension

**Option A: Keep Linux-only manifest (recommended for Phase 12)**
- FreeBSD builds are binary artifacts only (no Docker image)
- Manifest unchanged; focus on CI validation
- Cleaner separation of concerns

**Option B: Include FreeBSD in manifest (Phase 12b)**
- Requires Docker image builds (see Section 6)
- Extend manifest to include freebsd-amd64 and freebsd-arm64 images
- Add conditional logic:

```yaml
SOURCES="${IMAGE}:${CI_COMMIT_SHORT_SHA}-amd64 ${IMAGE}:${CI_COMMIT_SHORT_SHA}-arm64"
if [ -n "$FREEBSD_IMAGES" ]; then
  SOURCES="$SOURCES ${IMAGE}:${CI_COMMIT_SHORT_SHA}-freebsd-amd64 ${IMAGE}:${CI_COMMIT_SHORT_SHA}-freebsd-arm64"
fi
docker manifest create "${IMAGE}:${CI_COMMIT_SHORT_SHA}" $SOURCES
```

**Recommendation:** Pursue **Option A** for Phase 12. Manifest remains Linux-focused. FreeBSD artifacts are available as build outputs but not part of container distribution until Phase 13+ architecture decisions made.

---

## 8. eBPF Feature-Gating Implementation Details

### Code Changes Required

#### cli.rs — Trace Engine Initialization (lines 67-77)

```rust
// BEFORE:
let mut trace_engine = if enable_trace {
    match TraceEngine::new() {
        Ok(engine) => Some(engine),
        Err(e) => {
            eprintln!("Warning: eBPF tracing unavailable: {e}");
            None
        }
    }
} else {
    None
};

// AFTER:
let mut trace_engine = if enable_trace {
    #[cfg(feature = "trace")]
    {
        match TraceEngine::new() {
            Ok(engine) => Some(engine),
            Err(e) => {
                eprintln!("Warning: eBPF tracing unavailable: {e}");
                None
            }
        }
    }
    #[cfg(not(feature = "trace"))]
    {
        eprintln!("eBPF tracing not available on this platform");
        None
    }
} else {
    None
};
```

#### cli.rs — Path Engine Attachment (lines 80-97)

```rust
// BEFORE:
let path_engine = if enable_trace_path {
    if let Some(ref mut engine) = trace_engine {
        match engine.attach_path_engine() {
            Ok(pe) => {
                eprintln!("Kernel path tracing active.");
                Some(pe)
            }
            Err(e) => {
                eprintln!("Warning: path tracing unavailable: {e}");
                None
            }
        }
    } else {
        None
    }
} else {
    None
};

// AFTER:
let path_engine = if enable_trace_path {
    #[cfg(feature = "trace")]
    {
        if let Some(ref mut engine) = trace_engine {
            match engine.attach_path_engine() {
                Ok(pe) => {
                    eprintln!("Kernel path tracing active.");
                    Some(pe)
                }
                Err(e) => {
                    eprintln!("Warning: path tracing unavailable: {e}");
                    None
                }
            }
        } else {
            None
        }
    }
    #[cfg(not(feature = "trace"))]
    {
        if enable_trace_path {
            eprintln!("eBPF path tracing not available on this platform");
        }
        None
    }
} else {
    None
};
```

#### cli.rs — Path Event Polling (lines 180-200)

```rust
// BEFORE:
if let Some(ref mut pe) = path_engine {
    let events = pe.poll();
    if !events.is_empty() {
        total_path_events += events.len() as u64;
        path_aggregator.ingest(&events);
    }
    // ... rest of polling logic
}

// AFTER:
#[cfg(feature = "trace")]
{
    if let Some(ref mut pe) = path_engine {
        let events = pe.poll();
        if !events.is_empty() {
            total_path_events += events.len() as u64;
            path_aggregator.ingest(&events);
        }
        // ... rest of polling logic
    }
}
```

### Compile-Time Verification

After implementing feature gates, verify compilation:

```bash
# Linux build with trace (existing, should work)
cargo build --release --features trace -p tuishark

# Linux build without trace (new, should work)
cargo build --release --features "" -p tuishark

# FreeBSD cross-compile without trace (new, should work)
cargo build --release --target x86_64-unknown-freebsd --features "" -p tuishark

# Verify aya/bytes not pulled in:
cargo tree --target x86_64-unknown-freebsd --features "" | grep -i aya
# Should return empty (no aya dependency)
```

---

## 9. Implementation Timeline & Phases

### Phase 12a: Core Cross-Compilation (Primary)

**Deliverables:**
- Add `build-freebsd-amd64` job to .gitlab-ci.yml
- Add `build-freebsd-arm64` job to .gitlab-ci.yml
- Implement feature-gating in cli.rs (3 code sections)
- Verify via test execution under QEMU
- Binary artifacts available in CI pipeline

**Timeline:** 1-2 weeks (1 developer)

**GitLab Issue:** One epic or single issue #34 covering entire scope

**MR Review Requirements:**
1. **QA Expert:** Verify test execution on QEMU; confirm all save.rs tests pass on both architectures
2. **Rust Expert:** Review feature-gating implementation; verify no dead code or compilation warnings; check cfg guards properly protect eBPF code
3. **Domain Expert (FreeBSD):** Validate architecture choices; confirm suseconds_t handling correct; verify cross-rs image selection appropriate

### Phase 12b: Docker Image Integration (Optional, defer to Phase 13)

**Deliverables:** (if proceeding)
- Create `Dockerfile.freebsd` with FreeBSD runtime base
- Extend manifest creation to include FreeBSD images
- Tag strategy for freebsd-amd64 and freebsd-arm64

**Timeline:** 1 week (defer to Phase 13)

**Decision Point:** Review Phase 12a results before committing to Docker images. Phase 13 (Platform Trait) may influence runtime strategy.

---

## 10. Risk Assessment & Mitigation

### Risk 1: cross-rs Image Unavailability or Incompatibility

**Severity:** Medium | **Likelihood:** Low

**Mitigation:**
- Verify `ghcr.io/cross-rs/cross` images available for both x86_64-unknown-freebsd and aarch64-unknown-freebsd
- Test locally before committing to CI pipeline
- Create fallback: custom Dockerfile.freebsd if official images unsuitable

### Risk 2: QEMU Test Execution Timeout

**Severity:** Low | **Likelihood:** Medium

**Mitigation:**
- Allocate 2-hour timeout per build job (consistent with existing Linux jobs)
- Monitor test execution time; optimize if exceeding 30 minutes
- Small test suite (5 tests) unlikely to exceed 10 minutes under QEMU

### Risk 3: libc::suseconds_t Type Variations Cause Assertion Failures

**Severity:** High | **Likelihood:** Low

**Mitigation:**
- The `save_and_reload_roundtrip` test (line 119-153) explicitly validates suseconds_t handling
- Test casts to i64 for comparison, accommodating type variations
- If test fails on aarch64-freebsd, indicates architecture-specific issue requiring further investigation
- Fallback: add explicit platform-specific test if needed

### Risk 4: eBPF Code Paths Accidentally Included in FreeBSD Build

**Severity:** High | **Likelihood:** Low**

**Mitigation:**
- Add feature-gating around all eBPF code (cli.rs lines 67-77, 80-97, 180-200)
- Verify via `cargo tree --target x86_64-unknown-freebsd --features ""` that aya/bytes not included
- CI verification: `cargo build --target x86_64-unknown-freebsd --features ""` must succeed without aya errors

### Risk 5: FreeBSD Build Introduces Unintended Regressions in Linux Builds

**Severity:** Medium | **Likelihood:** Low**

**Mitigation:**
- Keep Linux build jobs (build-amd64, build-arm64) unchanged
- Phase 12 additions are FreeBSD-specific; no changes to existing Linux logic
- Run existing test suite on Linux builds to ensure no regression
- Code review focus on feature-gating implementation; ensure no conditional code affects Linux paths

### Risk 6: Platform Validation Incomplete

**Severity:** Low | **Likelihood:** Medium**

**Mitigation:**
- Document all tested behaviors (timestamp handling, file I/O, architecture variations)
- Establish test success criteria upfront (all inline tests pass)
- If edge cases discovered post-Phase 12, create Phase 12+ subtask to address
- Reserve 1-2 additional testing days in timeline

---

## 11. References & Related Work

### ADRs
- **2026-03-12-ebpf-build-from-source.md:** eBPF architecture-specific concerns; explains pt_regs and hardcoded offsets
- **2026-03-10-technology-stack.md:** Dependency justifications for aya, pcap, cross-compilation strategy

### Existing Phase Plans
- **phase5-filter-engine.md:** Display filter architecture
- **phase7-statistics.md:** Statistics and analysis features
- **phase9-config.md:** TOML configuration system
- **roadmap-freebsd-and-visibility.md:** Long-term roadmap; Phase 11-17 context

### External References
- **cross-rs Documentation:** https://github.com/cross-rs/cross
- **FreeBSD Rust Support:** https://wiki.freebsd.org/Rust
- **libc crate documentation:** https://docs.rs/libc/
- **QEMU User Mode Emulation:** https://www.qemu.org/

### Related Issues
- **#32 (Phase 11):** FreeBSD base port; completed `cargo check` validation
- **#27:** eBPF CO-RE/BTF migration (future, related to feature-gating)
- **#9:** Filter enhancements (unrelated to Phase 12)

---

## 12. Success Criteria Checklist

### Pre-Implementation
- [ ] Plan document reviewed and approved by domain expert
- [ ] GitLab issue #34 (Phase 12) created and linked to plan
- [ ] Feature-gating code locations identified (cli.rs lines 67-77, 80-97, 180-200)
- [ ] cross-rs images verified available locally

### Implementation
- [ ] build-freebsd-amd64 job added to .gitlab-ci.yml
- [ ] build-freebsd-arm64 job added to .gitlab-ci.yml
- [ ] Feature-gating implemented in cli.rs (3 sections)
- [ ] `cargo build --target x86_64-unknown-freebsd --features ""` succeeds
- [ ] `cargo build --target aarch64-unknown-freebsd --features ""` succeeds
- [ ] `cargo tree --target x86_64-unknown-freebsd --features ""` shows no aya/bytes

### Testing & Validation
- [ ] All inline tests execute under QEMU on x86_64-unknown-freebsd
- [ ] All inline tests execute under QEMU on aarch64-unknown-freebsd
- [ ] save_and_reload_roundtrip test passes (validates suseconds_t handling)
- [ ] save_multiple_packets_roundtrip test passes (validates multi-arch behavior)
- [ ] Linux builds (amd64, arm64) still pass after Phase 12 changes
- [ ] CI pipeline completes in <3 hours total

### Code Review
- [ ] QA Expert: Tests pass on QEMU; all tests validated
- [ ] Rust Expert: Feature-gating correct; no dead code; cfg guards proper
- [ ] Domain Expert: Architecture strategy sound; cross-rs choice justified; FreeBSD requirements met

### Post-Implementation
- [ ] FreeBSD binaries available as CI artifacts
- [ ] Documentation updated (if needed) to reflect FreeBSD support
- [ ] Linked to Phase 13 (Platform Trait Abstraction) for future work

---

## 13. Next Steps

1. **Create GitLab Issue #34** (Phase 12) linking to this plan
2. **Assign to developer** with FreeBSD/cross-compilation interest
3. **Local validation:** Test cross-rs images and build pipeline locally before CI commit
4. **Implement Phase 12a** (core cross-compilation) per timeline
5. **Code review** per three-expert review policy
6. **Defer Phase 12b** (Docker images) to Phase 13 unless high priority
7. **Track Phase 13 start:** Platform Trait Abstraction depends on Phase 12 completion


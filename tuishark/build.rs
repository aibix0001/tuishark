use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    if cfg!(feature = "trace") {
        let out_dir = env::var("OUT_DIR").unwrap();
        let dst = Path::new(&out_dir).join("tuishark-ebpf");

        // Try to compile eBPF from source so bpf_target_arch matches the current host.
        // This is critical: aya-ebpf bakes the host's pt_regs layout into the bytecode
        // at compile time, so a blob built on x86_64 silently breaks on aarch64.
        // Expose the host architecture so engine.rs can reject mismatched blobs at runtime
        let host_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "unknown".into());

        if let Some(built) = try_build_ebpf() {
            fs::copy(&built, &dst).unwrap_or_else(|e| {
                panic!("Failed to copy freshly built eBPF binary to OUT_DIR: {e}");
            });
            // From-source build always matches the host
            println!("cargo:rustc-env=TUISHARK_EBPF_ARCH={host_arch}");
        } else {
            // Fallback: use precompiled blob (may have wrong pt_regs for this arch)
            let precompiled = Path::new("ebpf/tuishark-ebpf");
            if precompiled.exists() {
                // Record the blob's architecture from the sidecar file, or "unknown"
                let blob_arch_file = Path::new("ebpf/tuishark-ebpf.arch");
                let blob_arch = if blob_arch_file.exists() {
                    fs::read_to_string(blob_arch_file)
                        .unwrap_or_else(|_| "unknown".into())
                        .trim()
                        .to_string()
                } else {
                    "unknown".into()
                };
                println!("cargo:rustc-env=TUISHARK_EBPF_ARCH={blob_arch}");
                println!(
                    "cargo:warning=Using precompiled eBPF blob (arch={blob_arch}) — \
                     if eBPF tracing doesn't work, install nightly + bpf-linker \
                     and rebuild so pt_regs matches this architecture"
                );
                fs::copy(precompiled, &dst)
                    .expect("Failed to copy precompiled eBPF binary to OUT_DIR");
            } else {
                panic!(
                    "eBPF binary not found and cannot build from source.\n\
                     Install: rustup toolchain install nightly && \
                     rustup component add rust-src --toolchain nightly && \
                     cargo install bpf-linker\n\
                     Or build manually: cd tuishark-ebpf && bash build.sh"
                );
            }
        }

        // Rerun when eBPF source or config changes.
        // Note: watching a directory only triggers on child add/remove, NOT content edits.
        // We must list individual source files to catch edits to existing files.
        let ebpf_src = Path::new(env::var("CARGO_MANIFEST_DIR").unwrap().as_str())
            .join("../tuishark-ebpf/src");
        if ebpf_src.is_dir() {
            for entry in fs::read_dir(&ebpf_src).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "rs") {
                    println!("cargo:rerun-if-changed={}", path.display());
                }
            }
        }
        // Also watch Cargo.toml/lock for dependency changes
        println!("cargo:rerun-if-changed=../tuishark-ebpf/Cargo.toml");
        println!("cargo:rerun-if-changed=../tuishark-ebpf/Cargo.lock");
        // Also rerun if precompiled blob or arch sidecar changes (manual rebuild)
        println!("cargo:rerun-if-changed=ebpf/tuishark-ebpf");
        println!("cargo:rerun-if-changed=ebpf/tuishark-ebpf.arch");
    }
}

/// Try to compile the eBPF crate from source using nightly + bpf-linker.
/// Returns the path to the built binary on success, None on failure.
fn try_build_ebpf() -> Option<PathBuf> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let ebpf_dir = Path::new(&manifest_dir).join("../tuishark-ebpf");
    if !ebpf_dir.join("Cargo.toml").exists() {
        println!("cargo:warning=tuishark-ebpf source not found, skipping from-source build");
        return None;
    }

    // Check that cargo +nightly is available
    let nightly_ok = Command::new("cargo")
        .args(["+nightly", "--version"])
        .output()
        .map_or(false, |o| o.status.success());
    if !nightly_ok {
        println!("cargo:warning=Nightly toolchain not available, skipping eBPF from-source build");
        return None;
    }

    // Nested cargo invocations inherit env vars that cause conflicts.
    // Clear CARGO_* vars that interfere with the inner build.
    // bpfel = little-endian BPF. Covers x86_64 and aarch64 (both LE).
    // A big-endian host (s390x, some MIPS) would need bpfeb-unknown-none.
    let mut cmd = Command::new("cargo");
    cmd.args([
        "+nightly",
        "build",
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
        "--release",
    ])
    .current_dir(&ebpf_dir);

    // Remove env vars set by the outer cargo that break nested builds.
    // Preserve CARGO_HOME and registry/network config for corporate/proxy environments.
    let preserve = |k: &str| -> bool {
        k == "CARGO_HOME"
            || k.starts_with("CARGO_REGISTRIES_")
            || k.starts_with("CARGO_HTTP_")
            || k.starts_with("CARGO_NET_")
    };
    for (key, _) in env::vars() {
        if (key.starts_with("CARGO_") && !preserve(&key)) || key == "RUSTUP_TOOLCHAIN" {
            cmd.env_remove(&key);
        }
    }
    // Also clear vars that leak from the outer build and confuse the inner nightly build
    cmd.env_remove("__CARGO_DEFAULT_LIB_METADATA");
    cmd.env_remove("RUSTC");
    cmd.env_remove("RUSTC_WRAPPER");
    cmd.env_remove("RUSTC_WORKSPACE_WRAPPER");
    cmd.env_remove("RUSTFLAGS");
    cmd.env_remove("CARGO_ENCODED_RUSTFLAGS");

    let output = cmd.output();

    match output {
        Ok(o) if o.status.success() => {
            let built = ebpf_dir.join("target/bpfel-unknown-none/release/tuishark-ebpf");
            if built.exists() {
                Some(built)
            } else {
                println!(
                    "cargo:warning=eBPF build succeeded but output not found at {}",
                    built.display()
                );
                None
            }
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            let exit = match o.status.code() {
                Some(c) => c.to_string(),
                None => "signal".into(),
            };
            println!("cargo:warning=eBPF from-source build failed (exit {exit}):");
            // Emit last 15 lines as separate warnings so they render reliably
            let lines: Vec<&str> = stderr.lines().collect();
            let start = lines.len().saturating_sub(15);
            for line in &lines[start..] {
                println!("cargo:warning=  {line}");
            }
            None
        }
        Err(e) => {
            println!("cargo:warning=Could not invoke cargo for eBPF build: {e}");
            None
        }
    }
}

#!/bin/bash
# Build the eBPF program and copy it to the main crate for embedding.
# Requires: nightly Rust toolchain, bpf-linker, rust-src component
set -e

cd "$(dirname "$0")"

cargo +nightly build \
    --target bpfel-unknown-none \
    -Z build-std=core \
    --release

cp target/bpfel-unknown-none/release/tuishark-ebpf ../tuishark/ebpf/tuishark-ebpf

# Record the Rust-canonical architecture name so the fallback path can validate
# at runtime against std::env::consts::ARCH. uname -m diverges on some platforms
# (e.g. armv7l vs arm, i686 vs x86), so we use rustc to get the canonical name.
RUST_ARCH=$(rustc -vV | grep '^host:' | cut -d- -f1 | awk '{print $2}')
echo "$RUST_ARCH" > ../tuishark/ebpf/tuishark-ebpf.arch

echo "eBPF binary built and copied to tuishark/ebpf/tuishark-ebpf (arch: $RUST_ARCH)"

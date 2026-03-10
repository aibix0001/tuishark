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

echo "eBPF binary built and copied to tuishark/ebpf/tuishark-ebpf"

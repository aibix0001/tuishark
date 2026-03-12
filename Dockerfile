# syntax=docker/dockerfile:1
# Multi-stage build for tuishark — terminal packet analyzer
# Supports linux/amd64 and linux/arm64 via docker buildx

# ── Build stage ──────────────────────────────────────────────
FROM rust:bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install nightly toolchain + bpf-linker for eBPF from-source build
RUN rustup toolchain install nightly \
    && rustup component add rust-src --toolchain nightly \
    && cargo install bpf-linker

WORKDIR /src
COPY . .

# Build with eBPF tracing support.
# build.rs compiles the eBPF crate from source so pt_regs matches the target arch.
RUN cargo build --release --features trace -p tuishark

# ── Runtime stage ────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 \
        tshark \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/tuishark /usr/local/bin/tuishark

# NET_RAW for packet capture, SYS_ADMIN + BPF for eBPF tracing
# (must be granted at runtime via --cap-add)
ENTRYPOINT ["tuishark"]

# syntax=docker/dockerfile:1
# Multi-stage build for tuishark — terminal packet analyzer
# Supports linux/amd64 and linux/arm64 via docker buildx

# ── Build stage ──────────────────────────────────────────────
# Pin Rust version for reproducible builds.
# Both stages use bookworm to ensure libpcap soname compatibility.
FROM rust:1.94-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install nightly toolchain + bpf-linker for eBPF from-source build.
# Pin bpf-linker version to avoid breakage from upstream LLVM changes.
RUN rustup toolchain install nightly \
    && rustup component add rust-src --toolchain nightly \
    && cargo install bpf-linker@0.10.2

WORKDIR /src
COPY . .

# Build with eBPF tracing support.
# build.rs compiles the eBPF crate from source so pt_regs matches the target arch.
RUN cargo build --release --locked --features trace -p tuishark

# ── Runtime stage ────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 \
        tshark \
        tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/tuishark /usr/local/bin/tuishark

# Run as non-root. Capabilities (NET_RAW, SYS_ADMIN, BPF) are granted to
# the container at runtime via --cap-add, not to the user.
RUN groupadd --system tuishark && useradd --system --gid tuishark tuishark
USER tuishark

LABEL org.opencontainers.image.source="https://git.lab.aibix.io/aibix0001/tuishark"
LABEL org.opencontainers.image.description="Terminal-based packet analyzer"

# tini handles PID 1 signal forwarding (graceful docker stop)
ENTRYPOINT ["tini", "--", "tuishark"]

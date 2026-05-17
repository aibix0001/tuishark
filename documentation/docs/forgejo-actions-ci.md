---
title: "Forgejo Actions CI"
date: 2026-05-17
author: agent
status: active
related_issues: [43, 44]
related_mrs: []
---

## Overview

The repository is mirrored to a Forgejo remote
(`ssh://git@forgejo.lab.aibix.io:224/aibix/tuishark.git`). Previously only
`.gitlab-ci.yml` existed, so pushes to the Forgejo mirror ran no CI. Two
Forgejo Actions workflows under `.forgejo/workflows/` give the mirror
independent coverage that parallels the GitLab pipeline:

- **`ci.yml`** — fmt / clippy / test / FreeBSD type-check on every push and
  pull request.
- **`docker.yml`** — native per-arch container builds (amd64 + arm64) and a
  combined multi-arch manifest, mirroring the `build-*` / `create-manifest`
  stages of `.gitlab-ci.yml`.

## Usage

The workflows run automatically on the Forgejo mirror:

| Workflow | Trigger | Runner(s) |
|---|---|---|
| `ci.yml` | every `push` (any branch) and `pull_request` | `ubuntu-latest` |
| `docker.yml` | `push` to any branch (when a build input changed) or any tag | `ubuntu-latest` (amd64), `arm64` (native), `ubuntu-latest` (manifest) |

`docker.yml` uses a path filter equivalent to `.build-rules` in
`.gitlab-ci.yml`: branch pushes build only when `Dockerfile`,
`.dockerignore`, `.forgejo/workflows/docker.yml`, `Cargo.lock`,
`Cargo.toml`, `tuishark/**`, or `tuishark-ebpf/**` change. Tag pushes
always build (releases).

Image tagging matches the GitLab pipeline:

- `<short-sha>` (always)
- `<branch>` (sanitised) on branch pushes
- `latest` on the default branch
- `<tag>` on tag pushes

## Configuration

`docker.yml` reads registry/auth settings from Forgejo repo or org
settings so they can change without editing the workflow:

| Setting | Type | Default | Purpose |
|---|---|---|---|
| `REGISTRY` | variable | `forgejo.lab.aibix.io` | container registry host |
| `IMAGE_NAME` | variable | `aibix/tuishark` | image path under the registry |
| `REGISTRY_TOKEN` | secret | falls back to the automatic `github.token` | package-write credential |

If the Forgejo container registry runs on a non-standard host/port, set
the `REGISTRY` variable accordingly (e.g. `forgejo.lab.aibix.io:3000`).

### fmt / clippy are report-only

The existing codebase is not yet rustfmt-clean (283 files differ) and
GitLab CI never enforced `fmt` or `clippy`. To keep the first Forgejo run
green, the `cargo fmt --check` and `cargo clippy` steps in `ci.yml` are
marked `continue-on-error: true` — they report drift without failing the
build. `cargo test` and the FreeBSD type-check remain blocking.

Promoting these to hard gates (and removing `continue-on-error`) is
tracked in issue #44.

## Technical Details

- **No third-party actions for Docker.** `docker.yml` uses the raw
  `docker` CLI (`docker login --password-stdin`,
  `docker buildx build --push`, `docker buildx imagetools create`) so it
  does not depend on `docker/*` actions being mirrored on the Forgejo
  instance. `actions/checkout@v4` is the only external action used (widely
  proxied by Forgejo runners).
- **Native multi-arch, no QEMU.** amd64 builds on `ubuntu-latest`, arm64
  on the native `arm64` runner; `manifest` combines the two per-arch
  images with `docker buildx imagetools create` (no experimental flag
  required).
- **Rust pinned to 1.94.0** in `ci.yml`, matching the `Dockerfile` and
  `.gitlab-ci.yml` for reproducibility. Installed via `rustup` on the
  runner; the FreeBSD target is added for the type-check gate.
- **System dependencies** installed in `ci.yml`: `libpcap-dev` +
  `pkg-config` (the `pcap` crate links libpcap), `build-essential`
  (linker for native crates), and `tshark` (deep-dissection integration
  tests; the `wireshark-common` debconf prompt is preseeded
  non-interactively).
- **`trace` is not a default feature**, so eBPF code (nightly +
  bpf-linker) is excluded from `ci.yml`; the eBPF build remains exercised
  by the Docker image, which builds with `--features trace`.
- **Runner assumptions:** `ubuntu-latest` resolves to a Debian/Ubuntu
  image with apt/git/node; both build runners have Docker ≥ 23 (buildx)
  available. The `apt-get` step prefixes `sudo` only when not running as
  root, to work across runner base images.
- **Concurrency:** both workflows cancel superseded runs on the same ref.

## Changelog

- 2026-05-17: Initial Forgejo Actions workflows added (`ci.yml`,
  `docker.yml`); fmt/clippy report-only pending cleanup (#44).

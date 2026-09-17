# jess-ironrdp-broker — multi-stage: rust:1.89-slim builder → distroless/cc.
#
# Build layout: workspace cache primed by copying Cargo.toml + dummy
# src/ first (so the dependency layer caches independently of source
# churn), then real sources copied + final cargo build.
#
# Distroless/cc carries libc + ld-linux + ca-certs, which is what
# reqwest's rustls backend needs at runtime. Image is ~50MB before
# the binary, plus ~25MB for our binary — well under any registry size
# concern.
#
# IMPORTANT: COPY paths are REPO-ROOT-RELATIVE because the shared
# shared-ci-templates/templates/build-service.yml sets the BuildKit context
# to ${CI_PROJECT_DIR}, not to SERVICE_PATH. SERVICE_PATH only
# controls where buildctl looks for THIS Dockerfile, not the build
# context. Keeping COPYs prefixed with services/ironrdp-broker/ keeps
# the lane working under that contract.

# syntax=docker/dockerfile:1.7
# Rust 1.89 is the floor for the IronRDP 0.15 / sspi 0.21 dep tree
# (post-2026-06-02 upgrade that fixed the sspi 0.15.14 ↔ picky
# 7.0.0-rc.23 build break — see services/ironrdp-broker/Cargo.toml
# header for the version-skew context). Earlier transitives stay
# compatible at 1.89; reverse-MSRV bumps are unlikely. Bumping to the
# highest
# MSRV in one step keeps the dep solver unconstrained. Keep in lockstep
# with rust-toolchain.toml.
ARG RUST_VERSION=1.89
ARG DEBIAN_TAG=bookworm-slim

# ---- builder -----------------------------------------------------------------
FROM rust:${RUST_VERSION}-slim AS builder

# pkg-config + libssl-dev only if a later crate flips from rustls to
# openssl; current Cargo.toml is rustls-only so build deps stay minimal.
# g++: OpenH264 (openh264-sys2, ADR 0061) is C++ — the slim image lacks c++, so
# the build fails with 'failed to find tool "c++"' without it. (This bin doesn't
# enable openh264 today, but keep the builder toolchain consistent with the
# session_live stage so enabling it here later doesn't break the lane.) nasm:
# optional SIMD for openh264's ~3x encode speedup (builds without it too).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    g++ \
    nasm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

# Prime the cargo dependency layer. Empty crate stubs let cargo resolve
# + fetch + compile deps; we'll overwrite src/* with real sources in
# the next layer.
COPY services/ironrdp-broker/Cargo.toml .
# Cargo.lock MUST be copied so the build resolves the committed, pinned
# versions. Without it cargo resolves fresh and grabs newer deps — e.g.
# `time 0.3.50`, which fails `error[E0432]: unresolved import
# time_macros::timestamp` and broke every jess-ironrdp-broker build. The
# `--locked` flags below then guarantee the lock is honoured (and CI fails
# loudly if the lock is ever stale, instead of silently drifting).
COPY services/ironrdp-broker/Cargo.lock .
COPY services/ironrdp-broker/rust-toolchain.toml .
COPY services/ironrdp-broker/crates/proxy-core/Cargo.toml crates/proxy-core/Cargo.toml
COPY services/ironrdp-broker/crates/broker-bin/Cargo.toml crates/broker-bin/Cargo.toml
# The workspace Cargo.toml carries a [patch.crates-io] that points
# ironrdp-connector at vendor/ironrdp-connector (a forked copy that flips
# on SUPPORT_DYN_VC_GFX_PROTOCOL so Windows opens the GFX DVC). cargo reads
# that patch as soon as it parses Cargo.toml — i.e. in the dependency-prime
# layer below, not just the real build — so the vendor tree must be present
# here or the build dies with "vendor/ironrdp-connector/Cargo.toml: No such
# file or directory". Its own deps (ironrdp-*, picky, sspi) are registry
# versions, so this single copy is self-contained.
COPY services/ironrdp-broker/vendor vendor
RUN mkdir -p crates/proxy-core/src crates/broker-bin/src \
 && echo "fn main() {}" > crates/broker-bin/src/main.rs \
 && echo "" > crates/proxy-core/src/lib.rs \
 && cargo build --release --workspace --locked || true

# Real sources.
COPY services/ironrdp-broker/crates crates
RUN touch crates/proxy-core/src/lib.rs crates/broker-bin/src/main.rs \
 && cargo build --release --bin jess-ironrdp-broker --locked

# ---- runtime -----------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=builder /work/target/release/jess-ironrdp-broker /app/jess-ironrdp-broker

# Distroless 'nonroot' runs as uid 65532 — k8s restricted PodSecurity
# is satisfied without any further securityContext nudging. The pod
# spec still pins runAsNonRoot=true + readOnlyRootFilesystem=true as
# belt-and-braces (matching jess-controller / jess-worker chart shape).
EXPOSE 7102
USER nonroot:nonroot
ENTRYPOINT ["/app/jess-ironrdp-broker"]

# syntax=docker/dockerfile:1.7
#
# Jess broker image — builds all FOUR binaries (jess-controller, jess-worker,
# jessctl, jess-web) into one minimal distroless image. The k8s Deployments
# select the binary via `command:` (controller vs worker vs web). Built by
# the platform BuildKit pipeline (shared-ci-templates .build-service); the netrc
# secret-mount lets `go mod download` fetch private github.com
# modules without baking the PAT into a layer. Production build is
# CGO_ENABLED=0 (static); the -race tests that need cgo run only in CI's
# go-test job.
#
# jess-web's React+TypeScript SPA is built in a separate Node stage so the
# Go stage doesn't carry npm. The Vite dist/ tree is then copied INTO the
# Go build context at cmd/jess-web/web/dist/ where `//go:embed all:web/dist`
# picks it up. Doing the SPA build inside Docker (not relying on CI to ship
# a pre-built dist artefact) is the defence-in-depth choice: the image
# never trusts an external artefact and is reproducible from source alone.
#
# The Rust `session_live` binary (services/ironrdp-broker, ironrdp_live
# feature) is built in its OWN stage and COPYied into the runtime image so
# the in-process jess-web RDP-live bridge (cmd/jess-web/ws_rdp_live.go) can
# spawn it at /usr/local/bin/session_live (JESS_RDP_SESSION_BIN default). It
# is a separate stage (not the ironrdp-broker's standalone image) because the
# bin must live IN the jess-web runtime image — jess-web spawns it as a
# subprocess, it is not a separate Deployment. The final image switches from
# distroless/static to distroless/cc: session_live is a dynamically-linked
# rustls/aws-lc-rs binary needing glibc + ld-linux + ca-certs (the same base
# the standalone ironrdp-broker image already uses); the static Go binaries
# run unchanged on cc (it is a superset of static).

# ----- Frontend builder: Vite SPA into /web/dist ----------------------------
FROM mirror.gcr.io/library/node:22-bookworm AS frontend
WORKDIR /web

# Layer-cache friendly: install deps first so source-only changes don't
# bust the npm install cache.
COPY cmd/jess-web/web/package.json cmd/jess-web/web/pnpm-lock.yaml ./
RUN corepack enable pnpm && pnpm install --frozen-lockfile

# Then source. tsconfig*.json + vite.config.ts + index.html + src/ — that
# is everything the build needs. Keep this list explicit so adding new
# top-level files doesn't accidentally get embedded.
COPY cmd/jess-web/web/tsconfig.json \
     cmd/jess-web/web/tsconfig.app.json \
     cmd/jess-web/web/tsconfig.node.json \
     cmd/jess-web/web/vite.config.ts \
     cmd/jess-web/web/index.html ./
COPY cmd/jess-web/web/src ./src

# `pnpm build` runs tsc -b && vite build && writes dist/.gitkeep (the
# touch hook protects the dir against Vite's emptyOutDir wipe).
RUN pnpm build

# ----- Rust builder: session_live (ADR 0051 ironrdp_live) -------------------
# Compiles the live RDP streaming bin the jess-web RDP-live bridge spawns.
# Same toolchain floor + dependency-cache priming pattern as the standalone
# services/ironrdp-broker/Dockerfile (Rust 1.89 is the IronRDP 0.15 / sspi
# 0.21 floor). Built under the ironrdp_live feature so it is the real
# CredSSP/streaming binary, not the default handshake-only broker.
# Pin -slim-bookworm (NOT bare -slim, which floats to Debian trixie = glibc
# 2.41): the runtime base is distroless/cc-DEBIAN12 (= bookworm, glibc 2.36),
# so the builder MUST be bookworm too or the dynamically-linked session_live
# fails at load with `GLIBC_2.38 not found`. Bookworm↔bookworm keeps the ABI
# aligned.
FROM mirror.gcr.io/library/rust:1.89-slim-bookworm AS rust-session-live
# g++: OpenH264 (openh264-sys2, ADR 0061 software H.264) is C++ — the slim image
# ships gcc/cc but NOT c++, so cc-rs fails with 'failed to find tool "c++"'
# without it. nasm: optional SIMD asm for openh264 (~3x encode speedup; builds
# without it via the C fallback). ca-certificates + pkg-config as before.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates pkg-config g++ nasm \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
# Prime the cargo dependency layer with crate stubs so deps fetch+compile
# independently of source churn.
COPY services/ironrdp-broker/Cargo.toml services/ironrdp-broker/Cargo.lock services/ironrdp-broker/rust-toolchain.toml ./
COPY services/ironrdp-broker/crates/proxy-core/Cargo.toml crates/proxy-core/Cargo.toml
COPY services/ironrdp-broker/crates/broker-bin/Cargo.toml crates/broker-bin/Cargo.toml
# The broker workspace Cargo.toml carries a [patch.crates-io] that points
# ironrdp-connector at vendor/ironrdp-connector (the GFX-DVC-enabled fork).
# cargo reads that patch as soon as it parses Cargo.toml, so the vendor tree
# must be present before the dependency-prime build below or it dies with
# "vendor/ironrdp-connector/Cargo.toml: No such file or directory". Same fix
# as services/ironrdp-broker/Dockerfile.
COPY services/ironrdp-broker/vendor vendor
RUN mkdir -p crates/proxy-core/src/bin crates/broker-bin/src \
 && echo "fn main() {}" > crates/broker-bin/src/main.rs \
 && echo "" > crates/proxy-core/src/lib.rs \
 && echo "fn main() {}" > crates/proxy-core/src/bin/session_live.rs \
 && cargo build --release -p jess-ironrdp-proxy-core \
      --features jess-ironrdp-proxy-core/ironrdp_live --bin session_live || true
# Real sources + the actual session_live build.
COPY services/ironrdp-broker/crates crates
RUN touch crates/proxy-core/src/lib.rs crates/proxy-core/src/bin/session_live.rs \
 && cargo build --release -p jess-ironrdp-proxy-core \
      --features jess-ironrdp-proxy-core/ironrdp_live --bin session_live

# ----- Go builder: 4 binaries ----------------------------------------------
FROM mirror.gcr.io/library/golang:1.26-bookworm AS build
WORKDIR /src

    GOFLAGS=-mod=mod \
    CGO_ENABLED=0

# GOPROXY plumbed from shared-ci-templates .build-service template via
# `--opt build-arg:GOPROXY=…` (line 131 of build-service.yml). The shared
# template passes the Athens proxy URL; the Dockerfile MUST declare the
# ARG + propagate it to ENV for `go mod download` to see it. Without
# this declaration, the build-arg is silently ignored and `go mod
# download` falls back to direct → proxy.golang.org over the runner pod's
# WAN egress. Same gotcha that bit talon + falcon-id (paired MRs today).
# Default `direct` keeps local `docker build` working when Athens isn't
# reachable.
ARG GOPROXY=direct
ENV GOPROXY=$GOPROXY

COPY go.mod go.sum ./
RUN --mount=type=secret,id=netrc,target=/root/.netrc \
    go mod download

COPY . .

# Replace the .gitkeep-only web/dist (committed for fresh-clone embed
# safety) with the real Vite output. MUST land BEFORE `go build` so the
# `//go:embed all:web/dist` in cmd/jess-web/main.go sees the actual bundle.
COPY --from=frontend /web/dist ./cmd/jess-web/web/dist

RUN go build -trimpath -ldflags="-s -w" -o /out/jess-controller ./cmd/jess-controller && \
    go build -trimpath -ldflags="-s -w" -o /out/jess-worker     ./cmd/jess-worker     && \
    go build -trimpath -ldflags="-s -w" -o /out/jessctl         ./cmd/jessctl         && \
    go build -trimpath -ldflags="-s -w" -o /out/jess-web        ./cmd/jess-web

# ----- Final distroless ----------------------------------------------------
# distroless/cc (not /static): the Rust session_live bin is dynamically
# linked (glibc + ld-linux + ca-certs via rustls/aws-lc-rs). The static Go
# binaries run unchanged on cc. Same base the standalone ironrdp-broker image
# uses, so the supply-chain/scan posture is identical.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/jess-controller /usr/local/bin/jess-controller
COPY --from=build /out/jess-worker     /usr/local/bin/jess-worker
COPY --from=build /out/jessctl         /usr/local/bin/jessctl
COPY --from=build /out/jess-web        /usr/local/bin/jess-web
# session_live for the in-process jess-web RDP-live bridge. JESS_RDP_SESSION_BIN
# defaults to this path so the deployed jess-web finds it with no extra config.
COPY --from=rust-session-live /work/target/release/session_live /usr/local/bin/session_live
ENV JESS_RDP_SESSION_BIN=/usr/local/bin/session_live
USER nonroot:nonroot
# Default entry is still the controller; the worker + jess-web Deployments
# override command:[...] to select their binary.
ENTRYPOINT ["/usr/local/bin/jess-controller"]

# syntax=docker/dockerfile:1.7
#
# Jess images. Build targets:
#
#   demo     Debian slim with jess-controller, jess-worker and jessctl plus the
#            tools the demo scripts use (curl, jq, openssl, ssh, psql). Used by
#            demo/docker-compose.yml. Runs as root; development use only.
#   release  (default, last stage) distroless image with all four binaries and
#            the Rust session_live binary that jess-web spawns for RDP.
#
#   docker build --target demo -t jess-demo:local .
#   docker build -t jess .
#
# The release image builds the web console (Node) and the RDP binary (Rust)
# first, so it takes a while on a cold cache. The demo target skips both.

# ----- Frontend: Vite SPA into /web/dist ------------------------------------
FROM node:22-bookworm AS frontend
WORKDIR /web
COPY cmd/jess-web/web/package.json cmd/jess-web/web/pnpm-lock.yaml ./
RUN corepack enable pnpm && pnpm install --frozen-lockfile
COPY cmd/jess-web/web/tsconfig.json \
     cmd/jess-web/web/tsconfig.app.json \
     cmd/jess-web/web/tsconfig.node.json \
     cmd/jess-web/web/vite.config.ts \
     cmd/jess-web/web/index.html ./
COPY cmd/jess-web/web/src ./src
COPY cmd/jess-web/web/public ./public
RUN pnpm build

# ----- Rust: session_live, the RDP streaming binary jess-web spawns ---------
# Rust 1.89 is the floor for the IronRDP 0.15 / sspi 0.21 dependency tree and
# must match services/ironrdp-broker/rust-toolchain.toml. The -bookworm tag
# matches the glibc of the distroless/cc-debian12 runtime base.
FROM rust:1.89-slim-bookworm AS rust-session-live
# g++ and nasm: OpenH264 (software H.264) is C++ with optional SIMD assembly.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates pkg-config g++ nasm \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY services/ironrdp-broker/Cargo.toml services/ironrdp-broker/Cargo.lock services/ironrdp-broker/rust-toolchain.toml ./
COPY services/ironrdp-broker/crates/proxy-core/Cargo.toml crates/proxy-core/Cargo.toml
COPY services/ironrdp-broker/crates/broker-bin/Cargo.toml crates/broker-bin/Cargo.toml
# The workspace has a [patch.crates-io] pointing at vendor/, and cargo reads it
# as soon as it parses Cargo.toml, so vendor/ must exist before the first build.
COPY services/ironrdp-broker/vendor vendor
# Prime the dependency layer with empty crates so it caches across source edits.
RUN mkdir -p crates/proxy-core/src/bin crates/broker-bin/src \
 && echo "fn main() {}" > crates/broker-bin/src/main.rs \
 && echo "" > crates/proxy-core/src/lib.rs \
 && echo "fn main() {}" > crates/proxy-core/src/bin/session_live.rs \
 && cargo build --release --locked -p jess-ironrdp-proxy-core \
      --features jess-ironrdp-proxy-core/ironrdp_live --bin session_live || true
COPY services/ironrdp-broker/crates crates
RUN touch crates/proxy-core/src/lib.rs crates/proxy-core/src/bin/session_live.rs \
 && cargo build --release --locked -p jess-ironrdp-proxy-core \
      --features jess-ironrdp-proxy-core/ironrdp_live --bin session_live

# ----- Go: shared module cache ----------------------------------------------
FROM golang:1.27-bookworm AS gobase
WORKDIR /src
ENV GOFLAGS=-mod=mod \
    CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# controller, worker and CLI (no web console needed)
FROM gobase AS build-core
RUN go build -trimpath -ldflags="-s -w" -o /out/jess-controller ./cmd/jess-controller && \
    go build -trimpath -ldflags="-s -w" -o /out/jess-worker     ./cmd/jess-worker     && \
    go build -trimpath -ldflags="-s -w" -o /out/jessctl         ./cmd/jessctl

# web console: needs the built SPA in cmd/jess-web/web/dist (go:embed)
FROM gobase AS build-web
COPY --from=frontend /web/dist ./cmd/jess-web/web/dist
RUN go build -trimpath -ldflags="-s -w" -o /out/jess-web ./cmd/jess-web

# ----- demo ------------------------------------------------------------------
FROM debian:bookworm-slim AS demo
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates curl jq openssl openssh-client postgresql-client \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build-core /out/ /usr/local/bin/

# ----- release (default) -----------------------------------------------------
# distroless/cc, not /static: session_live is dynamically linked (glibc,
# rustls/aws-lc-rs). The static Go binaries run unchanged on it.
FROM gcr.io/distroless/cc-debian12:nonroot AS release
COPY --from=build-core /out/ /usr/local/bin/
COPY --from=build-web  /out/jess-web /usr/local/bin/jess-web
COPY --from=rust-session-live /work/target/release/session_live /usr/local/bin/session_live
ENV JESS_RDP_SESSION_BIN=/usr/local/bin/session_live
USER nonroot:nonroot
# The default entry point is the controller. Run the other binaries by
# overriding the command (jess-worker, jess-web, jessctl).
ENTRYPOINT ["/usr/local/bin/jess-controller"]

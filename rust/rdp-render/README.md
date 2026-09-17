# rdp-render — sandboxed Rust RDP render worker (ADR 0030 Phase 5e)

> Scaffold. The single Rust component in the otherwise-Go Jess product: a
> headless RDP client that decodes a target's RDP stream server-side and emits a
> display-agnostic drawing stream to the Go `jess-web` worker, which relays it to
> the browser canvas and tees it to the tamper-evident recorder.

## Why Rust / why a separate process

- **RDP must not be done in Go or C here.** Pure-Go RDP libraries are immature;
  FreeRDP (C) had 61 CVEs in 2026 — unacceptable for a component that parses
  untrusted bytes from a privileged target. **Devolutions IronRDP** (Rust,
  MIT/Apache-2.0, sans-I/O, memory-safe, actively maintained) is what Teleport
  and Cloudflare both use. Its `screenshot.rs` example is already a headless
  `connect → ActiveStage loop → DecodedImage (RGBA) → image` pipeline — exactly
  our per-frame render path.
- **One process per session = the sandbox.** Run each render worker in a
  locked-down container (gVisor / seccomp, non-root, read-only rootfs, dropped
  caps, egress NetworkPolicy to ONLY the one target). The process boundary
  contains any parser RCE to a single ephemeral, credential-less session and
  avoids cgo. Go ↔ Rust over a local UDS/gRPC (not FFI).

## Planned crates (IronRDP workspace)

`ironrdp-connector` + `ironrdp-session` (connection/session state machines),
`ironrdp-graphics` (decoders incl. RemoteFX/EGFX — AD DCs often require RemoteFX),
`ironrdp-tokio` (async I/O), `ironrdp-pdu`. Auth: present a Vault-brokered
short-lived cert as a **virtual smart card** (no passwords to AD).

## Interface to `jess-web` (Go)

- Input: `{ target_addr, smartcard_cert, session_id }` on a UDS handed in by the
  Go shim (which received the session over the controller's yamux stream).
- Output: a drawing-instruction stream (rect / img(PNG) / copy / sync) + the
  decoded-image-on-`sync` frame boundary, plus input events (key/mouse) inbound.
- The Go side relays to the browser WebSocket and tees the drawing stream to
  `internal/recording` (drawing-dump format → WORM).

## Status / TODO

- [ ] Cargo workspace + IronRDP deps pinned by version.
- [ ] connect → ActiveStage → DecodedImage loop (port of `screenshot.rs` to a stream).
- [ ] drawing-instruction encoder (DecodedImage diffs → rect/img/copy/sync).
- [ ] virtual-smart-card cert auth (CredSSP) from a Vault-brokered cert.
- [ ] UDS/gRPC protocol to the Go `jess-web` shim.
- [ ] sandbox manifest (gVisor/seccomp, per-session, egress-locked).

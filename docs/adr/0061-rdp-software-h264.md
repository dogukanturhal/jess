# ADR 0061 — Software (CPU) H.264 for the RDP live console — GPU-free native feel

Status: Accepted — implemented (server). Builds clean. OFF by default
(`JESS_RDP_H264_SW`). UNLIKE every other H.264 path here, it is **verifiable
against the GPU-less hosts we already have** — no GPU anywhere. Live pixel
verification (a browser + an RDP host) is the remaining step.
Date: 2026-06-26
Related: ADR 0053 (EGFX/AVC420 H.264 — host-encoded), ADR 0058 (H.264 WORM
recording), ADR 0059 (AVC444), ADR 0060 (WebTransport datagrams), ADR 0051
(IronRDP live console / RGBA framebuffer).

## Context

The default live path re-encodes each dirty region as a **separate WebP image**:
no inter-frame compression, CPU-bound under motion, capped framerate → it is not
as smooth as native `mstsc`. The Tier-2 "native-feel" answer (ADR 0053) is H.264,
but that path **forwards the Windows host's *hardware* AVC encoder** (MS-RDPEGFX),
which on GPU-less Server SKUs does not exist — so it needs a GPU-passthrough
Windows host we don't have.

Research into how production no-GPU web remote desktops achieve smooth video
(Selkies-GStreamer ≥30 FPS@720p software, KasmVNC, Thinfinity, NICE DCV; the
canonical x264/OpenH264 `tune=zerolatency` config) shows the correct approach:
**encode H.264 on the gateway CPU** from the framebuffer we already decode. The
host AVC encoder — and thus a GPU — is never involved.

## Decision

`session_live` already decodes RDP into a full RGBA framebuffer
(`DecodedImage`). When `JESS_RDP_H264_SW` is set, CPU-encode that framebuffer as
a low-latency H.264 stream with Cisco's **OpenH264** (`openh264` crate, bundled
C source via `cc` — the same build path the existing `webp`/`libwebp-sys` dep
uses) and emit it as `MSG_H264`. This reuses, unchanged, **everything already
built**: the browser WebCodecs decoder (`rdpH264.ts`), the WORM recorder
(MSG_H264 tee, ADR 0058), and the WebTransport datagram transport (ADR 0060).

### Implementation (`crates/proxy-core/src/h264enc.rs` + `stream.rs`)

- `H264SwEncoder`: OpenH264 `Encoder` (bitrate-controlled, frame-skipping,
  `max_frame_rate`), reusable I420 plane buffers, BT.601 limited-range RGBA→I420
  (Y per pixel, U/V averaged per 2×2 block). The first frame is forced to an IDR
  (`force_intra_frame`) so the browser's `VideoDecoder` configures from it
  (OpenH264 emits SPS+PPS before each IDR). `frame_type()` → keyframe flag;
  `to_vec()` → Annex-B.
- `run_session`: when active, a `GraphicsUpdate` no longer emits WebP — it marks
  the framebuffer dirty; the loop encodes the **whole** framebuffer once per
  frame interval (coalescing bursts to ≤ fps) and on idle (trailing frame). EGFX
  is disabled (we are the encoder, not a forwarder).
- Tunables: `JESS_RDP_H264_SW_BITRATE` (default 8 Mbit/s), `JESS_RDP_H264_SW_FPS`
  (default 30). Go bridge forwards all three and treats sw-H.264 like EGFX-H.264
  for the lossless-PNG gate (recorded via the MSG_H264 tee; no PNG twin).
- Dockerfiles add `nasm` for OpenH264's SIMD (~3× encode speedup; it builds
  without it too — confirmed).

## Scope / non-goals / honesty

- **Default-off + never-regress.** Unset `JESS_RDP_H264_SW` ⇒ the WebP/PNG bitmap
  path is byte-for-byte unchanged. WebSocket/WebTransport, recording, EGFX, AVC444
  all behave exactly as before.
- **CPU cost.** ~1–1.5 cores for 720p–1080p30 software encode (Selkies-class). The
  jess-web pod limit (`cpu: "2"`) likely needs a bump for 1080p — a deployment
  follow-up. Bandwidth drops dramatically vs per-region WebP.
- **Colour.** BT.601 limited-range, no VUI — WebCodecs uses its resolution-based
  heuristic on decode, so a slight colour shift is possible. A VUI/colour-matrix
  refinement is future work (OpenH264 0.6.6's safe config doesn't expose it).
- **H.264 patents.** Compiling OpenH264 from source does **not** inherit Cisco's
  royalty coverage (that applies to *their* distributed binary). This is the SAME
  exposure jess already carries via the EGFX forward + WebCodecs decode paths;
  for a shipped product, cover it at the org level (MPEG-LA) or load Cisco's
  prebuilt binary (`openh264` `libloading`). Not a new architectural risk.
- **UNVERIFIED live pixels** — no browser + RDP host exercised in CI. BUT, unlike
  ADR 0053/0058/0059, this needs **no GPU**, so it can be live-verified against
  the existing GPU-less `exchange-01-rdp` host. Builds clean (cargo + clippy +
  fmt; go build/vet/test).

## Consequences

- A real, motion-compensated video codec replaces image-per-region — the smooth
  "native-feel" console, on the hardware we already have, against any RDP target.
- Reuses the entire browser + recorder + datagram stack from ADR 0053/0058/0060,
  and finally makes that stack verifiable without a GPU host.

# ADR 0053 — RDP Tier-2 "native-feel" H.264 path (WebCodecs + MS-RDPEGFX)

Status: Accepted — the EGFX/AVC420 channel is now **implemented in-tree** (no
IronRDP fork) on top of the 0.15 DVC framework + ZGFX decompressor; the broker
negotiates AVC420, extracts NAL units, and emits `MSG_H264`. End-to-end pixel
correctness still needs a live AVC420-capable host to confirm (none in CI). The
original "blocked on an IronRDP gap" verdict below is **superseded** — see
"UPDATE (2026-06-23): implemented in-tree". OFF by default (`JESS_RDP_H264`) and
hard-OFF for recorded sessions.
Date: 2026-06-23
Related: ADR 0051 (IronRDP / CredSSP build plan — the bitmap "first pixels"
path this builds beside), ADR 0049 (multi-protocol brokering), ADR 0030
(rdp-render worker / WORM recording), ADR 0033 (Phase 5f Rust IronRDP bridge)

## Context

The live RDP console (ADR 0051) streams the Windows desktop as a sequence of
**PNG dirty-rectangle bitmaps**: the Rust broker drives
`ironrdp_session::ActiveStage`, which decodes the RDP graphics stream to an RGBA
framebuffer; for each `ActiveStageOutput::GraphicsUpdate(region)` the broker
crops the region, PNG-encodes it (`stream.rs::encode_region_png`), and emits a
`FRAME` TLV (`MSG_FRAME = 2`). The browser (`RDPCanvas.tsx`) decodes each PNG via
`createImageBitmap` and blits it to a `<canvas>`.

This is correct and lossless, but it is **not VMware/RDP-native smooth**: every
repaint is a fresh intra-coded PNG with no inter-frame prediction, so scrolling,
video, and drag are bandwidth-heavy and visibly steppy. The "native feel" of
mstsc / FreeRDP / Windows 365 comes from the **MS-RDPEGFX graphics pipeline**
streaming **H.264** (AVC420 / AVC444) that the client decodes in hardware.

The modern browser primitive for hardware video decode is **WebCodecs**
(`VideoDecoder`): feed it H.264 access units (NAL units) and it returns
`VideoFrame`s decoded on the GPU/VPU, paintable directly to a canvas. This is the
same primitive scrcpy-web, Tango, and cloud-gaming clients use.

This ADR covers the **Tier-2** track of the RDP performance work: an H.264 /
WebCodecs path that runs **in parallel with**, never replacing, the Tier-1 bitmap
path. (Tier-1 = PNG→WebP + off-thread decode; Tier-3 = virtual channels — both
owned by sibling tracks. This track is purely additive and capability-gated so it
cannot regress the bitmap path.)

## UPDATE (2026-06-23): EGFX/AVC420 implemented in-tree — no fork needed

The "Verdict" below concluded a real pipeline needed a **fork of
`ironrdp-session`** (point 5: a new `ActiveStageOutput` variant to carry NAL
units). That conclusion was **wrong about the architecture** — it assumed the
H.264 had to exit through `ActiveStageOutput`. It does not. The fix is a
**side-channel out of the DVC processor**, which the published 0.15 crates fully
support:

- `ironrdp-dvc 0.6` *does* accept custom dynamic-channel processors:
  `DrdynvcClient::new().with_dynamic_channel(my_processor)`, registered on the
  connector via `with_static_channel(drdynvc)` (DRDYNVC is itself a static VC
  hosting dynamic channels). `ActiveStage` routes inbound EGFX DVC data to the
  processor's `process()` automatically. (The earlier claim that "ActiveStage
  does not accept custom DVC processors" was incorrect.)
- `ironrdp-graphics 0.8` ships a working **ZGFX `Decompressor`**
  (`zgfx::Decompressor::decompress`) — not just the compressor. That is the only
  codec primitive needed: the Rust side does **not** decode H.264, it only
  ZGFX-decompresses the EGFX stream and *locates* the AVC420 NAL bitstream to
  forward to the browser's WebCodecs decoder.
- The missing EGFX command-PDU codec is small and fixed-shape; we hand-rolled it
  (`src/egfx.rs`) per [MS-RDPEGFX] rather than waiting on upstream #427/#1158.
- No `ActiveStageOutput` variant (hence no `ironrdp-session` fork) is needed: the
  `DvcProcessor` pushes decoded `Avc420Frame`s onto an `mpsc` side-channel
  (`EgfxChannel`), and the session loop drains it each iteration into
  `ServerMsg::H264` — exactly the pattern the Tier-3 CLIPRDR backend already uses
  to bridge sync DVC callbacks to the async loop.

What was built (`src/egfx.rs`, `connect.rs`, `stream.rs`, `bin/session_live.rs`):

1. `EgfxClient: DvcProcessor` for `Microsoft::Windows::RDS::Graphics`.
2. On channel open, advertises **AVC420-only** caps (`RDPGFX_CAPVERSION_81` +
   `AVC420_ENABLED`) — 8.1 predates AVC444, so the server can never pick the
   dual-stream codec the browser can't directly decode.
3. Per inbound message: ZGFX-decompress → walk the RDPGFX PDU stream → on
   `WIRE_TO_SURFACE_1`/AVC420, parse the `RFX_AVC420_METABLOCK`, extract the NAL
   bitstream, map surface→output coords, push an `Avc420Frame`.
4. Sends the REQUIRED `FRAME_ACKNOWLEDGE` after each `END_FRAME`.
5. The session loop drains `EgfxChannel` → `ServerMsg::H264` (keyframe detected
   by scanning Annex-B NAL types for IDR/SPS). Bitmap path untouched as fallback.

**Recording interaction (resolved):** an H.264 frame yields no RGBA bitmap, so a
recorded session would capture nothing on the WORM PNG track. EGFX is therefore
**hard-gated OFF when recording** (`enable_h264 = JESS_RDP_H264 && !record_lossless`),
falling back to the WebP/PNG path that records losslessly. See `session_live.rs`.

**What still needs a live host:** end-to-end pixel correctness (a Windows host
with the H.264/AVC graphics codec enabled). The wire codecs are spec-faithful but
unverified against a real AVC420 server — there is none in CI.

The original analysis is retained below as the historical record of why the
in-tree route was initially judged out of scope.

## The hard constraint: IronRDP 0.15 has no client-side EGFX/H.264

Before designing the broker emit path we verified what the **pinned** IronRDP
actually supports. The locked graph (`Cargo.lock`) is `ironrdp = 0.15.0`,
`ironrdp-session = 0.9.0`, `ironrdp-pdu = 0.8.0`, `ironrdp-graphics = 0.8.1`,
`ironrdp-dvc = 0.6.0`. Inspecting the extracted crate sources:

- **`ironrdp-session 0.9.0` has ZERO EGFX / GFX / AVC / H.264 references.** Its
  `ActiveStage` only handles the legacy graphics path (bitmap updates, surface
  bits, RemoteFX via `rfx.rs`). `ActiveStageOutput` has **no H.264 / NAL / EGFX
  variant** — the only paint output is `GraphicsUpdate(InclusiveRectangle)`,
  i.e. *already-decoded RGBA*. There is no way to get raw AVC420 NAL units out of
  it, and no seam to register a custom graphics-pipeline channel handler after
  `ActiveStage::new(connection_result)`.
- **There is no `ironrdp-egfx` / `ironrdp-graphics-pipeline` crate** in the
  dependency graph at all. The only EGFX-adjacent bits that exist are:
  - a GCC capability flag `SUPPORT_DYN_VC_GFX_PROTOCOL` (`ironrdp-pdu`
    `gcc/core_data/client.rs`) and a nego flag `DYNVC_GFX_PROTOCOL_SUPPORTED`
    (`ironrdp-pdu` `nego.rs`) — just bits, no channel logic;
  - **ZGFX bulk *compression*** (`ironrdp-graphics::zgfx`, public
    `compress_and_wrap_egfx`) — the server-side compression wrapper, not a
    client decode path; and there is **no `WireToSurface` / `SurfaceToCache` /
    `StartFrame` / `CapsConfirm` PDU codec** and **no
    `Microsoft::Windows::RDS::Graphics` `DvcProcessor`**.
- The connector `Config` (`ironrdp-connector 0.9` `lib.rs`) has **no
  EGFX / graphics-pipeline field**. `ClientConnector::with_static_channel`
  registers *static* virtual channels; a GFX channel is a *dynamic* channel that
  would need a `DvcProcessor` impl on `DrdynvcClient` — which does not exist for
  GFX, and `ActiveStage` does not accept custom DVC processors anyway.

This matches the upstream signal: IronRDP issue **#427** ("Add GFX
([MS-RDPEGFX]) support") is unimplemented/`help wanted` — partial support that
once existed was **removed** (PRs #419/#425) — and issue **#1158**
("Multi-Codec Graphics Pipeline") confirms the EGFX codec encode/decode paths
(ClearCodec, RemoteFX Progressive, the multi-codec frame API) are still missing.
Out-of-tree forks (e.g. lamco-rdp-server) have built EGFX + AVC420/444 with
VA-API/NVENC, proving the *protocol* works on IronRDP — but that code is **not in
the published 0.15 crates** we are pinned to.

### Verdict (rigorously honest)

**Real end-to-end H.264 is NOT achievable with IronRDP 0.15 without forking or
re-implementing the EGFX graphics-pipeline channel.** A genuine pipeline would
require, broker-side:

1. a `DvcProcessor` for `Microsoft::Windows::RDS::Graphics` (the EGFX DVC),
2. an EGFX PDU codec (`CapsAdvertise`/`CapsConfirm`, `CreateSurface`,
   `StartFrame`/`EndFrame`, `WireToSurface1`/`WireToSurface2`, `SurfaceToCache`,
   `FrameAcknowledge`, …) — only ZGFX *de*compression and the bare PDU framing
   for a few of these exist today,
3. ZGFX **decompression** wired into that channel (the `zgfx` module today only
   exposes the *compressor*),
4. extraction of the AVC420/AVC444 bitstream meta + NAL units from
   `WireToSurface` payloads, and
5. a new `ActiveStageOutput` variant to surface those NAL units (a fork of
   `ironrdp-session`), since the closed enum cannot carry them today.

That is multi-week library work on a third-party crate and is out of scope for
this track. We therefore ship the **decode-side scaffold + the wire contract +
the broker emit seam**, and document the gap precisely.

## Decision

Ship the Tier-2 H.264 path as an **additive, capability-gated scaffold** that is
wired end-to-end *except* for the one piece IronRDP 0.15 cannot provide (raw
AVC420 NAL units out of the active session). Concretely:

### 1. New TLV message type `MSG_H264 = 5` (server→client)

Reserved type `5` (does not collide with `DESKTOP_SIZE=1`, `FRAME=2`, `CLOSE=3`,
or the jess-web-synthesised `ERROR=0xFF`). Layout:

```
[u8 flags][u16 x][u16 y][u16 w][u16 h][AVC NAL bytes (Annex-B)]
```

`flags` bit0 = keyframe (the access unit is an IDR carrying SPS+PPS), bit1 =
AVC444 (a second chroma plane the client composites; AVC420 4:2:0 when clear).
`x,y,w,h` is the EGFX surface region the access unit paints. Defined in three
places that are kept byte-identical and roundtrip-tested:

- Rust broker: `ServerMsg::H264` + `encode`/`decode` in `proxy-core/src/stream.rs`
  (test `server_h264_roundtrip`).
- TS browser: `MSG_H264` + the `h264` `ServerTLV` variant + `decodeServerTLV` in
  `cmd/jess-web/web/src/api/rdp.ts`.
- The Go bridge (`cmd/jess-web/ws_rdp_live.go`) is codec-agnostic — it relays any
  TLV `[u32 len][type][payload]` and only synthesises `0xFF`, so **no Go change
  is required**; `MSG_H264` flows through it unchanged.

### 2. Browser WebCodecs decode path (shipped, flag-gated)

`cmd/jess-web/web/src/api/rdpH264.ts` — a self-contained `RDPH264Decoder` that
wraps a WebCodecs `VideoDecoder`: lazily configured from the first keyframe
(Annex-B mode — no `description` ⇒ start-code NALs with in-band SPS/PPS), drops
deltas before the first keyframe, feeds `EncodedVideoChunk`s, and hands decoded
`VideoFrame`s to a paint callback (which `drawImage`s the frame and `close()`s it
to release the scarce decoder buffer). Gating:

- **Capability:** `'VideoDecoder' in window` (+ `EncodedVideoChunk`) —
  `hasWebCodecsH264()`.
- **Flag:** `h264Enabled()` — OFF by default; opt-in via build env
  `VITE_RDP_H264=1` or runtime `localStorage['jess.rdp.h264']='1'` (operator A/B
  without a rebuild).
- Both must hold (`h264PathActive()`) for `RDPCanvas` to construct a decoder; the
  AVC444 dual-plane case is skipped (only AVC420 4:2:0 is directly decodable —
  see Notes). On any decoder error the canvas drops the decoder and stays on the
  PNG path. `RDPCanvas.tsx`'s existing PNG `frame` case is **untouched**.

WebCodecs minimal types are declared locally in `rdpH264.ts` (TS's bundled `DOM`
lib has no WebCodecs types) to honor the **minimal-deps** constraint — no
`@types/dom-webcodecs` added.

### 3. Broker EGFX groundwork + emit seam (shipped; does not emit today)

`stream.rs` gains `h264_requested()` (the `JESS_RDP_H264=1` operator gate) and
`h264_message(region, nal, keyframe, avc444)` — the pure, tested constructor an
EGFX channel handler will call to emit a `ServerMsg::H264`. The `GraphicsUpdate`
arm of the decode loop carries a marker documenting exactly where the parallel
H.264 emit arm slots in once IronRDP surfaces NAL units. With the flag set today
the broker logs that the path was requested but is unavailable, and **continues
on the unconditional PNG bitmap path** — the flag never disables or degrades the
bitmap path.

## What is implemented vs not (no hand-waving)

| Piece | Status |
| --- | --- |
| `MSG_H264=5` wire type (Rust + TS, roundtrip-tested) | **Implemented** |
| Go bridge relays `MSG_H264` | **Works as-is** (codec-agnostic relay) |
| Browser `RDPH264Decoder` (WebCodecs configure/decode/paint/close) | **Implemented (scaffold)** |
| Capability + flag gating; PNG fallback preserved | **Implemented** |
| Broker `h264_requested()` flag + `h264_message()` emit seam | **Implemented** |
| Broker negotiating EGFX (DVC `Microsoft::Windows::RDS::Graphics`, AVC420 caps) | **Implemented in-tree** (`src/egfx.rs`) |
| Broker extracting AVC420 NAL units from the session | **Implemented** (DVC side-channel — no `ironrdp-session` fork) |
| Broker emitting `MSG_H264` (session loop drains `EgfxChannel`) | **Implemented** (`stream.rs`) |
| Recording-safety gate (EGFX off when recording) | **Implemented** (`session_live.rs`) |
| Live pixels-through-WebCodecs proof | **Unverified** — needs a live AVC420-capable Windows host (none in CI) |

The codec + channel are built and compile clean; the one open item is live
end-to-end verification against a real AVC420 server.

## Notes

### AVC444 → 4:2:0 for the browser

WebCodecs `VideoDecoder` decodes a single H.264 bitstream (4:2:0). RDP **AVC420**
is plain 4:2:0 → feeds WebCodecs directly. RDP **AVC444** packs full 4:4:4 chroma
as *two* 4:2:0 streams (a luma+subsampled-chroma "main view" plus an auxiliary
view carrying the chroma residual, per MS-RDPEGFX §AVC444). To present AVC444 in a
browser you either (a) transcode/down-convert to 4:2:0 broker-side (lose 4:4:4
chroma — fine for desktop text/UI, which is mostly luma-detail), or (b) decode
both sub-streams and recombine the chroma in a WebGL/WebGPU shader. The pragmatic
choice is **negotiate AVC420 only** (set the EGFX caps to advertise AVC420, not
AVC444) so the browser path is a direct decode; the `H264_FLAG_AVC444` bit and
the broker-side transcode are reserved for later. Today `RDPCanvas` skips AVC444
AUs defensively.

### Transport: WS today, WebTransport/WebRTC later

H.264 currently rides the **same WebSocket TLV** as the bitmap path (ordered,
reliable, head-of-line-blocked over a single TCP+TLS connection). That is fine
for a correctness scaffold and even for moderate motion. For true low-latency
"native feel" under loss, the better transports are:

- **WebTransport** (HTTP/3 / QUIC): unreliable+unordered datagrams or independent
  streams → no head-of-line blocking; a natural fit for video where a dropped
  delta frame should not stall the next keyframe. Requires HTTP/3 at the gateway.
- **WebRTC** (`RTCPeerConnection` + insertable streams / `RTCDataChannel`): the
  most battle-tested low-latency video transport, with built-in congestion
  control and NACK/FEC; heavier to operate (ICE/TURN, SFU-less p2p-to-broker).

Both are out of scope here; the TLV-over-WS contract is transport-agnostic enough
that a later move only changes the carrier, not `MSG_H264`'s bytes.

### WORM recording

Recording (ADR 0051 P4, `jess-rdp-recording-v2`) tees the **decoded** stream (the
PNG `FRAME` path) into the signed WORM bundle. An H.264 access unit produces no
decoded RGBA region, so a recorded EGFX session would capture nothing on that
track. Rather than build a server-side H.264 decoder (which we deliberately do
not — the browser decodes), EGFX is **hard-gated OFF for recorded sessions**
(`enable_h264 = JESS_RDP_H264 && !record_lossless` in `session_live.rs`). A
recorded session always uses the bitmap path, so the WORM bundle stays lossless
and replayable exactly as before — a must-record session never silently loses
fidelity. Storing H.264 AUs + SPS/PPS for re-decodable recording is a possible
future optimisation (would let recorded sessions also use H.264) but is out of
scope; the gate is the correct, safe default.

## Remaining work

Done (2026-06-23/24): the MS-RDPEGFX DVC handler, NAL extraction via DVC
side-channel (no fork), the loop emit wiring, AVC420 caps, the GFX-protocol
advertise (vendored connector patch), ZGFX-wrapped outbound PDUs, the graceful
H.264→bitmap fallback (live-validated), AND the GPU-host deferreds:
**dest-rect crop** (browser clips the 16-aligned coded frame to the dirty
region's w×h), **multi-monitor** (per-surface origins + `RESET_GRAPHICS` /
`MAP_SURFACE_TO_SCALED_OUTPUT`), and **AVC444 (opt-in, `JESS_RDP_AVC444`)** —
advertise capversion 10.7 and display the AVC444 **main view** (a complete 4:2:0
image). What's left:

1. **Live end-to-end verification** against a GPU-capable Windows host (AVC
   hardware encoder): confirm pixels paint, keyframe detection, and frame-ack
   flow. The Exchange box is GPU-less and can't encode H.264, so this is still
   the one unproven link.
2. **Full AVC444 4:4:4 chroma** — recombine the auxiliary (chroma) view with the
   main view in a WebGL/WebGPU shader for true 4:4:4. Today we display the 4:2:0
   main view only (correct colour, 4:2:0 chroma resolution). Needs a GPU host to
   develop/verify the shader.
3. **WORM recording of H.264 sessions** — store the H.264 AUs (+ SPS/PPS) in the
   recording so recorded sessions can also use H.264. Cross-cutting (recording
   format + replay decoder) and orthogonal to the GPU-host work; today recorded
   sessions are gated to the bitmap path (the correct, safe default), so this is
   a deferred optimisation, not a gap.
4. (Optional, perf) move H.264 to WebTransport/WebRTC for loss resilience — a
   gateway/HTTP-3 infrastructure initiative, not a jess code change.

The codec + channel are implemented and build clean; item 1 (a GPU host) is the
gate between "compiles + spec-faithful" and "proven native-feel session".

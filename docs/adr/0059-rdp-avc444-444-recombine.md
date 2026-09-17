# ADR 0059 — AVC444 true 4:4:4 chroma recombine for the RDP live console

Status: Accepted — implemented (EXPERIMENTAL, default-off, UNVERIFIED end-to-end).
Date: 2026-06-26
Related: ADR 0053 (RDP Tier-2 H.264 / WebCodecs / MS-RDPEGFX — the live path this
extends; "full 4:4:4 recombine" was listed there as remaining work), ADR 0058
(H.264 WORM recording), ADR 0049 (multi-protocol brokering).

## Context

ADR 0053 added the MS-RDPEGFX/AVC420 H.264 path and an opt-in AVC444 mode
(`JESS_RDP_AVC444`) that advertises capversion 10.7. When a host selects AVC444,
each graphics update is an `RFX_AVC444_BITMAP_STREAM` wrapping **two**
`RFX_AVC420_BITMAP_STREAM`s — a MAIN (luma + 4:2:0 chroma) view and an AUXILIARY
(chroma) view whose planes carry the chroma samples needed to upgrade the main's
4:2:0 to full 4:4:4. ADR 0053 shipped only the **main view** (a complete, correct
4:2:0 image); the broker *dropped* the aux view, and "recombining it in a WebGL
shader" was left as remaining work. The visible win of 4:4:4 is sharper saturated
colour edges / coloured text — subtle, but real for design/console work.

## Decision

Forward the aux view and recombine it with the main view into true 4:4:4 in the
browser, behind the existing `JESS_RDP_AVC444` flag, **never regressing** the
4:2:0 main-view behaviour.

1. **Broker (`crates/proxy-core/src/egfx.rs`).** A new `avc444_aux_view()`
   (mirror of `avc444_main_view`) extracts view 2. `handle_wire_to_surface_1`
   now emits the MAIN view as `MSG_H264` with `H264_FLAG_AVC444` (a "chroma frame
   follows" marker) AND, when present, the AUX view as `MSG_H264` with the new
   `H264_FLAG_AUX`. A luma-only (`LC==1`) update emits the main as a plain AVC420
   frame; a chroma-only (`LC==2`) update is dropped (as before — no main to pair).

2. **Wire (`stream.rs` / `rdp_live_engine.go` / `rdp.ts`).** New flag
   `H264_FLAG_AUX = 0b0000_0100`. `ServerMsg::H264` gains an `aux: bool` field;
   the byte layout is otherwise unchanged (the flag is a bit in the existing flags
   byte), so `server_h264_roundtrip` and the Go/SPA parsers stay aligned.

3. **Recording (`rdp_live_engine.go`).** The WORM tee SKIPS aux frames
   (`h264FlagAux`): a recording stays the AVC420 main view (4:2:0), so this never
   ripples into the ADR 0058 recording/replay format. Aux frames are still
   forwarded live (forwarding is independent of the recorder tee).

4. **Browser (`api/rdpAvc444.ts` + `components/RDPCanvas.tsx`).** A new
   `RDPAvc444Decoder` runs **two** WebCodecs `VideoDecoder`s (main + aux), pairs
   their outputs in order, reads back both as I420 via
   `VideoFrame.copyTo({format:'I420'})`, uploads the six planes as `R8` textures,
   and recombines them into 4:4:4 in a WebGL2 fragment shader, drawn to an
   offscreen canvas the existing crop-blit path then draws. The shader implements
   the exact FreeRDP `general_LumaToYUV444` + `general_ChromaV1ToYUV444` plane
   mapping ([MS-RDPEGFX] §3.3.8.3.2):
   - `Y[y][x]      = mainY[y][x]`
   - `y even, x even = main U/V[y/2][x/2]`        (the 4:2:0 chroma)
   - `y even, x odd  = aux  U/V[y/2][(x-1)/2]`
   - `y odd (k=(y-1)/2) = aux Y de-interleaved in 16-line blocks`:
     `U` row `= (k>>3)*16 + (k&7)`, `V` row `= (k>>3)*16 + 8 + (k&7)`,
   then BT.601 full-range YUV→RGB.

## Scope / non-goals / honesty

- **Default-off + never-regress.** Gated on `JESS_RDP_AVC444` (server) which is
  itself gated on `JESS_RDP_H264`; both default off. Non-AVC444 and non-H.264
  sessions are byte-for-byte unchanged. Recordings are unchanged (main view only).
- **Hard fallback.** The 4:4:4 path needs (a) WebGL2 AND (b) `copyTo({I420})` to
  actually yield planar YUV. (b) is **unreliable for hardware-decoded H.264** —
  many HW decoders return an opaque frame with no readback path
  (w3c/webcodecs#157/#390). On any readback/GL failure the decoder permanently
  flips to `mainOnly` and hands the caller the MAIN `VideoFrame` — i.e. the exact
  AVC420 4:2:0 behaviour. A browser without WebGL2 never engages it at all.
- **UNVERIFIED end-to-end.** There is no AVC444-capable Windows host in CI (the
  Exchange box is GPU-less and can't even encode H.264). The plane mapping,
  plane-layout/stride handling, and the YUV→RGB matrix/range (BT.601 full-range
  assumed) are spec-faithful but have **not** been pixel-confirmed. AVC444v2
  (`general_ChromaV2ToYUV444`) is not handled — only the v1 chroma layout; a v2
  host would mis-recombine, but the same `copyTo` gate usually deflects it to the
  safe main-view fallback. This is the same honesty caveat ADR 0053/0058 carry,
  plus the `copyTo`-on-HW-decode feasibility risk. Develop/verify against a real
  AVC444 host before relying on the recombined output.

## Consequences

- AVC444 sessions can reach true 4:4:4 chroma on software-decode browsers, and
  degrade cleanly to the existing 4:2:0 main view everywhere else.
- No new wire bytes, no recording-format change, no change to any default path.

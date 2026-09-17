# ADR 0058 — H.264 WORM recording for the RDP live console

Status: Accepted — implemented. Records MS-RDPEGFX/AVC420 H.264 access units into
the `jess-rdp-recording-v2` stream and replays them via WebCodecs, LIFTING the
prior "EGFX off when recording" gate (ADR 0053). H.264 capture is UNTESTED end-to-
end without an AVC420-encoding host (none in CI) — the format, recorder, and parse
sides are exercised by the existing recording tests; the live capture + replay
pixels need a real encoding Windows host to confirm. OFF by default
(`JESS_RDP_H264`); default (PNG) behaviour is byte-for-byte unchanged.
Date: 2026-06-24
Related: ADR 0053 (RDP Tier-2 H.264 / WebCodecs / MS-RDPEGFX — the live path this
records), ADR 0051 P4 (`jess-rdp-recording-v2` full decoded-stream WORM recording),
ADR 0030 (WORM recording / signed bundle), ADR 0049 (multi-protocol brokering).

## Context

ADR 0051 P4 records the live RDP console as a `jess-rdp-recording-v2` NDJSON
stream — a verbatim tee of the decoded server→client protocol (every
`DESKTOP_SIZE`, every dirty-region `FRAME` PNG, every operator input) into the
ADR-0030 signed WORM bundle, replayed by `RDPReplayCanvas` reusing the live SPA
blit path.

ADR 0053 added the Tier-2 "native-feel" H.264 path: when `JESS_RDP_H264` is set
and the host can encode, the broker negotiates MS-RDPEGFX/AVC420, extracts H.264
access units, and emits `MSG_H264` (`= 5`) TLVs; the browser decodes them with a
WebCodecs `VideoDecoder` (`rdpH264.ts`). That path was **hard-gated OFF for
recorded sessions**: an H.264 access unit produces no RGBA bitmap, so the WORM PNG
track would have captured nothing. The gate was implemented as
`enable_h264 = h264_requested() && !record_lossless` in `session_live.rs`, with
the Go bridge setting `JESS_RDP_RECORD_LOSSLESS=1` for every recorded session — so
a recorded session always fell back to the bitmap (PNG/WebP) path.

This meant operators had to choose between native-feel H.264 *or* a compliant
recording — never both. For regulated/Tier-0 targets (which are exactly the ones
that MUST be recorded) the live console was therefore stuck on the steppy bitmap
path.

## Decision

Record the H.264 access units directly into the v2 stream so an EGFX-driven
session is itself replayable, then lift the gate.

1. **New v2 event kind `h264`** (`internal/recording/rdpstream.go`). A new
   `RDPStreamWriter.H264Frame(x, y, w, h, keyframe, avc444, nal)` method writes a
   record:

   ```json
   {"kind":"h264","seq":3,"at":"…","x":0,"y":0,"width":1280,"height":1024,
    "keyframe":true,"avc444":false,"nal_b64":"AAAAAWdC…"}
   ```

   The Annex-B NAL bytes are inlined as base64 into the SAME single signed,
   hash-chained content stream as the PNG frames (the ADR 0051 P4 rationale for
   inlining is unchanged). `keyframe` marks an IDR carrying SPS+PPS so a replayer
   can (re)initialise its decoder from it. Oversized AUs are truncated + flagged
   with the same bound as a PNG frame. The existing event kinds (`meta`/`resize`/
   `frame`/`input`/`close`) are **unchanged**. A recording is either PNG-driven
   (`frame`) or H.264-driven (`h264`), never both.

2. **Engine tee** (`internal/broker/rdp_live_engine.go`). The server→client tee
   recognises `msgH264` (`= 5`, with flag bits `h264FlagKeyframe`/`h264FlagAVC444`
   mirrored from the Rust crate and the SPA). On `msgH264` it records the AU via
   `rec.H264Frame(...)` when a recorder is wired, and forwards the AU to the
   browser verbatim (it IS the live frame — `recorderOnly` stays keyed on
   `msgFrame`, so H.264 frames are never swallowed). The AU is NOT fed to the
   ADR-0030 periodic-screenshot track (raw NAL is not a decodable screenshot
   image; that track only runs on the `rec==nil` broker Dial path, which never
   uses H.264).

3. **Gate lift.** The Go bridge now sets `JESS_RDP_RECORD_LOSSLESS=1` **only for
   NON-H.264 recorded sessions** (`rec != nil && !JESS_RDP_H264`) — the bitmap
   path still needs the lossless-PNG twin, so that legacy behaviour is exactly
   preserved. `session_live.rs` drops the `&& !record_lossless` term:
   `enable_h264 = h264_requested()`. Because the bridge no longer sets
   `record_lossless` when H.264 is requested, the two stay consistent without an
   extra signal.

4. **Replay decode** (`cmd/jess-web/web/src/api/rdp.ts` + `RDPReplayCanvas.tsx`).
   `RDPV2Event` gains the `h264` kind (`nal_b64`/`keyframe`/`avc444` + geometry);
   `parseRDPRecordingNDJSON` already parses every line generically. The replayer
   feeds each `h264` event's NAL to the SAME `RDPH264Decoder` (WebCodecs) the live
   console uses, configured lazily from the first keyframe, and draws the decoded
   `VideoFrame`s into the canvas at their surface rect — with the original
   wall-clock timing. If the browser lacks WebCodecs, H.264 replay is skipped with
   a status note; the PNG replay path is untouched.

## Scope / non-goals

- **Default behaviour is unchanged.** Everything is gated on `JESS_RDP_H264`.
  Non-recorded sessions and non-H.264 (bitmap) recordings are byte-for-byte
  identical to before: the PNG `frame` recorder feed, the WebP/PNG dual-emit, the
  `recorderOnly` forwarding decision, and `JESS_RDP_RECORD_LOSSLESS` for bitmap
  recordings all behave exactly as they did. `TestLiveEngineRecordsFullStream`
  (which does not set `JESS_RDP_H264`) still passes unchanged.
- **No new tests** were added (project rule). The H.264 recorder/format/parse code
  is covered structurally by the existing recording + bridge tests; the live H.264
  capture and replay pixels are **untested** because there is no AVC420-encoding
  host in CI. This is the same honesty caveat ADR 0053 carries for the live path.
- AVC444 is recorded (the flag is preserved round-trip) but, like the live path,
  only the AVC420 4:2:0 main view is decoded by WebCodecs on replay today.
- Multi-surface EGFX region tracking on replay reuses the live decoder's
  single-slot region latch (ADR 0053 remaining-work) — correct for the
  single-stream AVC420 case.

## Consequences

- A recorded session can now use the native-feel H.264 path AND produce a
  compliant, replayable WORM bundle — the operator no longer has to choose.
- The recording is codec-tagged by event kind, so a verify/replay client can tell
  a bitmap recording from an H.264 one without out-of-band metadata.
- Replay fidelity of an H.264 recording depends on the browser's WebCodecs
  `VideoDecoder`; absent it, the bundle is still downloadable and the metadata
  (subject/target/timing/keyframe markers) is intact, but pixels won't paint.

# ADR 0060 — Loss-resilient H.264 over WebTransport datagrams

Status: Accepted — implemented (server + browser); builds clean. OFF by default
(`JESS_RDP_WEBTRANSPORT_DATAGRAMS`). UNVERIFIED end-to-end — needs a browser, a
reachable QUIC path (ADR 0055 ingress), and an AVC420-capable host. WebSocket and
the single-reliable-stream WebTransport path are both unchanged.
Date: 2026-06-26
Related: ADR 0055 (RDP over WebTransport — the carrier this extends), ADR 0053
(H.264/EGFX/AVC420), ADR 0059 (AVC444 4:4:4).

## Context

ADR 0055 carries the RDP TLV wire over a single **reliable** WebTransport bidi
stream — functionally the same as the WebSocket path, just over QUIC. That alone
removes cross-connection TCP head-of-line blocking, but within the one stream a
lost packet still HOL-blocks every later TLV behind it, including H.264 delta
frames. ADR 0055's own remaining-work item #3 is to move H.264 deltas onto
**unreliable** datagrams so a dropped delta doesn't stall the next frame.

We researched the canonical design (IETF **Media-over-QUIC** + WebTransport
real-time game-streaming work, the closest analog to a remote desktop): map media
frames onto QUIC datagrams (RFC 9221), fragment over the ~1200-byte MTU with an
application sequence header, and let the receiver **drop stale/incomplete frames**
rather than wait. Keyframes and control stay reliable; recovery from a lost GOP is
the next periodic keyframe + intra-refresh — there is no picture-loss-indication
(RDP gives the broker no way to force an IDR), which is exactly how remote-desktop
video over unreliable transport is normally handled.

## Decision

Split the H.264 path by frame type over the WebTransport connection. The engine
writes the SAME framed TLV wire to its client pipe; a wrapper routes it:

- **Reliable bidi stream**: every control TLV (`DESKTOP_SIZE`/`FRAME`/`FRAME_WEBP`/
  `CLIPBOARD`/`CLOSE` + client→server input), H.264 **keyframes** (an IDR is
  load-bearing), and the AVC444 main+aux pair (ADR 0059 — kept reliable + together
  so the recombine stays in sync).
- **Unreliable datagrams (RFC 9221)**: plain AVC420 H.264 **delta** frames only.

### Wire (Go `cmd/jess-web/wt_media.go` ↔ browser `web/src/api/rdpTransport.ts`)

Each datagram: `[u8 magic=0xD6][u32 frameSeq BE][u16 fragIdx BE][u16 fragCount BE][chunk]`
(9-byte header, ~1024-byte chunks). A frame's chunks concatenate to the inner
`[type][payload]` TLV (no `u32` length — datagrams are self-delimiting). The
reliable stream keeps the `[u32 len][type][payload]` framing the WtSocket reader
already splits, so both paths deliver through the same `decodeServerTLV`.

### Server (`wtMediaConn`)

Wraps the bidi stream as the engine's `io.ReadWriteCloser`. `Write` buffers and
parses complete frames; a datagram-eligible delta (`MSG_H264` with none of
keyframe/AVC444/aux set) is fragmented and `SendDatagram`'d; everything else goes
to the reliable stream verbatim. `Read` (input) and `Close` pass straight through.
A `SendDatagram` failure (oversized / unsupported path) **falls the whole frame
back onto the reliable stream** — a frame is never lost to this path.

### Browser (`WtSocket`)

When the info endpoint advertises `datagrams: true`, also drains
`wt.datagrams.readable`: reassembles fragments by `frameSeq` (bounded to 64
in-flight partial frames), **discards stale frames** (wrap-safe seq compare) and
incomplete ones, and delivers completed TLVs through the same `onmessage` path. A
datagram-side error is **non-fatal** — keyframes + control are on the reliable
stream, so the session continues.

## Scope / non-goals / honesty

- **Default-off + never-regress.** Gated on `JESS_RDP_WEBTRANSPORT_DATAGRAMS`
  (server). Off ⇒ the WT path is the unchanged ADR 0055 single reliable stream;
  WebSocket is unaffected. The browser ignores datagrams unless the server
  advertises them.
- **AVC444 stays reliable.** The dual-view recombine (ADR 0059) needs both views
  paired; datagram-izing one view would desync it, so AVC444 main+aux ride the
  reliable stream. Only plain AVC420 deltas use datagrams.
- **No keyframe-on-demand.** RDP exposes no PLI/FIR, so loss recovery relies on
  the host's periodic keyframes + intra-refresh; a lost delta shows a brief stale
  patch until the next keyframe (over the reliable stream). This is the accepted
  trade for screen video over an unreliable transport.
- **UNVERIFIED end-to-end.** No browser + reachable QUIC path + AVC420 host in CI,
  so the fragmentation/reassembly, stale-drop, and the keyframe/delta split are
  spec-faithful but **not** live-proven. Builds clean (Go + tsc) and is fully
  fallback-safe. Verify against a real browser + AVC420 host before enabling.

## Consequences

- A lost delta no longer HOL-blocks subsequent frames — the latency-under-loss win
  the ADR 0055 stream path can't give on its own.
- No new dependency (quic-go/webtransport-go already vendored; `EnableDatagrams`
  was already set). No recording-format change (recording is unaffected — it tees
  the engine's frames upstream of the transport).

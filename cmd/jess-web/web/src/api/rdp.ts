// RDP WebSocket frame protocol — Phase 5f-7.
//
// Wire format between the SPA's RDPCanvas component and the
// jess-ironrdp-broker's /ws/session endpoint. JSON-text frames for
// control plane; binary frames for bitmap payload (deferred to 5f-8b
// — first cut just renders the handshake events as a test pattern).
//
// FRAME TYPES (broker → SPA)
//   upstream_connecting       informational, shown as "Connecting…"
//   upstream_ready            X.224 handshake complete; SPA shows
//                             "Handshake OK — bridge pending" until
//                             5f-8b ships real fastpath frames
//   upstream_nego_failure     RDP negotiation rejected (e.g. NLA
//                             required but operator didn't relay
//                             credentials yet)
//   upstream_unreachable      target's RDP service didn't respond
//   error                     SSRF guard / config error
//   bitmap_update             5f-8b: binary follow-up payload with
//                             dirty rectangles
//   cursor                    5f-8b: cursor shape + position update
//
// FRAME TYPES (SPA → broker, all deferred to 5f-8b)
//   credentials               first frame; CredSSP relay for NLA
//   mouse_input               x,y,buttons,wheel
//   key_input                 RDP scancode + modifier mask
//   clipboard                 bidirectional sync
//   control                   resize, screenshot, disconnect

// fetchRDPRecorded resolves the EFFECTIVE recording decision for a target
// (admin catalog override beats the GitOps default) so the live console shows an
// HONEST recording indicator — recording is per-target, not unconditional.
// Throws on a non-2xx so the caller can leave the indicator at its safe default.
export async function fetchRDPRecorded(targetId: string, signal?: AbortSignal): Promise<boolean> {
  const r = await fetch(`/api/rdp/recorded?target=${encodeURIComponent(targetId)}`, {
    credentials: 'same-origin',
    cache: 'no-store',
    signal,
  })
  if (!r.ok) throw new Error(`recorded fetch failed: ${r.status}`)
  const j = (await r.json()) as { recorded?: boolean }
  return !!j.recorded
}

export type RDPFrame =
  | UpstreamConnecting
  | UpstreamReady
  | UpstreamNegoFailure
  | UpstreamUnreachable
  | RDPError
  | BitmapUpdate
  | CursorUpdate

export interface UpstreamConnecting {
  type: 'upstream_connecting'
  sub: string
  target_id: string
  upstream_addr: string
  grant_id: string
  broker_version: string
}

export interface UpstreamReady {
  type: 'upstream_ready'
  stage: 'x224_complete' | 'x224_legacy' | string
  target_id: string
  negotiated_protocol_bits?: number
  tls_supported?: boolean
  nla_required?: boolean
  duration_ms: number
  note?: string
}

export interface UpstreamNegoFailure {
  type: 'upstream_nego_failure'
  stage: 'x224_neg_failure'
  target_id: string
  failure_code: number
  duration_ms: number
}

export interface UpstreamUnreachable {
  type: 'upstream_unreachable'
  stage: 'x224_failed'
  target_id: string
  msg: string
}

export interface RDPError {
  type: 'error'
  stage: string
  msg: string
}

// 5f-8b placeholders — narrow types so the canvas component can
// pattern-match today even though broker doesn't emit these yet.
export interface BitmapUpdate {
  type: 'bitmap_update'
  // Dirty rect in screen coordinates. Bitmap pixels follow as a
  // sibling binary WebSocket frame (raw RGBA, length = w*h*4).
  rect: { x: number; y: number; w: number; h: number }
}

export interface CursorUpdate {
  type: 'cursor'
  x: number
  y: number
  // ARGB pixel data follows as sibling binary frame, or null when
  // the cursor is just a hot-spot move.
  shape_id?: string
}

export const RDP_FAILURE_REASONS: Record<number, string> = {
  1: 'SSL_REQUIRED_BY_SERVER (server requires TLS but client did not request it)',
  2: 'SSL_NOT_ALLOWED_BY_SERVER',
  3: 'SSL_CERT_NOT_ON_SERVER',
  4: 'INCONSISTENT_FLAGS',
  5: 'HYBRID_REQUIRED_BY_SERVER (server requires NLA/CredSSP)',
  6: 'SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER',
}

/// Parse a string frame into a typed RDPFrame, or null if unrecognised.
export function parseRDPFrame(raw: string): RDPFrame | null {
  try {
    const f = JSON.parse(raw) as { type?: string }
    if (typeof f.type !== 'string') return null
    return f as RDPFrame
  } catch {
    return null
  }
}

// =========================================================================
// P2b TLV streaming protocol (ADR 0051) — the /ws/rdp-live binary wire.
//
// jess-web relays ONE WS BINARY frame per TLV message, with the u32 length
// prefix STRIPPED, so each WS binary frame is exactly [u8 msg_type][payload]
// (big-endian payload fields). This is the protocol the live RDPCanvas speaks
// against /ws/rdp-live.
// =========================================================================

// Server→client message types (jess-web strips the u32 len; first byte = type).
export const MSG_DESKTOP_SIZE = 1 // [u16 w][u16 h]
export const MSG_FRAME = 2 // [u16 x][u16 y][u16 w][u16 h][PNG bytes] — LOSSLESS
export const MSG_CLOSE = 3 // empty
export const MSG_FRAME_WEBP = 4 // [u16 x][u16 y][u16 w][u16 h][WebP bytes] — LOSSY (Tier-1 live default)
// MSG_H264 = the Tier-2 "native-feel" H.264 access-unit path (ADR 0053). This is
// an ADDITIVE, capability-gated codepath that runs in PARALLEL with the legacy
// PNG MSG_FRAME bitmap path — it never replaces it. The broker's in-tree
// MS-RDPEGFX/AVC420 handler emits one MSG_H264 per access unit (NAL units,
// Annex-B) when the H.264 path is active (JESS_RDP_H264 on, session not
// recorded, server selected AVC420); the browser feeds them to a WebCodecs
// VideoDecoder for hardware decode. The legacy PNG/WebP path stays the default
// and the guaranteed fallback for any session/region the server doesn't send as
// AVC420. (End-to-end pixels need a live AVC420-capable host to confirm.)
// [u8 flags][u16 x][u16 y][u16 w][u16 h][AVC NAL bytes (Annex-B)]
export const MSG_H264 = 5
export const MSG_ERROR = 0xff // jess-web-synthesised: [UTF-8 message]

// MSG_H264 flag bits (payload byte 0).
export const H264_FLAG_KEYFRAME = 0b0000_0001 // access unit is an IDR/keyframe
// Set on the MAIN view of an AVC444 4:4:4 update — a second MSG_H264 with
// H264_FLAG_AUX follows, carrying the chroma view to recombine (ADR 0059).
// Clear ⇒ a plain AVC420 4:2:0 single-stream frame.
export const H264_FLAG_AVC444 = 0b0000_0010
// Set on the AVC444 AUXILIARY (chroma) view — the broker's second
// RFX_AVC420_BITMAP_STREAM. The browser decodes it on a SECOND VideoDecoder and
// recombines its YUV planes with the preceding main view into true 4:4:4 in a
// WebGL shader (rdpAvc444.ts). Browsers that can't read I420 planes (HW decode)
// or lack WebGL2 ignore it and keep the main view's 4:2:0 (ADR 0059).
export const H264_FLAG_AUX = 0b0000_0100

// Client→server message types.
export const MSG_MOUSE = 1 // [u16 x][u16 y][u8 button_mask][i8 wheel]
export const MSG_KEY = 2 // [u8 is_down][u32 scancode]

// CLIPBOARD message type — BIDIRECTIONAL (ADR 0054, Tier-3 virtual channels).
// Body after the type byte is [u8 subtype][payload]. A deliberately HIGH number
// (0x20) so it never collides with the graphics/input types (1/2/3) nor the
// render-path types (4/5). The broker only negotiates CLIPRDR when enabled, so
// these frames only ever appear for clipboard-enabled sessions.
export const MSG_CLIPBOARD = 0x20

// Server→client clipboard subtypes (remote → browser).
export const CLIP_SUB_REMOTE_TEXT_AVAILABLE = 1 // remote copied text; payload empty
export const CLIP_SUB_REMOTE_TEXT_DATA = 2 // remote text (answer to a request); payload = UTF-8
export const CLIP_SUB_REMOTE_IMAGE_AVAILABLE = 3 // remote copied an image; payload empty
export const CLIP_SUB_REMOTE_IMAGE_DATA = 4 // remote image (answer); payload = PNG (DIB→PNG broker-side)

// Client→server clipboard subtypes (browser → remote).
export const CLIP_SUB_LOCAL_TEXT = 1 // browser clipboard text to push; payload = UTF-8
export const CLIP_SUB_REQUEST_REMOTE_TEXT = 2 // ask remote for its text; payload empty
export const CLIP_SUB_LOCAL_IMAGE = 3 // browser clipboard image to push; payload = PNG (→DIB broker-side)
export const CLIP_SUB_REQUEST_REMOTE_IMAGE = 4 // ask remote for its image; payload empty

// Button-mask bits.
export const BUTTON_LEFT = 0b001
export const BUTTON_RIGHT = 0b010
export const BUTTON_MIDDLE = 0b100

export type ServerTLV =
  | { kind: 'desktop_size'; width: number; height: number }
  // A dirty-region frame. `bytes` is the encoded image; `mime` selects the
  // decoder (PNG for the lossless MSG_FRAME, WebP for the lossy MSG_FRAME_WEBP).
  // Both decode through the SAME createImageBitmap path in the canvas.
  | { kind: 'frame'; x: number; y: number; w: number; h: number; bytes: Uint8Array; mime: 'image/png' | 'image/webp' }
  | { kind: 'h264'; keyframe: boolean; avc444: boolean; aux: boolean; x: number; y: number; w: number; h: number; nal: Uint8Array }
  | { kind: 'close' }
  | { kind: 'error'; msg: string }
  // CLIPBOARD (ADR 0054): remote → browser. 'clipboard_available' = the remote
  // copied text (offer a paste-into-browser); 'clipboard_text' = the remote's
  // text (answer to a request) to write into navigator.clipboard.
  | { kind: 'clipboard_available' }
  | { kind: 'clipboard_text'; text: string }
  // CLIPBOARD images (ADR 0054 follow-up). 'clipboard_image_available' = remote
  // copied an image; 'clipboard_image' = the remote's image as PNG.
  | { kind: 'clipboard_image_available' }
  | { kind: 'clipboard_image'; png: Uint8Array }
  | { kind: 'unknown'; type: number }

// decodeServerTLV parses one WS binary frame ([u8 type][payload], len already
// stripped by jess-web) into a typed server message.
export function decodeServerTLV(buf: ArrayBuffer): ServerTLV {
  const view = new DataView(buf)
  if (view.byteLength < 1) return { kind: 'unknown', type: -1 }
  const type = view.getUint8(0)
  switch (type) {
    case MSG_DESKTOP_SIZE:
      return { kind: 'desktop_size', width: view.getUint16(1), height: view.getUint16(3) }
    case MSG_FRAME:
    case MSG_FRAME_WEBP: {
      // Identical geometry header for both image formats; only the body codec
      // differs ([u16 x][u16 y][u16 w][u16 h][image bytes]).
      const x = view.getUint16(1)
      const y = view.getUint16(3)
      const w = view.getUint16(5)
      const h = view.getUint16(7)
      const bytes = new Uint8Array(buf, 9)
      const mime = type === MSG_FRAME_WEBP ? 'image/webp' : 'image/png'
      return { kind: 'frame', x, y, w, h, bytes, mime }
    }
    case MSG_H264: {
      // [u8 flags][u16 x][u16 y][u16 w][u16 h][AVC NAL bytes]. Tier-2 path.
      if (view.byteLength < 10) return { kind: 'unknown', type }
      const flags = view.getUint8(1)
      const x = view.getUint16(2)
      const y = view.getUint16(4)
      const w = view.getUint16(6)
      const h = view.getUint16(8)
      const nal = new Uint8Array(buf, 10)
      return {
        kind: 'h264',
        keyframe: (flags & H264_FLAG_KEYFRAME) !== 0,
        avc444: (flags & H264_FLAG_AVC444) !== 0,
        aux: (flags & H264_FLAG_AUX) !== 0,
        x,
        y,
        w,
        h,
        nal,
      }
    }
    case MSG_CLOSE:
      return { kind: 'close' }
    case MSG_ERROR:
      return { kind: 'error', msg: new TextDecoder().decode(new Uint8Array(buf, 1)) }
    case MSG_CLIPBOARD: {
      // [u8 type][u8 subtype][payload]
      if (view.byteLength < 2) return { kind: 'unknown', type }
      const subtype = view.getUint8(1)
      if (subtype === CLIP_SUB_REMOTE_TEXT_AVAILABLE) return { kind: 'clipboard_available' }
      if (subtype === CLIP_SUB_REMOTE_TEXT_DATA) {
        const text = new TextDecoder().decode(new Uint8Array(buf, 2))
        return { kind: 'clipboard_text', text }
      }
      if (subtype === CLIP_SUB_REMOTE_IMAGE_AVAILABLE) return { kind: 'clipboard_image_available' }
      if (subtype === CLIP_SUB_REMOTE_IMAGE_DATA) {
        return { kind: 'clipboard_image', png: new Uint8Array(buf, 2) }
      }
      return { kind: 'unknown', type }
    }
    default:
      return { kind: 'unknown', type }
  }
}

// encodeClipboardTextTLV builds a [u8 CLIPBOARD][u8 LOCAL_TEXT][UTF-8 text] WS
// binary frame — the browser advertising its clipboard text to the remote.
export function encodeClipboardTextTLV(text: string): Uint8Array {
  const enc = new TextEncoder().encode(text)
  const out = new Uint8Array(2 + enc.length)
  out[0] = MSG_CLIPBOARD
  out[1] = CLIP_SUB_LOCAL_TEXT
  out.set(enc, 2)
  return out
}

// encodeClipboardRequestTLV builds a [u8 CLIPBOARD][u8 REQUEST_REMOTE_TEXT] WS
// binary frame — the browser asking the remote for its clipboard text (so it
// can be written into navigator.clipboard for a local paste).
export function encodeClipboardRequestTLV(): Uint8Array {
  return new Uint8Array([MSG_CLIPBOARD, CLIP_SUB_REQUEST_REMOTE_TEXT])
}

// encodeClipboardImageTLV builds a [u8 CLIPBOARD][u8 LOCAL_IMAGE][PNG bytes]
// frame — the browser advertising its clipboard image to the remote (the broker
// converts the PNG to CF_DIB).
export function encodeClipboardImageTLV(png: Uint8Array): Uint8Array {
  const out = new Uint8Array(2 + png.length)
  out[0] = MSG_CLIPBOARD
  out[1] = CLIP_SUB_LOCAL_IMAGE
  out.set(png, 2)
  return out
}

// encodeClipboardRequestImageTLV builds a [u8 CLIPBOARD][u8 REQUEST_REMOTE_IMAGE]
// frame — the browser asking the remote for its clipboard image.
export function encodeClipboardRequestImageTLV(): Uint8Array {
  return new Uint8Array([MSG_CLIPBOARD, CLIP_SUB_REQUEST_REMOTE_IMAGE])
}

// encodeMouseTLV builds a [u8 MOUSE][u16 x][u16 y][u8 mask][i8 wheel] WS binary
// frame (no u32 len — jess-web prepends it).
export function encodeMouseTLV(x: number, y: number, buttonMask: number, wheel: number): Uint8Array {
  const buf = new ArrayBuffer(7)
  const v = new DataView(buf)
  v.setUint8(0, MSG_MOUSE)
  v.setUint16(1, clampU16(x))
  v.setUint16(3, clampU16(y))
  v.setUint8(5, buttonMask & 0xff)
  v.setInt8(6, clampI8(wheel))
  return new Uint8Array(buf)
}

// encodeKeyTLV builds a [u8 KEY][u8 is_down][u32 scancode] WS binary frame.
export function encodeKeyTLV(isDown: boolean, scancode: number): Uint8Array {
  const buf = new ArrayBuffer(6)
  const v = new DataView(buf)
  v.setUint8(0, MSG_KEY)
  v.setUint8(1, isDown ? 1 : 0)
  v.setUint32(2, scancode >>> 0)
  return new Uint8Array(buf)
}

function clampU16(n: number): number {
  return Math.max(0, Math.min(0xffff, Math.round(n)))
}
function clampI8(n: number): number {
  return Math.max(-128, Math.min(127, Math.round(n)))
}

// =========================================================================
// jess-rdp-recording-v2 replay (ADR 0051 P4).
//
// A sealed recording is NDJSON: a one-time meta header then one line per event.
// The SPA replay reuses the SAME render path as the live session: bitmap-driven
// recordings re-decode each FRAME's base64 PNG and blit it; EGFX/AVC420 (H.264)
// recordings (ADR 0058) feed each `h264` event's base64 NAL to the SAME WebCodecs
// decoder the live console uses (rdpH264.ts), drawing the decoded VideoFrames —
// all with the original wall-clock timing.
// =========================================================================

export interface RDPRecordingSummary {
  session_id: string
  target_id: string
  grant_id?: string
  started_at: string
  sealed_at: string
  bytes: number
  format: string
}

export interface RDPV2Meta {
  kind: 'meta'
  version: number
  protocol: string
  subject: string
  target: string
  session_id?: string
  at: string
}

// One replay event. `kind` discriminates; only the fields for that kind are set.
export interface RDPV2Event {
  kind: 'resize' | 'frame' | 'h264' | 'input' | 'close'
  seq: number
  at: string
  // resize + frame + h264 geometry (the surface rect this event paints into).
  x?: number
  y?: number
  width?: number
  height?: number
  // frame pixels (base64 PNG) + truncation flag.
  png_b64?: string
  truncated?: boolean
  // h264 access unit (ADR 0058): the Annex-B NAL bytes (base64), the keyframe
  // flag (IDR carrying SPS+PPS — a replayer can (re)init its decoder from it),
  // and the AVC444 flag. Present only on `kind:'h264'` events (EGFX/AVC420
  // sessions). `frame` (PNG) and `h264` never coexist in one recording.
  nal_b64?: string
  keyframe?: boolean
  avc444?: boolean
  // input.
  input?: 'mouse' | 'key'
  mouse_x?: number
  mouse_y?: number
  buttons?: number
  wheel?: number
  key_down?: boolean
  scancode?: number
}

export interface RDPRecording {
  meta: RDPV2Meta
  events: RDPV2Event[]
}

// parseRDPRecordingNDJSON parses the sealed v2 content stream into a meta header
// + ordered events. Throws if line 1 isn't a v2 meta header.
export function parseRDPRecordingNDJSON(text: string): RDPRecording {
  const lines = text.split('\n').filter((l) => l.trim().length > 0)
  if (lines.length === 0) throw new Error('empty recording')
  const meta = JSON.parse(lines[0]) as RDPV2Meta
  if (meta.kind !== 'meta' || meta.version !== 2) {
    throw new Error('not a jess-rdp-recording-v2 stream')
  }
  const events: RDPV2Event[] = []
  for (let i = 1; i < lines.length; i++) {
    events.push(JSON.parse(lines[i]) as RDPV2Event)
  }
  return { meta, events }
}

// base64ToBytes decodes a base64 string to a Uint8Array (for frame PNG blits).
export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

// rdpH264 — Tier-2 "native-feel" H.264 decode path (ADR 0053).
//
// A SELF-CONTAINED, capability-gated WebCodecs decoder for the MSG_H264 TLV
// (see rdp.ts). It runs in PARALLEL with the legacy PNG MSG_FRAME bitmap path —
// RDPCanvas chooses the H.264 path ONLY when:
//   1. `'VideoDecoder' in window` (the browser exposes WebCodecs), AND
//   2. the H.264 flag is enabled (h264Enabled()), AND
//   3. the broker actually emits MSG_H264 access units.
// If any of those is false the canvas keeps painting the PNG path exactly as
// today. This module never touches the PNG path.
//
// STATUS (ADR 0053): the broker's in-tree MS-RDPEGFX/AVC420 handler now emits
// MSG_H264 when the H.264 path is active (server selected AVC420). This module is
// the matching browser-side WebCodecs decoder. End-to-end pixel correctness still
// needs a live AVC420-capable Windows host to confirm (none in CI); on any
// decoder error RDPCanvas drops the decoder and stays on the PNG/WebP path.
//
// WebCodecs notes (from the AVC WebCodecs registration, w3.org):
//   * We feed Annex-B (start-code-delimited NAL units) and configure the decoder
//     with `description` ABSENT, which selects Annex-B mode. A keyframe access
//     unit MUST carry SPS+PPS+IDR so the decoder can (re)initialise from it —
//     RDP AVC420 keyframes do exactly this, matching the live-streaming pattern.
//   * codec string "avc1.42E01F" = Constrained Baseline L3.1, the conservative
//     profile RDP AVC420 uses; the real broker can refine it from the SPS.

// --- Minimal WebCodecs ambient surface -----------------------------------
//
// TypeScript's bundled `DOM` lib does NOT yet ship WebCodecs types, and we keep
// dependencies minimal (no @types/dom-webcodecs). Declare ONLY the slice we use.
// These are structural; at runtime the real platform objects are used.

type CodecState = 'unconfigured' | 'configured' | 'closed'

interface VideoFrameLike {
  readonly displayWidth: number
  readonly displayHeight: number
  close(): void
}

interface EncodedVideoChunkInitLike {
  type: 'key' | 'delta'
  timestamp: number
  duration?: number
  data: BufferSource
}

interface EncodedVideoChunkCtor {
  new (init: EncodedVideoChunkInitLike): unknown
}

interface VideoDecoderConfigLike {
  codec: string
  codedWidth?: number
  codedHeight?: number
  // `description` ABSENT ⇒ Annex-B mode (start-code-delimited). Present ⇒ AVCC.
  description?: BufferSource
  optimizeForLatency?: boolean
}

interface VideoDecoderInitLike {
  output: (frame: VideoFrameLike) => void
  error: (e: DOMException) => void
}

interface VideoDecoderLike {
  readonly state: CodecState
  configure(config: VideoDecoderConfigLike): void
  decode(chunk: unknown): void
  flush(): Promise<void>
  close(): void
}

interface VideoDecoderCtor {
  new (init: VideoDecoderInitLike): VideoDecoderLike
  isConfigSupported?: (config: VideoDecoderConfigLike) => Promise<{ supported?: boolean }>
}

// Window augmentation for the two constructors we reach for.
declare global {
  interface Window {
    VideoDecoder?: VideoDecoderCtor
    EncodedVideoChunk?: EncodedVideoChunkCtor
  }
}

// --- capability + flag gating --------------------------------------------

// hasWebCodecsH264 reports whether the platform exposes the WebCodecs surface we
// need. This is the `'VideoDecoder' in window` capability check the task calls
// for, plus the EncodedVideoChunk constructor we feed it.
export function hasWebCodecsH264(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.VideoDecoder !== 'undefined' &&
    typeof window.EncodedVideoChunk !== 'undefined'
  )
}

// h264Enabled is the OPT-IN flag gate for the Tier-2 path. Default OFF so the
// bitmap path can never be regressed by an incomplete H.264 pipeline. Enabled by
// either a build-time env (VITE_RDP_H264=1) or a runtime localStorage toggle
// (`jess.rdp.h264 = "1"`) for operator A/B testing without a rebuild.
export function h264Enabled(): boolean {
  try {
    if (typeof localStorage !== 'undefined' && localStorage.getItem('jess.rdp.h264') === '1') {
      return true
    }
  } catch {
    // localStorage may throw in privacy modes — fall through to the env flag.
  }
  // import.meta.env is replaced at build time by Vite.
  const env = (import.meta as unknown as { env?: Record<string, string | undefined> }).env
  return env?.VITE_RDP_H264 === '1'
}

// h264PathActive = the full gate: WebCodecs present AND the flag on. RDPCanvas
// uses this to decide whether to construct a decoder when the first MSG_H264
// arrives. Both conditions must hold or we stay on the PNG path.
export function h264PathActive(): boolean {
  return hasWebCodecsH264() && h264Enabled()
}

// --- the decoder ----------------------------------------------------------

export interface H264FrameRegion {
  // Where in the framebuffer this access unit paints (EGFX surface rect). For a
  // full-screen AVC420 stream this is the whole desktop; for a sub-surface it's
  // the dirty region.
  x: number
  y: number
  w: number
  h: number
}

export interface RDPH264DecoderOptions {
  // Called for each decoded VideoFrame, with the region it should paint into.
  // The caller (RDPCanvas) draws the frame to the canvas/OffscreenCanvas and is
  // RESPONSIBLE for calling frame.close() to release the (scarce) decoder
  // buffer — WebCodecs frames are ref-counted GPU/CPU resources.
  onFrame: (frame: VideoFrameLike, region: H264FrameRegion) => void
  // Called on an unrecoverable decoder error. RDPCanvas should fall back to / stay
  // on the PNG path and surface a status.
  onError: (msg: string) => void
  // AVC profile/level codec string. Defaults to Constrained Baseline L3.1
  // (RDP AVC420's typical profile). The broker can override from the SPS later.
  codec?: string
}

// RDPH264Decoder wraps a WebCodecs VideoDecoder for the MSG_H264 access-unit
// stream. It is lazily configured from the first KEYFRAME (which carries SPS/PPS
// in Annex-B), drops delta frames that arrive before the first keyframe (the
// decoder can't start mid-GOP), and monotonically increments a timestamp so the
// decoder orders output. One decoder instance per session.
export class RDPH264Decoder {
  private decoder: VideoDecoderLike | null = null
  private configured = false
  private sawKeyframe = false
  private ts = 0
  // The region of the LAST submitted access unit, paired to the next output
  // frame. WebCodecs output is async + ordered; for the single-stream AVC420
  // case the region is effectively constant (full surface), so a single-slot
  // latch is correct. A multi-surface EGFX stream would need a per-timestamp map
  // (noted in ADR 0053 remaining-work).
  private pendingRegion: H264FrameRegion = { x: 0, y: 0, w: 0, h: 0 }
  private readonly opts: RDPH264DecoderOptions
  private closed = false

  constructor(opts: RDPH264DecoderOptions) {
    this.opts = opts
  }

  // submit feeds one MSG_H264 access unit (Annex-B NAL bytes) to the decoder.
  // `keyframe` selects the EncodedVideoChunk type ('key' vs 'delta'); the
  // decoder is configured lazily on the first keyframe so it can read SPS/PPS.
  submit(nal: Uint8Array, keyframe: boolean, region: H264FrameRegion): void {
    if (this.closed || nal.length === 0) return
    if (!hasWebCodecsH264()) {
      this.fail('WebCodecs VideoDecoder not available')
      return
    }
    // Can't start decoding mid-GOP: ignore deltas until the first keyframe.
    if (!this.sawKeyframe && !keyframe) return

    if (!this.configured) {
      if (!keyframe) return // wait for a keyframe to configure from
      if (!this.configure(region)) return
    }
    if (keyframe) this.sawKeyframe = true
    this.pendingRegion = region

    const dec = this.decoder
    const ChunkCtor = window.EncodedVideoChunk
    if (!dec || !ChunkCtor || dec.state !== 'configured') return
    try {
      // Copy into a standalone buffer: the WS frame's backing ArrayBuffer may be
      // reused, and EncodedVideoChunk references the bytes.
      const chunk = new ChunkCtor({
        type: keyframe ? 'key' : 'delta',
        timestamp: this.ts,
        data: nal.slice(),
      })
      this.ts += 16_666 // ~60fps in microseconds; ordering only, not playback rate
      dec.decode(chunk)
    } catch (e) {
      this.fail(`H.264 decode failed: ${String(e)}`)
    }
  }

  private configure(region: H264FrameRegion): boolean {
    const Ctor = window.VideoDecoder
    if (!Ctor) {
      this.fail('VideoDecoder constructor missing')
      return false
    }
    try {
      this.decoder = new Ctor({
        output: (frame: VideoFrameLike) => {
          if (this.closed) {
            frame.close()
            return
          }
          this.opts.onFrame(frame, this.pendingRegion)
        },
        error: (e: DOMException) => this.fail(`VideoDecoder error: ${e.message ?? String(e)}`),
      })
      this.decoder.configure({
        codec: this.opts.codec ?? 'avc1.42E01F',
        codedWidth: region.w || undefined,
        codedHeight: region.h || undefined,
        // No `description` ⇒ Annex-B mode (RDP AVC420 ships start-code NALs with
        // in-band SPS/PPS on keyframes).
        optimizeForLatency: true,
      })
      this.configured = true
      return true
    } catch (e) {
      this.fail(`VideoDecoder.configure failed: ${String(e)}`)
      return false
    }
  }

  private fail(msg: string): void {
    if (this.closed) return
    this.closed = true
    this.opts.onError(msg)
    this.close()
  }

  close(): void {
    this.closed = true
    const dec = this.decoder
    this.decoder = null
    if (dec && dec.state !== 'closed') {
      try {
        dec.close()
      } catch {
        // already torn down
      }
    }
  }
}

export type { VideoFrameLike }

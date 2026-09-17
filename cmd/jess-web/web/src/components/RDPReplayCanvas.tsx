// RDPReplayCanvas — ADR 0051 P4 replay mode.
//
// Plays back a sealed jess-rdp-recording-v2 bundle: it fetches the NDJSON content
// (owner-scoped, from /api/rdp/recordings/{id}), parses the meta + events, sizes
// the canvas from the first DESKTOP_SIZE, and re-blits each FRAME's decoded PNG
// at the original wall-clock timing (relative to the first event). It reuses the
// SAME blit path as the live RDPCanvas (createImageBitmap → ctx.drawImage), which
// is the whole point of the ADR 0051 "decoded stream" fork: replay needs no
// separate RDP renderer.
//
// H.264 (ADR 0058): an EGFX/AVC420 recording stores `h264` events (Annex-B NAL +
// keyframe flag + surface rect) instead of `frame` PNGs. Replay feeds each NAL to
// the SAME WebCodecs RDPH264Decoder the live console uses (rdpH264.ts) and draws
// the decoded VideoFrames — the decoder is configured lazily from the first
// keyframe. If the browser lacks WebCodecs, H.264 replay is skipped (with a status
// note); the PNG path is unaffected. A recording is either PNG-driven or
// H.264-driven, never both.
//
// HONEST STATUS: the parse + timing + blit path is unit-tested at the data layer
// (parseRDPRecordingNDJSON + the Go recorder produces these exact records). The
// visual playback (pixels painting in order) is operator-verified — this is the
// player, not a proof. The H.264 decode-on-replay path additionally needs an
// AVC420-encoding host to produce a real recording to confirm pixels (none in CI).
//
// PASS 2: a C2 player chrome (Play/Pause/Restart/Download + a scrubber readout)
// over a centred desktop canvas, and it reports the parsed meta + counts to the
// parent via `onMeta` so the recordings page can render a metadata side panel.
// The fetch + parse + timing + blit logic is UNCHANGED.

import { useCallback, useEffect, useRef, useState } from 'react'
import {
  base64ToBytes,
  parseRDPRecordingNDJSON,
  type RDPRecording,
  type RDPV2Event,
  type RDPV2Meta,
} from '../api/rdp'
import { RDPH264Decoder, hasWebCodecsH264, type VideoFrameLike } from '../api/rdpH264'

export interface RDPReplayMeta {
  meta: RDPV2Meta
  frameCount: number
  inputCount: number
  eventCount: number
}

interface RDPReplayCanvasProps {
  sessionId: string
  onMeta?: (m: RDPReplayMeta) => void
}

type State =
  | { kind: 'loading' }
  | { kind: 'error'; msg: string }
  | { kind: 'ready'; rec: RDPRecording }

export function RDPReplayCanvas({ sessionId, onMeta }: RDPReplayCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const ctxRef = useRef<CanvasRenderingContext2D | null>(null)
  const [state, setState] = useState<State>({ kind: 'loading' })
  const [playing, setPlaying] = useState(false)
  const [cursor, setCursor] = useState(0) // index of next event to apply
  const cancelRef = useRef(false)
  // H.264 (ADR 0058) replay decoder — lazily created when the first `h264` event
  // is reached. One per play-through; torn down on pause/restart/unmount.
  const h264Ref = useRef<RDPH264Decoder | null>(null)
  const [h264Note, setH264Note] = useState<string | null>(null)

  // disposeH264 tears down the live decoder (so a restart re-configures from the
  // next keyframe). Safe to call when there is no decoder.
  const disposeH264 = useCallback(() => {
    h264Ref.current?.close()
    h264Ref.current = null
  }, [])

  // Fetch + parse the recording on mount.
  useEffect(() => {
    cancelRef.current = false
    setState({ kind: 'loading' })
    fetch(`/api/rdp/recordings/${encodeURIComponent(sessionId)}`, {
      credentials: 'same-origin',
      cache: 'no-store',
    })
      .then(async (r) => {
        if (!r.ok) throw new Error(`recording fetch failed (${r.status})`)
        return r.text()
      })
      .then((text) => {
        if (cancelRef.current) return
        const rec = parseRDPRecordingNDJSON(text)
        setState({ kind: 'ready', rec })
        onMeta?.({
          meta: rec.meta,
          // Count both bitmap (PNG) and H.264 (ADR 0058) frames as "frames".
          frameCount: rec.events.filter((e) => e.kind === 'frame' || e.kind === 'h264').length,
          inputCount: rec.events.filter((e) => e.kind === 'input').length,
          eventCount: rec.events.length,
        })
      })
      .catch((e: unknown) => {
        if (cancelRef.current) return
        setState({ kind: 'error', msg: e instanceof Error ? e.message : String(e) })
      })
    return () => {
      cancelRef.current = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId])

  // Tear the H.264 decoder down on unmount (release the WebCodecs resource).
  useEffect(() => disposeH264, [disposeH264])

  // Draw a single FRAME event onto the canvas.
  const drawFrame = useCallback(async (ev: RDPV2Event) => {
    const ctx = ctxRef.current
    if (!ctx || !ev.png_b64) return
    try {
      const bytes = base64ToBytes(ev.png_b64)
      const blob = new Blob([bytes], { type: 'image/png' })
      const bmp = await createImageBitmap(blob)
      ctx.drawImage(bmp, ev.x ?? 0, ev.y ?? 0)
      bmp.close?.()
    } catch {
      // A single decode failure shouldn't kill playback; skip the region.
    }
  }, [])

  // Feed one H.264 access unit (ADR 0058) to the WebCodecs decoder, drawing each
  // decoded VideoFrame into the canvas at its surface rect. The decoder is created
  // lazily here (from the first event) so we don't spin one up for PNG recordings.
  const drawH264 = useCallback((ev: RDPV2Event) => {
    if (!ev.nal_b64) return
    if (!hasWebCodecsH264()) {
      setH264Note((n) => n ?? 'H.264 replay unavailable — this browser lacks WebCodecs (VideoDecoder).')
      return
    }
    if (!h264Ref.current) {
      h264Ref.current = new RDPH264Decoder({
        onFrame: (frame: VideoFrameLike, region) => {
          const ctx = ctxRef.current
          try {
            // VideoFrame is a CanvasImageSource; draw it at the surface origin.
            if (ctx) ctx.drawImage(frame as unknown as CanvasImageSource, region.x, region.y)
          } catch {
            // A single draw failure shouldn't kill playback.
          } finally {
            frame.close() // release the scarce decoder buffer (caller's contract)
          }
        },
        onError: (msg: string) => {
          setH264Note(`H.264 replay decode error: ${msg}`)
        },
      })
    }
    h264Ref.current.submit(base64ToBytes(ev.nal_b64), !!ev.keyframe, {
      x: ev.x ?? 0,
      y: ev.y ?? 0,
      w: ev.width ?? 0,
      h: ev.height ?? 0,
    })
  }, [])

  // Apply a resize event (size the canvas + clear).
  const applyResize = useCallback((ev: RDPV2Event) => {
    const c = canvasRef.current
    if (!c) return
    c.width = ev.width ?? c.width
    c.height = ev.height ?? c.height
    ctxRef.current = c.getContext('2d')
    if (ctxRef.current) {
      ctxRef.current.fillStyle = '#000'
      ctxRef.current.fillRect(0, 0, c.width, c.height)
    }
  }, [])

  // Play from `cursor` to the end, honouring original inter-event timing.
  const play = useCallback(async () => {
    if (state.kind !== 'ready') return
    setPlaying(true)
    cancelRef.current = false
    const { events } = state.rec
    const t0 = events.length > 0 ? new Date(events[0].at).getTime() : 0
    const startWall = performance.now()
    for (let i = cursor; i < events.length; i++) {
      if (cancelRef.current) break
      const ev = events[i]
      // Wait until this event's relative offset elapses (capped so a long idle
      // gap doesn't stall the player for minutes).
      const relMs = Math.min(new Date(ev.at).getTime() - t0, Number.MAX_SAFE_INTEGER)
      const elapsed = performance.now() - startWall
      const wait = Math.max(0, Math.min(relMs - elapsed, 5000))
      if (wait > 0) await sleep(wait)
      if (ev.kind === 'resize') applyResize(ev)
      else if (ev.kind === 'frame') await drawFrame(ev)
      else if (ev.kind === 'h264') drawH264(ev)
      setCursor(i + 1)
    }
    setPlaying(false)
  }, [state, cursor, applyResize, drawFrame, drawH264])

  const pause = useCallback(() => {
    cancelRef.current = true
    setPlaying(false)
  }, [])

  // Restart from the beginning: re-apply every resize/frame instantly (no timing)
  // up to the end so the operator can scrub to "final state" quickly, then reset.
  const restart = useCallback(() => {
    cancelRef.current = true
    setPlaying(false)
    setCursor(0)
    // Drop the H.264 decoder so the next play-through re-configures from the first
    // keyframe (a decoder can't resume mid-GOP after we rewind to seq 0).
    disposeH264()
    setH264Note(null)
    const c = canvasRef.current
    if (c && ctxRef.current) {
      ctxRef.current.fillStyle = '#000'
      ctxRef.current.fillRect(0, 0, c.width, c.height)
    }
  }, [disposeH264])

  if (state.kind === 'loading') {
    return <div className="c2-replay-stage"><p className="c2-ink-3" style={{ margin: 0 }}>Loading recording…</p></div>
  }
  if (state.kind === 'error') {
    return (
      <div className="c2-replay-stage">
        <span className="c2-badge c2-badge-danger" style={{ paddingLeft: 7 }}>error: {state.msg}</span>
      </div>
    )
  }

  const { events } = state.rec
  const frameCount = events.filter((e) => e.kind === 'frame' || e.kind === 'h264').length
  const inputCount = events.filter((e) => e.kind === 'input').length

  return (
    <div className="c2-replay">
      <div className="c2-replay-controls">
        {playing ? (
          <button className="c2-btn c2-btn-ghost c2-btn-sm" onClick={pause}>⏸ Pause</button>
        ) : (
          <button className="c2-btn c2-btn-primary c2-btn-sm" onClick={() => void play()}>▶ Play</button>
        )}
        <button className="c2-btn c2-btn-ghost c2-btn-sm" onClick={restart}>⟲ Restart</button>
        <a
          className="c2-btn c2-btn-ghost c2-btn-sm"
          href={`/api/rdp/recordings/${encodeURIComponent(sessionId)}`}
          download={`${sessionId}.ndjson`}
        >
          ⤓ NDJSON
        </a>
        <span className="c2-toolbar-spacer" />
        {h264Note && (
          <span className="c2-badge c2-badge-warning" style={{ paddingLeft: 7 }} title={h264Note}>
            H.264: {h264Note}
          </span>
        )}
        <span className="c2-replay-scrubber" title="frames · inputs · cursor/total events">
          {frameCount} frames · {inputCount} inputs · {cursor}/{events.length}
        </span>
      </div>
      <div className="c2-replay-stage">
        <canvas ref={canvasRef} width={1280} height={1024} className="c2-replay-canvas" aria-label={`Replay of ${sessionId}`} />
      </div>
    </div>
  )
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

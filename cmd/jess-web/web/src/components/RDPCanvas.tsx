// RDPCanvas — ADR 0051 P2c "first pixels in the browser".
//
// Renders the LIVE decoded Windows desktop streamed over the P2b TLV protocol
// from /ws/rdp-live (the in-process Go↔Rust bridge), and sends keyboard/mouse
// back. Each server message arrives as ONE WS BINARY frame [u8 type][payload]
// (jess-web strips the u32 length):
//
//   DESKTOP_SIZE → size the <canvas> to the negotiated desktop
//   FRAME(x,y,w,h,PNG) / FRAME_WEBP(x,y,w,h,WebP) → createImageBitmap(Blob)
//     → queue → blit in a requestAnimationFrame tick → ctx.drawImage(bmp,x,y)
//   CLOSE → session ended; ERROR(0xFF) → render the message
//
// TIER-1 RENDER PATH: the live wire is LOSSY WebP (MSG_FRAME_WEBP=4) by default
// — markedly smaller than the lossless PNG (MSG_FRAME=2, still accepted for the
// lossless mode + replay). Both decode through createImageBitmap, which runs the
// image decode OFF the main thread; decoded bitmaps are batched and blitted in a
// single rAF tick so the main thread does at most one paint per display frame
// (~60fps), coalescing decode bursts and never blocking input.
//
// Input: pointer move/down/up + wheel → MOUSE TLV (coords scaled to desktop),
// keydown/keyup → KEY TLV (KeyboardEvent.code → RDP scancode, 0xE0 high byte for
// extended keys). Sent as WS BINARY [type][payload]; jess-web prepends the len.
//
// HONEST STATUS: the byte path (Go bridge relays real frames; WS framing) is
// unit- + live-tested. The browser VISUAL (pixels actually painting) is
// operator-verified — this component is the renderer, not a proof.
//
// PASS 2: the status pill / chrome moved up into the C2 ConsoleFrame (RDP.tsx).
// This component now (a) reports its live status to the parent via `onStatus`
// so the toolbar badge + overlay reflect DESKTOP_SIZE / frame-count / the real
// close reason, and (b) exposes an imperative `sendCtrlAltDel()` for the
// toolbar's "Send Ctrl-Alt-Del" button. The TLV decode + mouse/keyboard relay
// + WS-error-surfacing logic are UNCHANGED.

import {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useRef,
  useState,
} from 'react'
import {
  BUTTON_LEFT,
  BUTTON_MIDDLE,
  BUTTON_RIGHT,
  decodeServerTLV,
  encodeClipboardImageTLV,
  encodeClipboardRequestImageTLV,
  encodeClipboardRequestTLV,
  encodeClipboardTextTLV,
  encodeKeyTLV,
  encodeMouseTLV,
} from '../api/rdp'
import { RDPH264Decoder, h264PathActive } from '../api/rdpH264'
import { RDPAvc444Decoder, hasAvc444Support } from '../api/rdpAvc444'
import { openRDPSocket, type RDPSocket } from '../api/rdpTransport'
import { scancodeFor } from '../api/rdpScancodes'

interface RDPCanvasProps {
  targetId: string
  // Fallback width/height (CSS px) until DESKTOP_SIZE arrives.
  width: number
  height: number
  grantId?: string
  // Report status transitions to the parent (toolbar badge + overlay).
  onStatus?: (s: RDPStatus) => void
  // Explicit desktop size (DEVICE px) to request via ?w=&h= (session settings:
  // a preset / custom resolution × the DPI multiplier). When undefined, the
  // canvas auto-measures its stage ("Match window" — today's behaviour).
  desiredSize?: { w: number; h: number }
  // CLIPBOARD sync (ADR 0054, Tier-3 virtual channels). When true (the
  // default), bidirectional TEXT clipboard sync is attempted via the async
  // Clipboard API, gated on the document being focused + the API being
  // available. Harmless when the broker did NOT negotiate CLIPRDR for the
  // session: the browser's outbound clipboard frames are simply ignored
  // server-side, and no remote clipboard events ever arrive.
  clipboard?: boolean
}

export type RDPStatus =
  | { kind: 'opening' }
  | { kind: 'live'; w: number; h: number; frames: number }
  | { kind: 'closed'; reason: string }
  | { kind: 'error'; msg: string }

export interface RDPCanvasHandle {
  // Send the Ctrl-Alt-Del secure-attention sequence to the remote desktop.
  sendCtrlAltDel: () => void
  // Focus the canvas (so keyboard input is captured).
  focus: () => void
}

export const RDPCanvas = forwardRef<RDPCanvasHandle, RDPCanvasProps>(function RDPCanvas(
  { targetId, width, height, grantId, onStatus, desiredSize, clipboard = true }: RDPCanvasProps,
  ref,
) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const wsRef = useRef<RDPSocket | null>(null)
  const ctxRef = useRef<CanvasRenderingContext2D | null>(null)
  const deskRef = useRef<{ w: number; h: number }>({ w: width, h: height })
  const framesRef = useRef(0)
  const buttonMaskRef = useRef(0)
  // Frame pacing/coalescing: dirty-region bitmaps decoded off the main thread
  // (createImageBitmap) queue here and are blitted in arrival order inside a
  // single requestAnimationFrame tick — capping the layout-flushing drawImage
  // cycles at the display refresh rate (~60fps) while preserving every region
  // (dropping a dirty rect would desync the canvas). The queue is bounded so a
  // decode burst on a slow tab can't grow it without limit: oldest pending
  // regions past the cap are closed + dropped (a fresher full region will
  // repaint that area), trading a momentary stale patch for bounded memory.
  const pendingRef = useRef<Array<{ bmp: ImageBitmap; x: number; y: number }>>([])
  const rafRef = useRef<number | null>(null)
  // Tier-2 H.264 decoder (ADR 0053). Lazily constructed on the first MSG_H264
  // ONLY when the WebCodecs+flag gate is open; null = the PNG bitmap path (the
  // default + guaranteed fallback). Torn down on unmount / session close.
  const h264Ref = useRef<RDPH264Decoder | null>(null)
  // AVC444 4:4:4 recombine decoder (ADR 0059). Lazily constructed on the first
  // AVC444 (main/aux) MSG_H264 when WebGL2+WebCodecs are present; recombines the
  // dual stream into true 4:4:4, falling back to the 4:2:0 main view when plane
  // readback isn't possible. null = not an AVC444 session.
  const avc444Ref = useRef<RDPAvc444Decoder | null>(null)
  // CLIPBOARD sync (ADR 0054). The last clipboard text we observed in EITHER
  // direction, so we don't loop (push the same text the remote just sent us, or
  // re-push an unchanged local clipboard). A single shared value is enough: a
  // round-trip leaves both sides holding the same string.
  const lastClipTextRef = useRef<string>('')
  // CLIPBOARD image dedup (byte length of the last image seen in either
  // direction) — a cheap guard against the remote→browser→remote echo loop.
  const lastClipImageLenRef = useRef<number>(0)
  // Latch for the server's authoritative 0xFF error TLV. The broker fails
  // closed by sending an ERROR(0xFF) message (e.g. "a grant id is required",
  // "rdp live bridge not configured", "target … is not an RDP target") over
  // onmessage, THEN closing the socket. The gateway strips the WS close-frame
  // reason, so onerror/onclose only carry the generic "transport error" /
  // "code 1006". This ref captures the real reason synchronously the instant
  // it arrives, so the later generic onerror/onclose can defer to it without
  // depending on React state-update ordering.
  const serverErrorRef = useRef<string | null>(null)
  const [status, setStatus] = useState<RDPStatus>({ kind: 'opening' })

  // Keep the parent in sync with every status change (toolbar + overlay).
  useEffect(() => { onStatus?.(status) }, [status, onStatus])

  // Open the live WS on mount; tear down on unmount.
  useEffect(() => {
    framesRef.current = 0
    serverErrorRef.current = null // fresh connection — drop any prior latched error
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const qs = new URLSearchParams({ target: targetId })
    if (grantId) qs.set('grant', grantId)
    // QUALITY item #3 — resolution match. Ask the server for a desktop sized to
    // the stage area in *device* pixels (×DPR) so the canvas renders 1:1 instead
    // of being CSS-upscaled (the main source of blurry text). The Go bridge
    // forwards w/h to session_live, which clamps them server-side; an absent /
    // zero value falls back to the legacy default. Measured here (not in a
    // resize listener) because the negotiated RDP desktop size is fixed for the
    // life of the session — dynamic mid-session resize isn't wired (see below).
    // SESSION SETTINGS: when the operator picked an explicit resolution/scale
    // (`desiredSize`, already in device px), request exactly that (clamped to
    // the same even/cap rules). Otherwise "Match window" auto-measures the
    // stage (today's behaviour). A change to either re-runs this effect.
    const desired = desiredSize ? clampDesktopSize(desiredSize) : desiredDesktopSize(canvasRef.current)
    if (desired) {
      qs.set('w', String(desired.w))
      qs.set('h', String(desired.h))
    }
    const url = `${proto}//${window.location.host}/ws/rdp-live?${qs.toString()}`
    // Open the carrier: WebTransport when enabled+advertised, else WebSocket
    // (ADR 0055). `openRDPSocket` is async (the WebTransport handshake awaits a
    // server ticket + QUIC ready), so wire the handlers after it resolves; a
    // `cancelled` latch handles unmount racing the open.
    let cancelled = false
    void openRDPSocket({ wsUrl: url, query: qs }).then((sock) => {
      if (cancelled) {
        sock.close(1000, 'unmount')
        return
      }
      wsRef.current = sock
      sock.onopen = () => setStatus({ kind: 'opening' })
      sock.onmessage = (ev) => {
        if (typeof ev.data === 'string') return // live path is binary-only
        void handleServerTLV(ev.data as ArrayBuffer)
      }
      // onerror fires on an abnormal close BEFORE onclose. Only fall back to the
      // generic message — never clobber a specific reason. The 0xFF latch wins
      // outright (it carries the broker's real "why"); otherwise we don't
      // overwrite an error state already set from a close-frame reason.
      sock.onerror = () =>
        setStatus((prev) => {
          if (serverErrorRef.current) return { kind: 'error', msg: serverErrorRef.current }
          if (prev.kind === 'error') return prev
          return { kind: 'error', msg: 'transport error' }
        })
      // The broker fails closed by sending an ERROR(0xFF) TLV (latched above) and
      // a close with a reason. The gateway STRIPS the WS close-frame reason, so
      // it's usually empty in prod — the 0xFF latch is the reliable carrier of
      // the authoritative diagnostic. Precedence: latched 0xFF reason >
      // close-frame reason (dev / same-origin / WebTransport) > an error already
      // set > a plain close (code 1000).
      sock.onclose = (ev) =>
        setStatus((prev) => {
          if (serverErrorRef.current) return { kind: 'error', msg: serverErrorRef.current }
          if (ev.reason) return { kind: 'error', msg: ev.reason }
          if (prev.kind === 'error') return prev
          return { kind: 'closed', reason: `code ${ev.code}` }
        })
    })

    return () => {
      cancelled = true
      wsRef.current?.close(1000, 'unmount')
      wsRef.current = null
      // Release the WebCodecs decoder (GPU/CPU buffers) on teardown.
      h264Ref.current?.close()
      h264Ref.current = null
      avc444Ref.current?.close()
      avc444Ref.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetId, grantId, desiredSize?.w, desiredSize?.h])

  // Blit every queued region in arrival order in ONE rAF tick, then clear the
  // queue. Batching here caps the layout-flushing drawImage cycles at the
  // display refresh rate even when many regions decode between frames, and
  // keeps blits off the WS onmessage callback so decode/network never block a
  // paint. Each bitmap is closed after it's drawn to release its memory.
  const flushFrames = useCallback(() => {
    rafRef.current = null
    const ctx = ctxRef.current
    const queue = pendingRef.current
    pendingRef.current = []
    if (!ctx) {
      // No context yet (pre-DESKTOP_SIZE) — drop the bitmaps we can't draw.
      for (const f of queue) f.bmp.close?.()
      return
    }
    // A few engines reset smoothing on some context ops; re-assert once per
    // batch so drawImage blits stay pixel-exact (crisp text).
    ctx.imageSmoothingEnabled = false
    for (const f of queue) {
      ctx.drawImage(f.bmp, f.x, f.y)
      f.bmp.close?.()
    }
  }, [])

  // Queue a decoded dirty-region bitmap and schedule a rAF flush. The queue is
  // bounded: on a runaway backlog (a slow/background tab) the OLDEST pending
  // regions are closed + dropped so memory stays bounded — a subsequent full
  // region repaints that area, so the worst case is a brief stale patch, never
  // a leak or an unbounded paint storm.
  const enqueueFrame = useCallback((bmp: ImageBitmap, x: number, y: number) => {
    const q = pendingRef.current
    q.push({ bmp, x, y })
    if (q.length > MAX_PENDING_FRAMES) {
      const drop = q.splice(0, q.length - MAX_PENDING_FRAMES)
      for (const f of drop) f.bmp.close?.()
    }
    if (rafRef.current === null) {
      rafRef.current = requestAnimationFrame(flushFrames)
    }
  }, [flushFrames])

  // Cancel any pending rAF + drop queued bitmaps on unmount so a torn-down
  // session can't blit into a stale context or leak decoded frames.
  useEffect(() => {
    return () => {
      if (rafRef.current !== null) {
        cancelAnimationFrame(rafRef.current)
        rafRef.current = null
      }
      for (const f of pendingRef.current) f.bmp.close?.()
      pendingRef.current = []
    }
  }, [])

  // Apply DESKTOP_SIZE / draw a FRAME / handle CLOSE+ERROR.
  const handleServerTLV = useCallback(async (buf: ArrayBuffer) => {
    const msg = decodeServerTLV(buf)
    switch (msg.kind) {
      case 'desktop_size': {
        deskRef.current = { w: msg.width, h: msg.height }
        const c = canvasRef.current
        if (c) {
          // Backing store = exact desktop pixels (1:1 blits); CSS scales to fit.
          // Assigning width/height RESETS all context state, so the context must
          // be re-fetched and image smoothing re-disabled AFTER the resize.
          c.width = msg.width
          c.height = msg.height
          const ctx = c.getContext('2d')
          ctxRef.current = ctx
          if (ctx) {
            // QUALITY item #1 — kill the 2D context's bilinear smoothing so
            // drawImage blits are pixel-exact (crisp text). Paired with the
            // canvas's `image-rendering: pixelated` CSS for any residual CSS
            // scale. Re-asserted here because the resize above cleared it.
            disableSmoothing(ctx)
            ctx.fillStyle = '#000'
            ctx.fillRect(0, 0, msg.width, msg.height)
          }
        }
        setStatus({ kind: 'live', w: msg.width, h: msg.height, frames: framesRef.current })
        return
      }
      case 'frame': {
        const ctx = ctxRef.current
        if (!ctx || msg.bytes.length === 0) return
        let bmp: ImageBitmap
        try {
          // createImageBitmap decodes OFF the main thread (PNG or WebP per
          // msg.mime). Copy into a standalone buffer so the Blob owns its bytes.
          const blob = new Blob([msg.bytes.slice()], { type: msg.mime })
          bmp = await createImageBitmap(blob)
        } catch {
          // A single decode failure shouldn't kill the session; skip the region.
          return
        }
        // Queue the decoded region; the rAF tick does the actual blit so the
        // main thread paints at most once per display frame (pacing/coalescing).
        enqueueFrame(bmp, msg.x, msg.y)
        framesRef.current += 1
        setStatus((prev) =>
          prev.kind === 'live'
            ? { ...prev, frames: framesRef.current }
            : { kind: 'live', w: deskRef.current.w, h: deskRef.current.h, frames: framesRef.current },
        )
        return
      }
      case 'h264': {
        // Tier-2 "native-feel" path (ADR 0053). ADDITIVE + flag-gated: only ever
        // reached when the broker emits MSG_H264 AND the WebCodecs+flag gate is
        // open. The PNG 'frame' path above is untouched and remains the default.
        const ctx = ctxRef.current
        if (!ctx || msg.nal.length === 0) return
        if (!h264PathActive()) {
          // Gate closed (no WebCodecs, or flag off): ignore H.264 AUs. A
          // correctly-negotiated broker wouldn't send these, but stay safe.
          return
        }
        // Shared paint: H.264 access units are coded at a 16-aligned size that can
        // be LARGER than the dirty region; crop to the region's w×h from the source
        // top-left (9-arg drawImage) so alignment padding never bleeds onto
        // neighbours. `img` is a VideoFrame OR the AVC444 recombine canvas — both
        // are CanvasImageSource. The CALLER owns `img`'s lifecycle (closes any
        // VideoFrame after this returns), so paint must draw synchronously.
        const paint = (img: CanvasImageSource, region: { x: number; y: number; w: number; h: number }) => {
          const c = ctxRef.current
          if (!c) return
          try {
            c.imageSmoothingEnabled = false
            if (region.w > 0 && region.h > 0) {
              c.drawImage(img, 0, 0, region.w, region.h, region.x, region.y, region.w, region.h)
            } else {
              c.drawImage(img, region.x, region.y)
            }
          } catch {
            // a single paint failure shouldn't kill the session
          }
          framesRef.current += 1
          setStatus((prev) =>
            prev.kind === 'live'
              ? { ...prev, frames: framesRef.current }
              : { kind: 'live', w: deskRef.current.w, h: deskRef.current.h, frames: framesRef.current },
          )
        }

        // AVC444 4:4:4 path (ADR 0059): a 4:4:4 update is a MAIN view (msg.avc444)
        // followed by an AUXILIARY view (msg.aux). With WebGL2 present, route both
        // to the recombine decoder (true 4:4:4, else 4:2:0 main-view fallback).
        // Without WebGL2/WebCodecs-plane-readback we can't recombine: display the
        // main view through the plain AVC420 decoder and ignore the aux frames.
        if (msg.avc444 || msg.aux) {
          if (hasAvc444Support()) {
            if (!avc444Ref.current) {
              avc444Ref.current = new RDPAvc444Decoder({
                onFrame: (img, region) => paint(img, region),
                onError: (m) => {
                  avc444Ref.current?.close()
                  avc444Ref.current = null
                  console.warn('RDP AVC444 decoder error, falling back:', m)
                },
              })
            }
            if (msg.aux) avc444Ref.current.submitAux(msg.nal, msg.keyframe)
            else avc444Ref.current.submitMain(msg.nal, msg.keyframe, { x: msg.x, y: msg.y, w: msg.w, h: msg.h })
            return
          }
          // No recombine capability: drop the aux view; the main view falls
          // through to the plain AVC420 decoder below (it IS a valid AVC420 stream).
          if (msg.aux) return
        }

        // Plain AVC420 single-stream path (also the AVC444 main view when we can't
        // recombine). The decoder owns the VideoFrame; close it after painting.
        if (!h264Ref.current) {
          h264Ref.current = new RDPH264Decoder({
            onFrame: (frame, region) => {
              try {
                paint(frame as unknown as CanvasImageSource, region)
              } finally {
                frame.close() // MUST release the scarce decoder buffer
              }
            },
            onError: (m) => {
              // Decoder gave up. The broker SHOULD then fall back to PNG frames;
              // surface the reason but don't kill a still-usable session.
              h264Ref.current?.close()
              h264Ref.current = null
              console.warn('RDP H.264 decoder error, falling back to bitmap path:', m)
            },
          })
        }
        h264Ref.current.submit(msg.nal, msg.keyframe, {
          x: msg.x,
          y: msg.y,
          w: msg.w,
          h: msg.h,
        })
        return
      }
      case 'clipboard_available': {
        // The remote copied TEXT. Pull it across so a local paste (Ctrl+V in
        // the browser/host OS) gets the remote content — but only while we're
        // focused (the Clipboard API write below requires focus anyway, and we
        // shouldn't fetch a remote secret into the local clipboard when the tab
        // is backgrounded). If unfocused now, the focus effect re-requests on
        // refocus via the same path.
        if (clipboard && document.hasFocus()) {
          const ws = wsRef.current
          if (ws && ws.readyState === WebSocket.OPEN) ws.send(encodeClipboardRequestTLV())
        }
        return
      }
      case 'clipboard_text': {
        // The remote's clipboard TEXT — write it into the local clipboard so a
        // paste outside the canvas works. Gated on focus + API availability;
        // record it so the local→remote poll doesn't immediately echo it back.
        if (clipboard && msg.text !== lastClipTextRef.current) {
          lastClipTextRef.current = msg.text
          if (document.hasFocus() && navigator.clipboard?.writeText) {
            navigator.clipboard.writeText(msg.text).catch(() => {
              // Permission denied / not focused — non-fatal; the remote text is
              // still applied on the remote side. Clear the latch so a later
              // refocus poll can retry.
              lastClipTextRef.current = ''
            })
          }
        }
        return
      }
      case 'clipboard_image_available': {
        // The remote copied an IMAGE. Pull it across (gated on focus + the
        // ClipboardItem write API) so a local paste gets it. Like text, we fetch
        // it now so it's ready in the local clipboard; the focus poll re-requests
        // on refocus if we were unfocused.
        if (
          clipboard &&
          document.hasFocus() &&
          typeof ClipboardItem !== 'undefined' &&
          typeof navigator.clipboard?.write === 'function'
        ) {
          const ws = wsRef.current
          if (ws && ws.readyState === WebSocket.OPEN) ws.send(encodeClipboardRequestImageTLV())
        }
        return
      }
      case 'clipboard_image': {
        // The remote's clipboard IMAGE as PNG — write it into the local
        // clipboard via the async ClipboardItem API. Record its length so the
        // local→remote poll doesn't echo it straight back.
        if (
          clipboard &&
          typeof ClipboardItem !== 'undefined' &&
          typeof navigator.clipboard?.write === 'function'
        ) {
          lastClipImageLenRef.current = msg.png.length
          const blob = new Blob([msg.png.slice()], { type: 'image/png' })
          navigator.clipboard
            .write([new ClipboardItem({ 'image/png': blob })])
            .catch(() => {
              // Permission denied / not focused — non-fatal; clear the latch so a
              // later refocus can retry.
              lastClipImageLenRef.current = 0
            })
        }
        return
      }
      case 'close':
        setStatus({ kind: 'closed', reason: 'session ended' })
        return
      case 'error':
        // Latch the broker's authoritative reason synchronously so the later
        // onerror/onclose (which only carry the gateway-stripped generic text)
        // can't overwrite it.
        serverErrorRef.current = msg.msg
        setStatus({ kind: 'error', msg: msg.msg })
        return
      case 'unknown':
        return
    }
  }, [enqueueFrame, clipboard])

  // --- input → TLV ---------------------------------------------------------

  // Scale a pointer event's client coords into desktop pixel coords.
  const toDesktopCoords = useCallback((e: { clientX: number; clientY: number }) => {
    const c = canvasRef.current
    if (!c) return { x: 0, y: 0 }
    const rect = c.getBoundingClientRect()
    const { w, h } = deskRef.current
    const x = ((e.clientX - rect.left) / rect.width) * w
    const y = ((e.clientY - rect.top) / rect.height) * h
    return { x, y }
  }, [])

  const sendMouse = useCallback((x: number, y: number, wheel: number) => {
    const ws = wsRef.current
    if (!ws || ws.readyState !== WebSocket.OPEN) return
    ws.send(encodeMouseTLV(x, y, buttonMaskRef.current, wheel))
  }, [])

  const onPointerMove = useCallback(
    (e: React.PointerEvent<HTMLCanvasElement>) => {
      const { x, y } = toDesktopCoords(e)
      sendMouse(x, y, 0)
    },
    [sendMouse, toDesktopCoords],
  )

  const buttonBit = (button: number): number =>
    button === 0 ? BUTTON_LEFT : button === 2 ? BUTTON_RIGHT : button === 1 ? BUTTON_MIDDLE : 0

  const onPointerDown = useCallback(
    (e: React.PointerEvent<HTMLCanvasElement>) => {
      e.currentTarget.focus()
      e.preventDefault()
      buttonMaskRef.current |= buttonBit(e.button)
      const { x, y } = toDesktopCoords(e)
      sendMouse(x, y, 0)
    },
    [sendMouse, toDesktopCoords],
  )

  const onPointerUp = useCallback(
    (e: React.PointerEvent<HTMLCanvasElement>) => {
      e.preventDefault()
      buttonMaskRef.current &= ~buttonBit(e.button)
      const { x, y } = toDesktopCoords(e)
      sendMouse(x, y, 0)
    },
    [sendMouse, toDesktopCoords],
  )

  const onWheel = useCallback(
    (e: React.WheelEvent<HTMLCanvasElement>) => {
      // Normalise to a small signed step; positive deltaY = scroll down → wheel
      // toward the user (negative in the RDP convention positive=up/away).
      const { x, y } = toDesktopCoords(e)
      const wheel = e.deltaY > 0 ? -1 : 1
      sendMouse(x, y, wheel)
    },
    [sendMouse, toDesktopCoords],
  )

  const sendKey = useCallback((isDown: boolean, code: string): boolean => {
    const scancode = scancodeFor(code)
    if (scancode === undefined) return false
    const ws = wsRef.current
    if (!ws || ws.readyState !== WebSocket.OPEN) return false
    ws.send(encodeKeyTLV(isDown, scancode))
    return true
  }, [])

  // Capture keyboard at the DOCUMENT level for the whole console session. A bare
  // focusable <canvas> loses focus too easily (toolbar/gear clicks, re-renders),
  // so relying on canvas focus dropped EVERY keystroke — zero key events reached
  // the broker. Skip when a form field is focused (e.g. the resolution settings
  // dialog) so those inputs still type. sendKey only emits when the WS is open.
  useEffect(() => {
    const inField = (t: EventTarget | null): boolean => {
      const el = t as HTMLElement | null
      if (!el || !el.tagName) return false
      const tag = el.tagName
      return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || el.isContentEditable === true
    }
    const onDown = (e: KeyboardEvent) => {
      if (inField(e.target)) return
      // stop the browser stealing Tab / F-keys etc. — but only if we sent it.
      if (sendKey(true, e.code)) e.preventDefault()
    }
    const onUp = (e: KeyboardEvent) => {
      if (inField(e.target)) return
      if (sendKey(false, e.code)) e.preventDefault()
    }
    document.addEventListener('keydown', onDown)
    document.addEventListener('keyup', onUp)
    return () => {
      document.removeEventListener('keydown', onDown)
      document.removeEventListener('keyup', onUp)
    }
  }, [sendKey])

  // CLIPBOARD sync — browser → remote (ADR 0054). The async Clipboard API
  // requires the document to be FOCUSED and (for read) a user gesture / granted
  // permission. So we poll the local clipboard on focus + on pointer-down in
  // the canvas (a genuine user gesture inside the session), pushing the text to
  // the remote only when it actually changed (the lastClipText latch also
  // breaks the remote→browser→remote echo loop). Best-effort: a permission
  // denial / non-text clipboard is silently ignored — the session is
  // unaffected. No-op entirely when `clipboard` is false or the API is absent.
  useEffect(() => {
    if (!clipboard || !navigator.clipboard?.readText) return
    const pushLocalClipboard = () => {
      if (!document.hasFocus()) return
      const ws = wsRef.current
      if (!ws || ws.readyState !== WebSocket.OPEN) return
      navigator.clipboard
        .readText()
        .then((text) => {
          // Skip empty + unchanged (incl. text we just received from the
          // remote, which is already in lastClipTextRef) to avoid an echo loop.
          if (!text || text === lastClipTextRef.current) return
          lastClipTextRef.current = text
          ws.send(encodeClipboardTextTLV(text))
        })
        .catch(() => {
          // Not focused / permission denied / no text — ignore.
        })
    }
    // Browser → remote IMAGE. navigator.clipboard.read() is heavier + more
    // permission-prompty than readText, and reads the WHOLE clipboard, so we run
    // it ONLY on focus (not on every pointer-down) — pushing a browser-copied
    // image to the remote when the operator switches into the session.
    const pushLocalImage = () => {
      if (!document.hasFocus()) return
      if (typeof ClipboardItem === 'undefined' || typeof navigator.clipboard?.read !== 'function') return
      const ws = wsRef.current
      if (!ws || ws.readyState !== WebSocket.OPEN) return
      void navigator.clipboard
        .read()
        .then(async (items) => {
          for (const item of items) {
            if (!item.types.includes('image/png')) continue
            const blob = await item.getType('image/png')
            const png = new Uint8Array(await blob.arrayBuffer())
            // Skip empty + unchanged (incl. an image we just wrote from the
            // remote) to avoid an echo loop.
            if (png.length === 0 || png.length === lastClipImageLenRef.current) return
            lastClipImageLenRef.current = png.length
            const sock = wsRef.current
            if (sock && sock.readyState === WebSocket.OPEN) sock.send(encodeClipboardImageTLV(png))
            return
          }
        })
        .catch(() => {
          // Permission denied / no image / not focused — ignore (best-effort).
        })
    }

    window.addEventListener('focus', pushLocalClipboard)
    window.addEventListener('focus', pushLocalImage)
    // A pointer-down in the canvas is a user gesture that also satisfies the
    // Clipboard API's read requirements on stricter browsers.
    const canvas = canvasRef.current
    canvas?.addEventListener('pointerdown', pushLocalClipboard)
    // Prime once on mount in case we're already focused.
    pushLocalClipboard()
    pushLocalImage()
    return () => {
      window.removeEventListener('focus', pushLocalClipboard)
      window.removeEventListener('focus', pushLocalImage)
      canvas?.removeEventListener('pointerdown', pushLocalClipboard)
    }
  }, [clipboard])

  // Ctrl-Alt-Del secure attention sequence: press Ctrl, Alt, Del in order then
  // release in reverse. Reuses the SAME KEY TLV path as live keystrokes — no
  // new transport. (Browsers can't synthesise the real C-A-D, so the toolbar
  // button is the only reliable way to send it to the remote desktop.)
  const sendCtrlAltDel = useCallback(() => {
    const seq = ['ControlLeft', 'AltLeft', 'Delete']
    for (const code of seq) sendKey(true, code)
    for (const code of [...seq].reverse()) sendKey(false, code)
  }, [sendKey])

  useImperativeHandle(ref, () => ({
    sendCtrlAltDel,
    focus: () => canvasRef.current?.focus(),
  }), [sendCtrlAltDel])

  // Block the native context menu so right-click reaches the remote desktop.
  const onContextMenu = useCallback((e: React.MouseEvent) => e.preventDefault(), [])

  return (
    <canvas
      ref={canvasRef}
      width={width}
      height={height}
      tabIndex={0}
      onPointerMove={onPointerMove}
      onPointerDown={onPointerDown}
      onPointerUp={onPointerUp}
      onWheel={onWheel}
      onContextMenu={onContextMenu}
      className="c2-rdp-canvas"
      aria-label={`Live RDP session to ${targetId}`}
    />
  )
})

// Upper bound on decoded dirty-region bitmaps queued between two rAF ticks.
// A steady stream is flushed each frame so the queue stays tiny; this only
// bites on a stalled/background tab, where dropping the oldest pending regions
// keeps memory bounded (a later full region repaints the dropped area). 240 ≈
// a few seconds of dense region updates at 60fps — generous headroom before any
// drop kicks in.
const MAX_PENDING_FRAMES = 240

// Disable bilinear/anti-aliased scaling on a 2D context, covering the older
// vendor-prefixed property names some engines still read. Without this,
// `drawImage` smooths each FRAME blit and text reads blurry.
function disableSmoothing(ctx: CanvasRenderingContext2D): void {
  ctx.imageSmoothingEnabled = false
  // Vendor-prefixed fallbacks for engines that predate the unprefixed name.
  const anyCtx = ctx as unknown as Record<string, boolean>
  if ('mozImageSmoothingEnabled' in anyCtx) anyCtx.mozImageSmoothingEnabled = false
  if ('webkitImageSmoothingEnabled' in anyCtx) anyCtx.webkitImageSmoothingEnabled = false
  if ('msImageSmoothingEnabled' in anyCtx) anyCtx.msImageSmoothingEnabled = false
}

// Compute the desktop resolution to REQUEST from the server (quality item #3).
// We size to the canvas's stage container in DEVICE pixels (CSS px × DPR) so a
// HiDPI display gets a correspondingly higher-res desktop and the canvas paints
// 1:1 — no CSS upscaling, the chief cause of blurry text. Returns null when the
// area can't be measured yet (the server then uses its default size).
function desiredDesktopSize(canvas: HTMLCanvasElement | null): { w: number; h: number } | null {
  // Prefer the stage (the canvas's parent) so we match the actual draw area;
  // fall back to the viewport if the parent hasn't laid out yet.
  const host = canvas?.parentElement
  const rect = host?.getBoundingClientRect()
  let cssW = rect && rect.width > 0 ? rect.width : window.innerWidth
  let cssH = rect && rect.height > 0 ? rect.height : window.innerHeight
  if (!(cssW > 0) || !(cssH > 0)) return null
  const dpr = window.devicePixelRatio || 1
  return clampDesktopSize({ w: cssW * dpr, h: cssH * dpr })
}

// Round to even and clamp to the on-wire u16 range. RDP desktop dimensions are
// u16; the server clamps too, but we round to even + cap here so we never emit
// a silly value. Even dimensions avoid half-pixel chroma artefacts on some
// servers. Shared by the auto-measure path and the explicit session-settings
// size (which already has the DPI multiplier baked in).
function clampDesktopSize(size: { w: number; h: number }): { w: number; h: number } {
  const round2 = (n: number) => Math.max(2, Math.round(n / 2) * 2)
  return { w: Math.min(round2(size.w), 8192), h: Math.min(round2(size.h), 8192) }
}

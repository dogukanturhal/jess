// ConsoleFrame — the vSphere-grade remote-console chrome shared by the live
// SSH / RDP / SQL viewports. It is pure layout: a top toolbar, a full-bleed
// "stage" that hosts the live viewport (xterm host / RDP canvas / result grid)
// plus any connecting/closed/error overlay, and a thin bottom status bar.
//
// It owns NOTHING about transports — the page passes its own WS/xterm/canvas
// children and telemetry. The only behavior it adds is browser fullscreen
// (requestFullscreen on the frame element), which is purely presentational and
// safe for every console.
import { useCallback, useEffect, useRef, useState, type CSSProperties, type ReactNode, type PointerEvent as ReactPointerEvent } from 'react'
import { Loading } from '@carbon/react'
import { Maximize, Minimize, Subtract, Move } from '@carbon/icons-react'
import { StatusBadge, type Tone } from './StatusBadge'
import { Button } from './Button'

type WinMode = 'docked' | 'floating' | 'minimized'

export interface ConsoleFrameProps {
  /** uppercase protocol chip (SSH / RDP / POSTGRES …) */
  protocol: string
  /** the target id / address (mono) */
  target: ReactNode
  /** connection status chip shown next to the target */
  status?: { tone: Tone; label: ReactNode; title?: string }
  /** telemetry cells rendered in the toolbar (duration, latency, link-quality…) */
  telemetry?: ReactNode
  /** extra toolbar actions to the LEFT of the built-in fullscreen/disconnect */
  toolbarActions?: ReactNode
  /** disconnect / close handler. When `disconnectHref` is set this is an <a>. */
  onDisconnect?: () => void
  disconnectHref?: string
  disconnectLabel?: string
  /** When hosted in the cross-nav ConsoleDock, the Minimize button hands the
   *  session to the dock (hide + taskbar pill, stays connected) instead of the
   *  in-place pill. Unset → the standalone in-place minimize is used. */
  onMinimize?: () => void
  /** the live viewport (xterm host, canvas, grid). Filled into the stage. */
  children: ReactNode
  /** centre the stage content (RDP canvas) instead of stretching it (xterm). */
  centerStage?: boolean
  /** absolutely-positioned overlay over the stage (connecting/closed/error). */
  overlay?: ReactNode
  /** status-bar cells. */
  statusbar?: ReactNode
}

export function ConsoleFrame({
  protocol,
  target,
  status,
  telemetry,
  toolbarActions,
  onDisconnect,
  disconnectHref,
  disconnectLabel = 'Disconnect',
  onMinimize,
  children,
  centerStage = false,
  overlay,
  statusbar,
}: ConsoleFrameProps) {
  const frameRef = useRef<HTMLDivElement | null>(null)
  const [isFs, setIsFs] = useState(false)
  // Window mode (presentational only — the stage/children stay MOUNTED in every
  // mode, so a minimized console keeps its live session connected; CSS hides the
  // stage rather than React unmounting it). 'docked' = full-bleed (unchanged
  // default); 'floating' = draggable + resizable window; 'minimized' = pill.
  const [mode, setMode] = useState<WinMode>('docked')
  const restoreTo = useRef<Exclude<WinMode, 'minimized'>>('docked')
  const [pos, setPos] = useState({ x: 96, y: 88 })
  const [size, setSize] = useState({ w: 1024, h: 640 })

  useEffect(() => {
    const onChange = () => setIsFs(document.fullscreenElement != null)
    document.addEventListener('fullscreenchange', onChange)
    return () => document.removeEventListener('fullscreenchange', onChange)
  }, [])

  const toggleFullscreen = useCallback(() => {
    const el = frameRef.current
    if (!el) return
    if (document.fullscreenElement) {
      void document.exitFullscreen?.()
    } else {
      void el.requestFullscreen?.()
    }
  }, [])

  const minimize = useCallback(() => {
    setMode((m) => {
      if (m !== 'minimized') restoreTo.current = m
      return 'minimized'
    })
  }, [])
  const restore = useCallback(() => setMode(restoreTo.current), [])
  const toggleFloat = useCallback(() => setMode((m) => (m === 'floating' ? 'docked' : 'floating')), [])

  // Drag the floating window by its toolbar; resize by the bottom-right handle.
  // Pointer capture keeps the gesture even if the cursor outruns the element.
  const startDrag = useCallback((e: ReactPointerEvent) => {
    if (mode !== 'floating') return
    if ((e.target as HTMLElement).closest('button, a, input, [role="button"]')) return // don't drag from a control
    const sx = e.clientX, sy = e.clientY
    const ox = pos.x, oy = pos.y
    ;(e.currentTarget as HTMLElement).setPointerCapture?.(e.pointerId)
    const onMove = (ev: PointerEvent) => setPos({ x: Math.max(0, ox + ev.clientX - sx), y: Math.max(0, oy + ev.clientY - sy) })
    const onUp = () => { window.removeEventListener('pointermove', onMove); window.removeEventListener('pointerup', onUp) }
    window.addEventListener('pointermove', onMove)
    window.addEventListener('pointerup', onUp)
  }, [mode, pos])

  const startResize = useCallback((e: ReactPointerEvent) => {
    e.stopPropagation()
    const sx = e.clientX, sy = e.clientY
    const ow = size.w, oh = size.h
    const onMove = (ev: PointerEvent) => setSize({ w: Math.max(360, ow + ev.clientX - sx), h: Math.max(220, oh + ev.clientY - sy) })
    const onUp = () => { window.removeEventListener('pointermove', onMove); window.removeEventListener('pointerup', onUp) }
    window.addEventListener('pointermove', onMove)
    window.addEventListener('pointerup', onUp)
  }, [size])

  const floatStyle: CSSProperties | undefined =
    mode === 'floating' ? { left: pos.x, top: pos.y, width: size.w, height: size.h } : undefined

  const disconnectBtn = disconnectHref
    ? <Button variant="danger" size="sm" href={disconnectHref}>{disconnectLabel}</Button>
    : <Button variant="danger" size="sm" onClick={onDisconnect}>{disconnectLabel}</Button>

  const idBlock = (
    <div className="c2-console-id">
      <span className="c2-console-proto">{protocol}</span>
      <span className="c2-console-target" title={typeof target === 'string' ? target : undefined}>{target}</span>
      {status && <StatusBadge tone={status.tone} title={status.title}>{status.label}</StatusBadge>}
    </div>
  )

  return (
    <div ref={frameRef} className="c2-console" data-mode={mode} style={floatStyle}>
      {mode === 'minimized' ? (
        // Compact pill — the stage below stays mounted (CSS-hidden), so the live
        // session keeps running while minimized.
        <div className="c2-console-toolbar c2-console-pill">
          {idBlock}
          <span className="c2-toolbar-spacer" />
          <Button variant="ghost" size="sm" icon onClick={restore} title="Restore" aria-label="Restore console">
            <Maximize size={16} />
          </Button>
          {disconnectBtn}
        </div>
      ) : (
        <div className="c2-console-toolbar" onPointerDown={mode === 'floating' ? startDrag : undefined}>
          {idBlock}
          {telemetry && (<><span className="c2-console-sep" />{telemetry}</>)}
          <span className="c2-toolbar-spacer" />
          {toolbarActions}
          <Button
            variant="ghost"
            size="sm"
            icon
            onClick={onMinimize ?? minimize}
            title={onMinimize ? 'Minimize to background (keeps the session connected — browse other pages)' : 'Minimize (keeps the session connected)'}
            aria-label="Minimize"
          >
            <Subtract size={16} />
          </Button>
          {/* Windowed/float toggle only makes sense for a standalone console.
              When dock-hosted (onMinimize set) the dock owns foreground/
              background, and floating would just hover over the dock's opaque
              backdrop — so hide it there and let Minimize be the background verb. */}
          {!onMinimize && (
            <Button variant="ghost" size="sm" icon onClick={toggleFloat} title={mode === 'floating' ? 'Dock (full window)' : 'Windowed (float)'} aria-label="Toggle windowed mode">
              <Move size={16} />
            </Button>
          )}
          <Button variant="ghost" size="sm" icon onClick={toggleFullscreen} title={isFs ? 'Exit fullscreen (Esc)' : 'Fullscreen'} aria-label={isFs ? 'Exit fullscreen' : 'Enter fullscreen'}>
            {isFs ? <Minimize size={16} /> : <Maximize size={16} />}
          </Button>
          {disconnectBtn}
        </div>
      )}

      <div className={`c2-console-stage${centerStage ? ' is-canvas' : ''}`}>
        {children}
        {overlay}
      </div>

      {statusbar && <div className="c2-console-statusbar">{statusbar}</div>}
      {mode === 'floating' && <div className="c2-console-resize" onPointerDown={startResize} aria-hidden="true" />}
    </div>
  )
}

// ConsoleOverlay — the connecting/closed/error scrim over the stage. tone picks
// the icon colour; `spinner` swaps the icon for a connecting spinner.
export function ConsoleOverlay({
  tone = 'mute',
  spinner = false,
  icon,
  title,
  children,
  actions,
}: {
  tone?: 'mute' | 'warn' | 'danger'
  spinner?: boolean
  icon?: ReactNode
  title: ReactNode
  children?: ReactNode
  actions?: ReactNode
}) {
  return (
    <div className="c2-console-overlay" role="status">
      {spinner ? (
        <Loading description="Connecting…" withOverlay={false} small />
      ) : (
        <span className={`c2-console-overlay-icon is-${tone}`} aria-hidden="true">{icon}</span>
      )}
      <h2 className="c2-console-overlay-title">{title}</h2>
      {children}
      {actions && <div className="c2-console-overlay-actions">{actions}</div>}
    </div>
  )
}

// ConsoleTelem — a single labelled telemetry cell for the toolbar.
export function ConsoleTelem({ label, children, title }: { label?: ReactNode; children: ReactNode; title?: string }) {
  return (
    <span className="c2-console-telem" title={title}>
      {label != null && <span>{label}</span>}
      <b>{children}</b>
    </span>
  )
}

// ConsoleStat — a single labelled status-bar cell.
export function ConsoleStat({ label, children, title }: { label?: ReactNode; children: ReactNode; title?: string }) {
  return (
    <span className="c2-console-stat" title={title}>
      {label != null && <span className="c2-eyebrow">{label}</span>}
      <b>{children}</b>
    </span>
  )
}

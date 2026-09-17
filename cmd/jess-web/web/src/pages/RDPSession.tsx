// RDPSession — the LIVE RDP console body, extracted from the /rdp route so it
// can be hosted by the cross-nav ConsoleDock (app-root) and survive navigation.
// It is exactly the ConsoleFrame + RDPCanvas + session state that used to live
// inside pages/RDP.tsx, MINUS the AppShell wrapper and the auth gate (the dock
// only ever opens a session once the launcher has confirmed sign-in). Disconnect
// and Minimize are wired to dock callbacks instead of an href: Disconnect
// unmounts this node (the canvas unmount effect closes the WS), Minimize hands
// off to the dock taskbar while staying connected.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Settings } from '@carbon/icons-react'
import { fetchRDPRecorded } from '../api/rdp'
import { adminSetRecording } from '../api/admin'
import { isAdmin } from '../api/me'
import { useMe } from '../hooks/useMe'
import { RDPCanvas, type RDPCanvasHandle, type RDPStatus } from '../components/RDPCanvas'
import { RecordingDot } from '../components/RecordingDot'
import {
  RDPSettingsDialog,
  computeDesiredSize,
  loadRDPSettings,
  rdpSettingsLabel,
  saveRDPSettings,
  type RDPSettings,
} from '../components/RDPSettings'
import {
  Button,
  ConsoleFrame,
  ConsoleOverlay,
  ConsoleStat,
  ConsoleTelem,
  type Tone,
} from '../components/c2'

export interface RDPSessionProps {
  targetId: string
  grantId?: string
  /** hand the session to the dock taskbar (stays connected). */
  onMinimize: () => void
  /** tear the session down — unmounts the canvas, which closes the WS. */
  onClose: () => void
}

export function RDPSession({ targetId, grantId, onMinimize, onClose }: RDPSessionProps) {
  const [status, setStatus] = useState<RDPStatus>({ kind: 'opening' })
  const canvasRef = useRef<RDPCanvasHandle | null>(null)
  // EFFECTIVE recording decision for this target (admin catalog toggle, override
  // beats default). null = not yet known; false = recording disabled for this
  // target → the indicator must say so instead of claiming "Recording".
  const [recorded, setRecorded] = useState<boolean | null>(null)
  // The TARGET's recording setting for the admin toggle (separate from `recorded`,
  // which drives the live dot and must stay accurate to THIS session — recording
  // is fixed at session start, so flipping the target setting only affects the
  // NEXT session). null = unknown.
  const meState = useMe()
  const admin = isAdmin(meState.kind === 'signed_in' ? meState.me : null)
  const [targetRec, setTargetRec] = useState<boolean | null>(null)
  const [recSaving, setRecSaving] = useState(false)
  const toggleRecording = useCallback(() => {
    if (!targetId || targetRec == null || recSaving) return
    setRecSaving(true)
    adminSetRecording(targetId, !targetRec)
      .then((s) => setTargetRec(s.recorded))
      .catch(() => { /* leave as-is; the next fetch reconciles */ })
      .finally(() => setRecSaving(false))
  }, [targetId, targetRec, recSaving])

  // VMware-style session settings (resolution / DPI / colour). Loaded from
  // localStorage; "Apply" persists + reconnects the live session.
  const [settings, setSettings] = useState<RDPSettings>(() => loadRDPSettings())
  const [settingsOpen, setSettingsOpen] = useState(false)
  // Bumped on every Apply to force-remount RDPCanvas (re-opens the WS with the
  // newly-chosen ?w=&h=). The remount is the reconnect mechanism.
  const [reconnectNonce, setReconnectNonce] = useState(0)
  const desiredSize = useMemo(() => computeDesiredSize(settings), [settings])

  const applySettings = useCallback((next: RDPSettings) => {
    setSettings(next)
    saveRDPSettings(next)
    setSettingsOpen(false)
    setReconnectNonce((n) => n + 1)
  }, [])

  // Resolve whether this target is recorded (honest indicator). On any error,
  // leave `recorded` null so the dot keeps its safe default rather than wrongly
  // claiming a session is NOT recorded.
  useEffect(() => {
    if (!targetId) return
    const ctrl = new AbortController()
    fetchRDPRecorded(targetId, ctrl.signal)
      .then((v) => { setRecorded(v); setTargetRec(v) })
      .catch(() => { /* leave null — keep safe default */ })
    return () => ctrl.abort()
  }, [targetId])

  // Distinguish multiple RDP sessions in the OS task switcher / tab strip.
  useEffect(() => {
    const glyph = status.kind === 'live' ? '●' : status.kind === 'opening' ? '◐' : status.kind === 'closed' ? '○' : '✗'
    document.title = targetId ? `${glyph} ${targetId} · RDP · jess` : 'RDP · jess'
    return () => { document.title = 'jess' }
  }, [targetId, status.kind])

  const onStatus = useCallback((s: RDPStatus) => setStatus(s), [])
  const live = status.kind === 'live'
  const badge = statusBadge(status)

  return (
    <>
      <ConsoleFrame
        protocol="RDP"
        target={targetId}
        status={badge}
        onDisconnect={onClose}
        onMinimize={onMinimize}
        disconnectLabel="Disconnect"
        telemetry={
          <>
            {live && <ConsoleTelem label="desktop" title="Negotiated desktop size">{status.w}×{status.h}</ConsoleTelem>}
            {live && <ConsoleTelem label="frames" title="Decoded frames painted">{status.frames}</ConsoleTelem>}
            <ConsoleTelem label="size" title="Requested resolution / scale (Session settings)">{rdpSettingsLabel(settings)}</ConsoleTelem>
            <RecordingDot status={recorded === false ? 'off' : live ? 'live' : 'stopped'}>
              {recorded === false
                ? 'disabled for this target (catalog recording toggle off)'
                : live
                  ? 'tee to audit-archive (jess-rdp-recording-v2 + Vault Transit signature)'
                  : 'recording sealed in audit-archive'}
            </RecordingDot>
          </>
        }
        toolbarActions={
          <>
            {admin && targetRec != null && (
              <Button
                variant="ghost"
                size="sm"
                disabled={recSaving}
                onClick={toggleRecording}
                title={`Per-target WORM recording (admin). Currently ${targetRec ? 'ON' : 'OFF'} for this target. Applies to the NEXT session — this session's recording is fixed at connect and cannot be changed mid-stream.`}
              >
                Recording: {targetRec ? 'On' : 'Off'}
              </Button>
            )}
            <Button
              variant="ghost"
              size="sm"
              disabled={!live}
              onClick={() => canvasRef.current?.sendCtrlAltDel()}
              title="Send the Ctrl-Alt-Del secure-attention sequence to the remote desktop"
            >
              Ctrl-Alt-Del
            </Button>
            <Button
              variant="ghost"
              size="sm"
              icon
              onClick={() => setSettingsOpen(true)}
              title="Session settings — resolution, scale/DPI, colour"
              aria-label="Session settings"
            >
              <Settings size={16} />
            </Button>
          </>
        }
        centerStage
        overlay={<RDPOverlay status={status} targetId={targetId} onReconnect={() => setReconnectNonce((n) => n + 1)} />}
        statusbar={
          <>
            <ConsoleStat label="Status">{statusLine(status)}</ConsoleStat>
            {grantId && <ConsoleStat label="Grant"><span className="c2-mono">{grantId.slice(0, 8)}</span></ConsoleStat>}
            <span className="c2-toolbar-spacer" />
            <ConsoleStat label="Transport">/ws/rdp-live · TLV</ConsoleStat>
          </>
        }
      >
        {/* Fallback size until DESKTOP_SIZE arrives; the canvas backing store is
            then resized to the negotiated desktop (commonly 1280×1024). The
            `key` (target + reconnect nonce) remounts the canvas on Apply, which
            re-opens the WS with the chosen ?w=&h= — the reconnect mechanism. */}
        <RDPCanvas
          key={`${targetId}#${reconnectNonce}`}
          ref={canvasRef}
          targetId={targetId}
          width={1280}
          height={1024}
          grantId={grantId}
          desiredSize={desiredSize}
          onStatus={onStatus}
        />
      </ConsoleFrame>
      {settingsOpen && (
        <RDPSettingsDialog
          initial={settings}
          onApply={applySettings}
          onClose={() => setSettingsOpen(false)}
        />
      )}
    </>
  )
}

function statusBadge(s: RDPStatus): { tone: Tone; label: string; title?: string } {
  switch (s.kind) {
    case 'opening': return { tone: 'warn', label: 'connecting' }
    case 'live': return { tone: 'online', label: 'connected' }
    case 'closed': return { tone: 'mute', label: 'closed', title: s.reason }
    case 'error': return { tone: 'danger', label: 'error', title: s.msg }
  }
}

function statusLine(s: RDPStatus): string {
  switch (s.kind) {
    case 'opening': return 'negotiating RDP handshake…'
    case 'live': return `live · ${s.w}×${s.h} · ${s.frames} frame${s.frames === 1 ? '' : 's'}`
    case 'closed': return `closed · ${s.reason}`
    case 'error': return `error · ${s.msg}`
  }
}

// RDPOverlay scrims the canvas while connecting, and surfaces the authoritative
// close/error reason once the session ends. It never covers a live desktop.
// Reconnect re-mounts the canvas (re-opens the WS) in place rather than reloading
// the page — the dock host has no page of its own to reload.
function RDPOverlay({ status, targetId, onReconnect }: { status: RDPStatus; targetId: string; onReconnect: () => void }) {
  if (status.kind === 'live') return null
  if (status.kind === 'opening') {
    return (
      <ConsoleOverlay spinner title="Connecting to remote desktop">
        <p className="c2-console-overlay-msg">
          Negotiating the RDP handshake to <span className="c2-mono">{targetId}</span> through the broker.
          First pixels arrive on <span className="c2-mono">DESKTOP_SIZE</span>.
        </p>
      </ConsoleOverlay>
    )
  }
  if (status.kind === 'closed') {
    return (
      <ConsoleOverlay tone="mute" icon="○" title="Session closed"
        actions={<Button variant="ghost" size="sm" onClick={onReconnect}>Reconnect</Button>}>
        <p className="c2-console-overlay-msg c2-mono">{status.reason}</p>
      </ConsoleOverlay>
    )
  }
  // error — the authoritative WS-close reason (the merged WS-error-surfacing fix).
  return (
    <ConsoleOverlay tone="danger" icon="✗" title="Connection error"
      actions={<Button variant="ghost" size="sm" onClick={onReconnect}>Retry</Button>}>
      <p className="c2-console-overlay-msg c2-mono">{status.msg}</p>
    </ConsoleOverlay>
  )
}

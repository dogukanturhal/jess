// Session viewport — xterm.js ⇄ /ws/session ⇄ controller operator port.
//
// Per direction (Phase 5e-8 frame split):
//   server → client BINARY → terminal output (xterm renders)
//   server → client TEXT   → JSON envelope (session_meta etc.)
//   client → server TEXT   → operator keystrokes (xterm.onData)
//   client → server BINARY → resize / future control frames
//
// session_meta arrives ~50-700ms after WS open (jess-web fetches the
// just-created jit_sessions row from controller admin). When it lands
// the status bar flips from generic copy to live session id + recording
// path with copy-to-clipboard.
//
// PASS 2: the page is now a first-class C2 remote-console view — a paneled
// dark terminal stage inside a ConsoleFrame with a top console toolbar
// (target + protocol, connection status, session duration, RecordingDot,
// link-quality, fullscreen, Disconnect) and a thin status bar (session id,
// bytes in/out). The /ws/session xterm logic + fit addon + session_meta
// frame handling are UNCHANGED — only telemetry counters (byte totals +
// duration), which read off the same data path, are added.
import { FitAddon } from '@xterm/addon-fit'
import { Terminal } from '@xterm/xterm'
import { useEffect, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { fetchWebConfig, recordingConsoleLink, type WebConfig } from '../api/config'
import { RecordingDot } from '../components/RecordingDot'
import {
  AppShell,
  ConsoleFrame,
  ConsoleOverlay,
  ConsoleStat,
  ConsoleTelem,
  StatusBadge,
  useConsoleDock,
  type Tone,
} from '../components/c2'

type StateKind = 'connecting' | 'open' | 'error' | 'closed' | 'missing'

interface SessionMeta {
  type: 'session_meta'
  session_id?: string
  target_id: string
  grant_id: string
  operator_email?: string
  started_at: string
  recording_path?: string
  protocol?: string
  controller_id?: string
}

const STATE_META: Record<StateKind, { label: string; tone: Tone }> = {
  connecting: { label: 'connecting', tone: 'warn' },
  open: { label: 'connected', tone: 'online' },
  error: { label: 'error', tone: 'danger' },
  closed: { label: 'closed', tone: 'mute' },
  missing: { label: 'missing params', tone: 'danger' },
}

interface SSHSessionProps {
  target: string
  grant: string
  /** hand the session to the dock taskbar (stays connected). */
  onMinimize: () => void
  /** tear the session down — unmounts the terminal, which closes the WS. */
  onClose: () => void
}

// SSHSession — the LIVE SSH terminal body, extracted from the /session route so
// it can be hosted by the cross-nav ConsoleDock (app root) and survive
// navigation, exactly like RDPSession. Disconnect/Minimize are wired to dock
// callbacks; the xterm + /ws/session lifecycle is otherwise unchanged.
export function SSHSession({ target, grant, onMinimize, onClose }: SSHSessionProps) {
  const termHostRef = useRef<HTMLDivElement | null>(null)
  const [state, setState] = useState<StateKind>('connecting')
  const [latencyMs, setLatencyMs] = useState<number | null>(null)
  const [closeNote, setCloseNote] = useState<string | null>(null)
  const [meta, setMeta] = useState<SessionMeta | null>(null)
  const [cfg, setCfg] = useState<WebConfig | null>(null)
  const [authChecked, setAuthChecked] = useState<'loading' | 'ok' | 'anon'>('loading')

  // Pre-flight: refuse to even open the WS for anonymous browsers.
  // The handler at /ws/session also 401s pre-upgrade, but checking
  // /api/me first avoids the half-opened socket and lets us render
  // a sign-in CTA instead of a cryptic "session closed (code 1006)".
  useEffect(() => {
    const ctrl = new AbortController()
    fetch('/api/me', { credentials: 'same-origin', cache: 'no-store', signal: ctrl.signal })
      .then((r) => {
        if (ctrl.signal.aborted) return
        setAuthChecked(r.ok ? 'ok' : 'anon')
      })
      .catch(() => { if (!ctrl.signal.aborted) setAuthChecked('anon') })
    return () => ctrl.abort()
  }, [])
  // Connection-quality state. lastByteAt is bumped on every server
  // frame (binary terminal output OR text meta) and every client
  // keystroke. Stale check runs every 2s via setInterval to flip
  // the link-quality badge between active / idle / quiet / stalled.
  const lastByteAtRef = useRef<number>(performance.now())
  const [linkQuality, setLinkQuality] = useState<LinkQuality>('active')

  // Telemetry counters (status-bar throughput + session duration). These
  // ride the SAME data path — they only accumulate byte counts already
  // flowing through the WS handlers, so they cannot affect the transport.
  const bytesInRef = useRef(0)
  const bytesOutRef = useRef(0)
  const [bytes, setBytes] = useState<{ in: number; out: number }>({ in: 0, out: 0 })
  const openedAtRef = useRef<number | null>(null)
  const [durationMs, setDurationMs] = useState(0)

  // Fetch SPA runtime config once. Affects recording-link surfacing on
  // the status bar. Failure → cfg stays null; chip renders copy-only.
  useEffect(() => {
    const ctrl = new AbortController()
    fetchWebConfig(ctrl.signal).then((c) => {
      if (!ctrl.signal.aborted) setCfg(c)
    })
    return () => ctrl.abort()
  }, [])

  // Set the document title so multiple session tabs are distinguishable
  // from the OS task switcher / browser tab strip. Includes a state
  // glyph so a disconnected session is visibly different even before
  // the operator clicks the tab.
  useEffect(() => {
    const glyph =
      state === 'open' ? '●' :
        state === 'connecting' ? '◐' :
          state === 'error' ? '✗' :
            state === 'closed' ? '○' : '?'
    document.title = target ? `${glyph} ${target} · jess` : 'jess'
    return () => {
      document.title = 'jess'
    }
  }, [target, state])

  useEffect(() => {
    if (authChecked !== 'ok') return // wait for auth check, OR skip if anon
    // grant is OPTIONAL (admin-direct-connect path — empty grant
    // triggers the controller's spine.AdminAutoGrantRole inline
    // auto-mint when the operator carries platform_admin + MFA
    // amr). target is still required — there's no session without
    // a destination.
    if (!target) {
      setState('missing')
      return
    }
    const host = termHostRef.current
    if (!host) return

    const term = new Terminal({
      fontFamily: 'JetBrains Mono, ui-monospace, Menlo, monospace',
      fontSize: 13,
      lineHeight: 1.25,
      cursorBlink: true,
      convertEol: false,
      scrollback: 5000,
      // The xterm palette is DERIVED from the active app theme rather than a
      // fixed dark hex set. readTerminalTheme() pulls the --c2-terminal-*
      // custom properties off <html> (g100 dark → near-black console; g10 light
      // → Carbon-white console), and the MutationObserver below re-applies them
      // when the masthead theme toggle flips data-theme / data-carbon-theme — so
      // the terminal is legible in light mode instead of a dark box in a white
      // shell, and JS never drifts from the CSS token bridge.
      theme: readTerminalTheme(),
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(host)
    fit.fit()

    // Live-track the app theme: when the masthead toggle mutates data-theme /
    // data-carbon-theme on <html>, recompute the xterm palette from the freshly
    // resolved custom properties and apply it to the running terminal.
    const themeObserver = new MutationObserver(() => {
      term.options.theme = readTerminalTheme()
    })
    themeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme', 'data-carbon-theme'],
    })

    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    // grant is OPTIONAL — when empty, the backend forwards an
    // empty GrantID to the controller, which dispatches into
    // the admin-direct-connect inline auto-mint path. The
    // backend handler explicitly accepts the empty case.
    const grantQS = grant ? `&grant=${encodeURIComponent(grant)}` : ''
    // jess-web (the SSH client) requests the PTY before any resize frame can
    // arrive, so seed the initial PTY size from the post-fit dimensions in the
    // URL. The browser then re-asserts size with a binary resize control frame
    // on open + on every resize (encodeResize / sendResize below).
    const url =
      `${proto}//${window.location.host}/ws/session` +
      `?target=${encodeURIComponent(target)}` +
      `&cols=${term.cols}&rows=${term.rows}` +
      grantQS

    const startedAt = performance.now()
    setState('connecting')
    setCloseNote(null)
    setMeta(null)
    bytesInRef.current = 0
    bytesOutRef.current = 0
    setBytes({ in: 0, out: 0 })
    openedAtRef.current = null
    setDurationMs(0)

    let ws: WebSocket
    try {
      ws = new WebSocket(url)
    } catch (e: unknown) {
      setState('error')
      const msg = e instanceof Error ? e.message : String(e)
      term.writeln(`\x1b[31mwebsocket construct failed: ${msg}\x1b[0m`)
      // The resize listener isn't registered until after a successful
      // construct, so there's nothing to remove on this path. The theme
      // observer was set up with the terminal (above), so disconnect it here.
      themeObserver.disconnect()
      term.dispose()
      return
    }
    ws.binaryType = 'arraybuffer'

    // sendResize emits a binary control frame so jess-web (the SSH client)
    // issues an SSH window-change to the remote PTY. Wire format (matches
    // ssh_client.go parseResize): [0x01][cols uint32 BE][rows uint32 BE].
    const sendResize = (cols: number, rows: number) => {
      if (ws.readyState !== WebSocket.OPEN) return
      const frame = new ArrayBuffer(9)
      const dv = new DataView(frame)
      dv.setUint8(0, 0x01)
      dv.setUint32(1, cols, false)
      dv.setUint32(5, rows, false)
      ws.send(frame)
    }
    const onResize = () => {
      // Skip while minimized to the dock (host display:none → 0 dimensions):
      // fitting to 0 would shrink the remote PTY. The dock keeps the session
      // mounted + connected; the ResizeObserver re-fits on restore.
      if (host.offsetParent === null) return
      fit.fit()
      sendResize(term.cols, term.rows)
    }
    window.addEventListener('resize', onResize)
    // Observe the host so a restore from the dock (display:none → flex, or any
    // container size change) re-fits the terminal — window 'resize' alone
    // misses show/hide transitions.
    const ro = new ResizeObserver(() => onResize())
    ro.observe(host)

    ws.onopen = () => {
      setState('open')
      setLatencyMs(Math.round(performance.now() - startedAt))
      lastByteAtRef.current = performance.now()
      openedAtRef.current = performance.now()
      // Re-assert the terminal size now that the socket is open (the URL seed
      // covers the PTY-request race; this catches any fit change since).
      sendResize(term.cols, term.rows)
      // xterm fires onResize whenever cols/rows change (fit, font, container).
      term.onResize(({ cols, rows }) => sendResize(cols, rows))
      term.onData((data) => {
        if (ws.readyState === WebSocket.OPEN) ws.send(data)
        // Operator typing counts as "alive" — keeps the link-quality
        // badge fresh even if the target isn't echoing back yet.
        lastByteAtRef.current = performance.now()
        bytesOutRef.current += byteLen(data)
      })
    }
    ws.onmessage = (evt) => {
      lastByteAtRef.current = performance.now()
      if (typeof evt.data === 'string') {
        bytesInRef.current += byteLen(evt.data)
        // TEXT frame — Phase 5e-8 JSON envelope. Parse + dispatch by
        // .type. Anything that doesn't parse OR doesn't have a known
        // type falls back to writing into xterm so error markers from
        // pre-Phase-5e-8 jess-web (which sent ANSI-coloured text frames
        // on dial failure) still render readably.
        try {
          const parsed = JSON.parse(evt.data) as { type?: string; stage?: string; msg?: string }
          if (parsed && parsed.type === 'session_meta') {
            setMeta(parsed as SessionMeta)
            return
          }
          if (parsed && parsed.type === 'error') {
            // Backend-synthesised error frame (e.g. the SSH client failed to
            // mint a cert / handshake / start the shell). Render it in red so
            // the operator sees a cause instead of a bare 1011 close.
            setState('error')
            const stage = parsed.stage ? ` [${parsed.stage}]` : ''
            term.writeln(`\x1b[31mjess-web${stage}: ${parsed.msg ?? 'session error'}\x1b[0m`)
            return
          }
        } catch {
          // fall through to terminal write
        }
        term.write(evt.data)
        return
      }
      if (evt.data instanceof ArrayBuffer) {
        bytesInRef.current += evt.data.byteLength
        term.write(new Uint8Array(evt.data))
      }
    }
    ws.onerror = () => setState('error')
    ws.onclose = (evt) => {
      setState(evt.wasClean ? 'closed' : 'error')
      term.writeln('')
      term.writeln(
        `\x1b[33msession closed (code ${evt.code}${evt.reason ? `, reason "${evt.reason}"` : ''})\x1b[0m`,
      )
      if (evt.code === 1006) {
        const note = 'grant expired? target offline? sign-in expired?'
        setCloseNote(note)
        term.writeln(`\x1b[33m  → ${note}\x1b[0m`)
        term.writeln('\x1b[33m  → check /api/me, then refresh the grant via jessctl request\x1b[0m')
      }
    }

    // Link-quality ticker: classify silence into active/idle/quiet/
    // stalled based on time since last byte in either direction. Also
    // publishes the accumulated byte counters + the live session
    // duration. 1s cadence is fine for the visible telemetry.
    const qualityTick = window.setInterval(() => {
      const gap = performance.now() - lastByteAtRef.current
      setLinkQuality(classifyLink(gap))
      setBytes({ in: bytesInRef.current, out: bytesOutRef.current })
      if (openedAtRef.current != null) {
        setDurationMs(performance.now() - openedAtRef.current)
      }
    }, 1000)

    return () => {
      window.removeEventListener('resize', onResize)
      ro.disconnect()
      themeObserver.disconnect()
      window.clearInterval(qualityTick)
      try {
        if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
          ws.close()
        }
      } catch {
        // intentional — best effort
      }
      term.dispose()
    }
  }, [target, grant, authChecked])

  // The dock only mounts SSHSession once the launcher confirmed sign-in, so the
  // anon path is unreachable here; render nothing rather than an AppShell (which
  // would nest a second masthead inside the dock host).
  if (authChecked === 'anon') return null

  const sm = STATE_META[state]

  return (
    <ConsoleFrame
        protocol="SSH"
        target={target || '<no target>'}
        status={{ tone: sm.tone, label: sm.label }}
        onDisconnect={onClose}
        onMinimize={onMinimize}
        disconnectLabel="Disconnect"
        telemetry={
          <>
            {state === 'open' && (
              <ConsoleTelem label="up" title="Session duration">{formatDuration(durationMs)}</ConsoleTelem>
            )}
            <ConsoleTelem label="rtt" title="WebSocket open latency">
              {latencyMs == null ? '—' : `${latencyMs}ms`}
            </ConsoleTelem>
            {state === 'open' && <LinkQualityBadge quality={linkQuality} />}
            <RecordingDot status={state === 'open' ? 'live' : 'stopped'}>
              {state === 'open'
                ? 'tee to audit-archive (asciicast v2 + Vault Transit signature)'
                : (closeNote ?? 'recording sealed in audit-archive')}
            </RecordingDot>
          </>
        }
        overlay={
          state === 'missing' ? (
            <ConsoleOverlay tone="danger" icon="✗" title="No target">
              <p className="c2-console-overlay-msg">
                Open an SSH session from a target's <b>Connect ▾</b> action in the catalog.
              </p>
            </ConsoleOverlay>
          ) : undefined
        }
        statusbar={<SessionStatusBar meta={meta} cfg={cfg} bytes={bytes} state={state} closeNote={closeNote} />}
      >
        <div ref={termHostRef} className="c2-terminal" aria-label="Brokered session terminal" />
      </ConsoleFrame>
  )
}

// Session — the /session route is now a thin LAUNCHER (mirrors RDP): it confirms
// sign-in, registers the live SSH session into the app-root ConsoleDock, and
// redirects to the inventory. The session (SSHSession above) is then hosted by
// the dock and survives navigation — Minimize drops it to the session tray
// (stays connected), Disconnect unmounts it (closing the WS). Re-opening the
// same target just foregrounds the existing session (dock.open is idempotent).
export function Session() {
  const [params] = useSearchParams()
  const target = params.get('target') ?? ''
  const grant = params.get('grant') ?? ''
  const [auth, setAuth] = useState<'loading' | 'anon' | 'ok'>('loading')
  const navigate = useNavigate()
  const { open, minimize, close } = useConsoleDock()
  const launched = useRef(false)

  useEffect(() => {
    const ctrl = new AbortController()
    fetch('/api/me', { credentials: 'same-origin', cache: 'no-store', signal: ctrl.signal })
      .then((r) => setAuth(r.ok ? 'ok' : 'anon'))
      .catch(() => setAuth('anon'))
    return () => ctrl.abort()
  }, [])

  useEffect(() => {
    if (auth !== 'ok' || !target || launched.current) return
    launched.current = true
    const id = `ssh:${target}${grant ? `:${grant}` : ''}`
    open({
      id,
      title: target,
      proto: 'SSH',
      node: (
        <SSHSession
          key={id}
          target={target}
          grant={grant}
          onMinimize={minimize}
          onClose={() => close(id)}
        />
      ),
    })
    navigate('/targets', { replace: true })
  }, [auth, target, grant, open, minimize, close, navigate])

  if (auth === 'anon') return <AppShell variant="console" />
  if (!target) {
    return (
      <AppShell variant="console" requireAuth={false}>
        <div className="c2-console-body">
          <ConsoleOverlay tone="danger" icon="✗" title="No target">
            <p className="c2-console-overlay-msg">
              Open an SSH session from a target's <b>Connect ▾</b> action in the catalog.
            </p>
          </ConsoleOverlay>
        </div>
      </AppShell>
    )
  }
  return (
    <AppShell variant="console" requireAuth={false}>
      <div className="c2-console-body">
        <ConsoleOverlay spinner title="Opening session">
          <p className="c2-console-overlay-msg">Launching the SSH session for <span className="c2-mono">{target}</span>…</p>
        </ConsoleOverlay>
      </div>
    </AppShell>
  )
}

// SessionStatusBar — thin bottom strip: session id + recording chips + byte
// throughput. Phase 5e-8 session_meta rendering preserved.
//   meta=null              → "session id: pending"
//   meta.session_id=""     → "session id: unavailable" (no controller SessionStore)
//   meta.session_id set    → mono copy chip + recording path link
function SessionStatusBar({
  meta,
  cfg,
  bytes,
  state,
  closeNote,
}: {
  meta: SessionMeta | null
  cfg: WebConfig | null
  bytes: { in: number; out: number }
  state: StateKind
  closeNote: string | null
}) {
  const consoleLink = meta?.recording_path ? recordingConsoleLink(cfg, meta.recording_path) : null
  return (
    <>
      {meta == null ? (
        <ConsoleStat label="Session"><span className="c2-ink-3">pending…</span></ConsoleStat>
      ) : !meta.session_id ? (
        <ConsoleStat label="Session"><span className="c2-ink-3">unavailable</span></ConsoleStat>
      ) : (
        <span className="c2-console-stat">
          <span className="c2-eyebrow">Session</span>
          <CopyChip label={meta.session_id} />
          {meta.recording_path && (
            <>
              <span className="c2-eyebrow" style={{ marginLeft: 4 }}>Rec</span>
              <CopyChip label={meta.recording_path} title="WORM bundle path in audit-archive" />
              {consoleLink && (
                <a href={consoleLink} target="_blank" rel="noopener noreferrer"
                  className="c2-btn c2-btn-ghost c2-btn-sm"
                  title="Open in MinIO Console — Falcon-ID SSO carries auth">Open ↗</a>
              )}
            </>
          )}
        </span>
      )}
      <span className="c2-toolbar-spacer" />
      <ConsoleStat label="In" title="Bytes received from the target"><span className="c2-ink-1">{formatBytes(bytes.in)}</span></ConsoleStat>
      <ConsoleStat label="Out" title="Bytes sent to the target"><span className="c2-ink-1">{formatBytes(bytes.out)}</span></ConsoleStat>
      {state === 'error' && closeNote && <span className="c2-ink-3">· {closeNote}</span>}
    </>
  )
}

// LinkQuality classifies silence on the WS into operator-meaningful
// states. 'active' is "bytes in the last 5s either direction"; the
// ladder degrades to 'stalled' if nothing's moved in >2min — at that
// point the operator should suspect a network drop even though
// ws.readyState may still claim OPEN (the TCP-level half-close may
// not have surfaced yet).
type LinkQuality = 'active' | 'idle' | 'quiet' | 'stalled'

function classifyLink(gapMs: number): LinkQuality {
  if (gapMs < 5_000) return 'active'
  if (gapMs < 30_000) return 'idle'
  if (gapMs < 120_000) return 'quiet'
  return 'stalled'
}

function LinkQualityBadge({ quality }: { quality: LinkQuality }) {
  const meta: Record<LinkQuality, { label: string; tone: Tone }> = {
    active: { label: 'active', tone: 'online' },
    idle: { label: 'idle', tone: 'mute' },
    quiet: { label: 'quiet', tone: 'warn' },
    stalled: { label: 'stalled', tone: 'danger' },
  }
  const m = meta[quality]
  return <StatusBadge tone={m.tone} title={`Link ${m.label} — no bytes in either direction for the threshold`}>{m.label}</StatusBadge>
}

// CopyChip renders a monospace token with a one-click copy-to-clipboard
// button. Falls back gracefully when navigator.clipboard isn't available
// (HTTP origins, locked-down browser policy).
function CopyChip({ label, title }: { label: string; title?: string }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(label)
        setCopied(true)
        window.setTimeout(() => setCopied(false), 1500)
      }
    } catch {
      // intentional — best effort. Visible label is still selectable.
    }
  }
  return (
    <button
      type="button"
      onClick={copy}
      className="c2-copy-chip"
      title={title ?? `Click to copy ${label}`}
      aria-label={`Copy ${label}`}
    >
      <span>{label}</span>
      <span className="c2-copy-state" aria-hidden="true">
        {copied ? '✓' : '⧉'}
      </span>
    </button>
  )
}

// readTerminalTheme resolves the xterm palette from the active app theme by
// reading the --c2-terminal-* custom properties off <html> (set by the SCSS
// bridge per g100/g10). Falls back to the dark console palette if a property is
// missing (e.g. computed styles not yet available). Returning a fresh object is
// what xterm's `term.options.theme =` setter needs to re-paint on theme change.
function readTerminalTheme(): {
  background: string
  foreground: string
  cursor: string
  selectionBackground: string
} {
  const FALLBACK = {
    background: '#070b12',
    foreground: '#e4e7ee',
    cursor: '#22d3ee',
    selectionBackground: 'rgba(34, 211, 238, 0.28)',
  }
  try {
    const cs = getComputedStyle(document.documentElement)
    const pick = (name: string, fb: string) => {
      const v = cs.getPropertyValue(name).trim()
      return v || fb
    }
    return {
      background: pick('--c2-terminal-bg', FALLBACK.background),
      foreground: pick('--c2-terminal-fg', FALLBACK.foreground),
      cursor: pick('--c2-terminal-cursor', FALLBACK.cursor),
      selectionBackground: pick('--c2-terminal-sel', FALLBACK.selectionBackground),
    }
  } catch {
    return FALLBACK
  }
}

// byteLen returns the UTF-8 byte length of a WS payload (string or buffer).
function byteLen(data: unknown): number {
  if (typeof data === 'string') {
    // Fast, allocation-free approximation is wrong for multibyte; use the
    // encoder for correctness — keystroke payloads are tiny so this is cheap.
    return new TextEncoder().encode(data).length
  }
  if (data instanceof ArrayBuffer) return data.byteLength
  if (ArrayBuffer.isView(data)) return data.byteLength
  return 0
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

function formatDuration(ms: number): string {
  const s = Math.floor(ms / 1000)
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  const pad = (n: number) => String(n).padStart(2, '0')
  return h > 0 ? `${h}:${pad(m)}:${pad(sec)}` : `${m}:${pad(sec)}`
}

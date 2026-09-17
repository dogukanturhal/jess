// Recording playback — /recordings/:sessionId. Streams the asciicast
// bundle from jess-web's /api/my/sessions/{id}/recording proxy and
// plays it with asciinema-player.
//
// Auth: the proxy enforces owner-or-admin server-side. This page is
// also gated client-side (same pattern as Landing / Session) so anon
// browsers see a sign-in card instead of "couldn't load".
//
// Failure modes the UI handles:
//   503 → "controller doesn't have MinIO read creds — open the bundle
//         in MinIO Console instead" with a deep link (Phase 5e-9)
//   404 → "session has no recording (target wasn't Recorded) OR you
//         don't own this session"
//   any other → generic "couldn't load recording" with HTTP status
//
// PASS 2: a paneled player view + a metadata/KeyValueList side panel
// (session, key id, sealed-at, content size + sha256) carrying the
// tamper-evidence verify result, with the broken-seal detail re-expanded
// into its own panel.
import * as AsciinemaPlayer from 'asciinema-player'
import 'asciinema-player/dist/bundle/asciinema-player.css'
import { useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { fetchWebConfig, recordingConsoleLink, type WebConfig } from '../api/config'
import { verifyRecording, type VerifyResponse } from '../api/verify'
import { AppShell, KeyValueList, PageHeader, Panel, StatusBadge, type KVItem } from '../components/c2'

type LoadState =
  | { kind: 'loading' }
  | { kind: 'ok' }
  | { kind: 'unavailable'; recordingPath?: string } // 503
  | { kind: 'forbidden' }                            // 404
  | { kind: 'err'; status: number; msg: string }
  | { kind: 'anon' }

type VerifyState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'ok'; verify: VerifyResponse }
  | { kind: 'unavailable' }
  | { kind: 'err'; msg: string }

export function Recording() {
  const { sessionId } = useParams<{ sessionId: string }>()
  const hostRef = useRef<HTMLDivElement | null>(null)
  const [state, setState] = useState<LoadState>({ kind: 'loading' })
  const [cfg, setCfg] = useState<WebConfig | null>(null)
  const [verify, setVerify] = useState<VerifyState>({ kind: 'idle' })

  useEffect(() => {
    const ctrl = new AbortController()
    fetchWebConfig(ctrl.signal).then((c) => {
      if (!ctrl.signal.aborted) setCfg(c)
    })
    return () => ctrl.abort()
  }, [])

  // Phase 5e-14: fire the verify request in parallel with the
  // asciicast fetch. Verify is cheap (a few MinIO reads + local
  // ed25519 verify) but we don't want it to gate playback — render the
  // player as soon as bytes arrive, drop the badge in whenever the
  // verifier completes. 503 = controller not configured → badge stays
  // hidden (admin can wire it later without a UI change).
  useEffect(() => {
    if (!sessionId) return
    const ctrl = new AbortController()
    setVerify({ kind: 'loading' })
    verifyRecording(sessionId, ctrl.signal)
      .then((v) => { if (!ctrl.signal.aborted) setVerify({ kind: 'ok', verify: v }) })
      .catch((e: unknown) => {
        if (ctrl.signal.aborted) return
        // 503: not configured. Don't surface as an error — hide the
        // badge so the page doesn't look broken when the operator
        // just wants to watch a session in dev.
        if (e && typeof e === 'object' && 'status' in e && (e as { status: number }).status === 503) {
          setVerify({ kind: 'unavailable' })
          return
        }
        const msg = e instanceof Error ? e.message : String(e)
        setVerify({ kind: 'err', msg })
      })
    return () => ctrl.abort()
  }, [sessionId])

  useEffect(() => {
    if (!sessionId) return
    const ctrl = new AbortController()
    // Pre-flight: ensure the operator is signed in. The proxy 401s
    // anon callers but we want a sign-in card not a JSON error.
    fetch('/api/me', { credentials: 'same-origin', cache: 'no-store', signal: ctrl.signal })
      .then(async (meR) => {
        if (ctrl.signal.aborted) return
        if (!meR.ok) {
          setState({ kind: 'anon' })
          return
        }
        // Try a HEAD-equivalent: do the GET but only inspect status
        // first. If 200, we'll have the asciicast bytes inside the
        // Response — pass directly to the player via fetchOpts.
        const r = await fetch(`/api/my/sessions/${encodeURIComponent(sessionId)}/recording`, {
          credentials: 'same-origin',
          signal: ctrl.signal,
        })
        if (ctrl.signal.aborted) return
        if (r.status === 200) {
          const text = await r.text()
          // Defer to next tick so the host div is mounted.
          window.setTimeout(() => {
            const host = hostRef.current
            if (!host) return
            const blob = new Blob([text], { type: 'application/x-asciicast' })
            const url = URL.createObjectURL(blob)
            try {
              AsciinemaPlayer.create(url, host, {
                fit: 'width',
                terminalFontFamily: 'JetBrains Mono, ui-monospace, Menlo, monospace',
                terminalFontSize: '13px',
                // No autoplay — operator may want to scrub. Click to start.
                autoPlay: false,
                idleTimeLimit: 2, // collapse multi-second idle gaps
              })
            } catch {
              // intentional — asciinema-player will surface its own
              // error inside the host div if the bundle is malformed
            }
            setState({ kind: 'ok' })
          }, 0)
          return
        }
        if (r.status === 503) {
          // Controller has no MinIO read; surface fallback link.
          const j = await r.json().catch(() => null) as { recording_path?: string } | null
          setState({ kind: 'unavailable', recordingPath: j?.recording_path })
          return
        }
        if (r.status === 404) {
          setState({ kind: 'forbidden' })
          return
        }
        const j = await r.json().catch(() => null) as { error?: string } | null
        setState({ kind: 'err', status: r.status, msg: j?.error ?? `HTTP ${r.status}` })
      })
      .catch(() => {
        if (!ctrl.signal.aborted) setState({ kind: 'err', status: 0, msg: 'network error' })
      })
    return () => ctrl.abort()
  }, [sessionId])

  if (state.kind === 'anon') return <AppShell />

  return (
    <AppShell requireAuth={false}>
      <div className="c2-page">
        <PageHeader
          crumbs={[{ label: 'Recordings', to: '/rdp/recordings' }, { label: sessionId ?? '' }]}
          title="Session replay"
          badge={<VerifyBadge state={verify} />}
          subtitle={<>Tamper-evident WORM bundle · asciicast v2</>}
        />
        <div className="c2-page-body">
          <div className="c2-rec-layout">
            <Panel title="Playback" className="c2-rec-main">
              <div className="c2-panel-pad">
                {state.kind === 'loading' && <p className="c2-ink-3">Loading recording…</p>}
                {state.kind === 'ok' && <div ref={hostRef} className="c2-rec-player" />}
                {state.kind === 'forbidden' && <ForbiddenHint />}
                {state.kind === 'unavailable' && <UnavailableHint recordingPath={state.recordingPath} cfg={cfg} />}
                {state.kind === 'err' && (
                  <p className="c2-ink-3">Couldn't load recording (HTTP {state.status}): {state.msg}</p>
                )}
              </div>
            </Panel>
            <div className="c2-rec-side">
              <Panel title="Metadata">
                <KeyValueList items={metadataItems(sessionId, verify)} />
              </Panel>
              <SealPanel state={verify} />
            </div>
          </div>
          <p style={{ marginTop: 4 }}><Link to="/" className="c2-btn c2-btn-ghost">← Back to overview</Link></p>
        </div>
      </div>
    </AppShell>
  )
}

function metadataItems(sessionId: string | undefined, v: VerifyState): KVItem[] {
  const items: KVItem[] = [
    { key: 'Session', value: <code>{sessionId ?? '—'}</code> },
    { key: 'Format', value: 'asciicast v2 (WORM)' },
  ]
  if (v.kind === 'ok') {
    const ver = v.verify
    items.push({ key: 'Key id', value: ver.key_id ? <code>{ver.key_id}</code> : <span className="c2-ink-3">—</span> })
    items.push({ key: 'Sealed at', value: ver.sealed_at ? new Date(ver.sealed_at).toLocaleString() : <span className="c2-ink-3">—</span> })
    items.push({ key: 'Content size', value: <span className="c2-mono">{formatBytes(ver.content_bytes)}</span> })
    if (ver.content_sha256) {
      items.push({ key: 'SHA-256', value: <code style={{ wordBreak: 'break-all' }}>{ver.content_sha256}</code> })
    }
  } else if (v.kind === 'loading') {
    items.push({ key: 'Seal', value: <span className="c2-ink-3">verifying…</span> })
  } else if (v.kind === 'unavailable') {
    items.push({ key: 'Seal', value: <span className="c2-ink-3">verifier not configured</span> })
  }
  return items
}

// SealPanel re-expands the tamper-evidence detail condensed in pass 1: the
// signature-valid / hash-match verdict, and an escalation note on a broken seal.
function SealPanel({ state }: { state: VerifyState }) {
  if (state.kind === 'idle' || state.kind === 'unavailable') return null
  if (state.kind === 'loading') {
    return (
      <Panel title="Tamper evidence">
        <div className="c2-panel-pad"><p className="c2-ink-3" style={{ margin: 0 }}>Verifying WORM seal…</p></div>
      </Panel>
    )
  }
  if (state.kind === 'err') {
    return (
      <Panel title="Tamper evidence">
        <div className="c2-panel-pad">
          <div className="c2-note c2-note-mute">
            <p className="c2-note-title">Verify unavailable</p>
            <p className="c2-mono" style={{ margin: 0, fontSize: 12 }}>{state.msg}</p>
          </div>
        </div>
      </Panel>
    )
  }
  const v = state.verify
  if (v.ok) {
    return (
      <Panel title="Tamper evidence" actions={<StatusBadge tone="online">intact</StatusBadge>}>
        <KeyValueList items={[
          { key: 'Signature', value: <StatusBadge tone="online">valid</StatusBadge> },
          { key: 'Content hash', value: <StatusBadge tone="online">match</StatusBadge> },
          { key: 'WORM chain', value: <StatusBadge tone="online">linked</StatusBadge> },
        ]} />
      </Panel>
    )
  }
  // Broken seal — surface the specific failure (sig vs hash vs chain) +
  // escalation note. Re-expanded from pass-1's condensed badge.
  return (
    <Panel title="Tamper evidence" actions={<StatusBadge tone="danger">TAMPERED</StatusBadge>}>
      <div className="c2-panel-pad">
        <div className="c2-note c2-note-danger">
          <p className="c2-note-title">⚠ WORM seal broken</p>
          <p style={{ margin: '0 0 8px' }}>
            This bundle failed verification. Escalate to security — do not treat the playback as authoritative.
          </p>
          <KeyValueList items={[
            { key: 'Signature', value: <StatusBadge tone={v.signature_valid ? 'online' : 'danger'}>{v.signature_valid ? 'valid' : 'invalid'}</StatusBadge> },
            { key: 'Content hash', value: <StatusBadge tone={v.hash_match ? 'online' : 'danger'}>{v.hash_match ? 'match' : 'mismatch'}</StatusBadge> },
            { key: 'WORM chain', value: <StatusBadge tone={v.chain_link_ok ? 'online' : 'danger'}>{v.chain_link_ok ? 'linked' : 'broken'}</StatusBadge> },
          ]} />
          {!v.chain_link_ok && (v.chain_link_expected || v.chain_link_got) && (
            <div style={{ marginTop: 10 }}>
              <p className="c2-eyebrow" style={{ margin: '0 0 4px' }}>Chain mismatch</p>
              <KeyValueList items={[
                { key: 'Expected', value: <code style={{ wordBreak: 'break-all' }}>{v.chain_link_expected ?? '—'}</code> },
                { key: 'Got', value: <code style={{ wordBreak: 'break-all' }}>{v.chain_link_got ?? '—'}</code> },
              ]} />
            </div>
          )}
        </div>
      </div>
    </Panel>
  )
}

function VerifyBadge({ state }: { state: VerifyState }) {
  if (state.kind === 'idle' || state.kind === 'unavailable') return null
  if (state.kind === 'loading') return <StatusBadge tone="mute">verifying…</StatusBadge>
  if (state.kind === 'err') return <StatusBadge tone="mute" title={state.msg}>verify unavailable</StatusBadge>
  const v = state.verify
  if (v.ok) {
    const sealedAt = v.sealed_at ? new Date(v.sealed_at).toLocaleString() : ''
    return (
      <StatusBadge
        tone="online"
        title={`signature_valid=true · hash_match=true · key=${v.key_id ?? '—'} · sealed_at=${sealedAt} · ${v.content_bytes} bytes · sha256=${v.content_sha256 ?? ''}`}
      >
        tamper-evident{v.key_id ? ` · ${v.key_id}` : ''}
      </StatusBadge>
    )
  }
  return <StatusBadge tone="danger" title="WORM seal broken — escalate to security">bundle tampered</StatusBadge>
}

function ForbiddenHint() {
  return (
    <p className="c2-ink-2">
      No recording for this session — either it didn't exist, doesn't belong to you,
      or the target wasn't recorded.
    </p>
  )
}

function UnavailableHint({ recordingPath, cfg }: { recordingPath?: string; cfg: WebConfig | null }) {
  const link = recordingPath ? recordingConsoleLink(cfg, recordingPath) : null
  return (
    <div className="c2-note c2-note-warn">
      <p style={{ margin: '0 0 10px' }}>
        In-browser playback isn't configured on this controller (MinIO read
        credentials not wired). The bundle is still safely stored in WORM — open it directly:
      </p>
      {link ? (
        <a className="c2-btn c2-btn-primary c2-btn-sm" href={link} target="_blank" rel="noopener noreferrer">
          Open in MinIO Console ↗
        </a>
      ) : (
        <p className="c2-ink-3" style={{ margin: 0 }}>
          MinIO Console deep-link base also unset (<code>JESS_WEB_RECORDING_CONSOLE_URL</code>);
          ask an admin to provision either path.
        </p>
      )}
    </div>
  )
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

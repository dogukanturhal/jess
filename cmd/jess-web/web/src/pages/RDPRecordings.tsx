// RDP recordings — ADR 0051 P4 replay, in the C2 shell.
//   /rdp/recordings            → list THIS operator's sealed v2 recordings
//   /rdp/recordings/:sessionId → replay one recording (RDPReplayCanvas) + verify
// Owner-scoping + WORM verify are enforced server-side; this is the viewer.
import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import type { RDPRecordingSummary } from '../api/rdp'
import { RDPReplayCanvas, type RDPReplayMeta } from '../components/RDPReplayCanvas'
import { AppShell, Column, DataGrid, KeyValueList, PageHeader, Panel, StatusBadge, type KVItem } from '../components/c2'

export function RDPRecordings() {
  const { sessionId } = useParams<{ sessionId?: string }>()
  if (sessionId) return <RDPReplayView sessionId={sessionId} />
  return <RDPRecordingsList />
}

function RDPRecordingsList() {
  const [rows, setRows] = useState<RDPRecordingSummary[] | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    const ctrl = new AbortController()
    fetch('/api/rdp/recordings', { credentials: 'same-origin', cache: 'no-store', signal: ctrl.signal })
      .then(async (r) => {
        if (r.status === 503) throw new Error('recording store not configured')
        if (!r.ok) throw new Error(`list failed (${r.status})`)
        return r.json() as Promise<{ recordings: RDPRecordingSummary[] }>
      })
      .then((d) => setRows(d.recordings ?? []))
      .catch((e: unknown) => {
        if ((e as { name?: string }).name === 'AbortError') return
        setErr(e instanceof Error ? e.message : String(e))
      })
    return () => ctrl.abort()
  }, [])

  const columns: Column<RDPRecordingSummary>[] = [
    { key: 'target', header: 'Target', sortValue: (r) => r.target_id, cell: (r) => <Link to={`/targets/${encodeURIComponent(r.target_id)}`} className="c2-grid-mono">{r.target_id}</Link> },
    { key: 'sealed', header: 'Sealed', numeric: true, sortValue: (r) => r.sealed_at, cell: (r) => <span className="c2-grid-mute">{new Date(r.sealed_at).toLocaleString()}</span> },
    { key: 'bytes', header: 'Size', numeric: true, sortValue: (r) => r.bytes, cell: (r) => <span className="c2-grid-mute">{formatBytes(r.bytes)}</span> },
  ]

  return (
    <AppShell>
      <div className="c2-page">
        <PageHeader
          crumbs={[{ label: 'Inventory', to: '/' }, { label: 'Recordings' }]}
          title="RDP recordings"
          subtitle="Tamper-evident WORM recordings of your brokered RDP sessions (jess-rdp-recording-v2)"
        />
        <div className="c2-page-body">
          <Panel title="Recordings">
            {err ? (
              <div className="c2-grid-empty">{err}</div>
            ) : rows === null ? (
              <div className="c2-loading">Loading…</div>
            ) : (
              <DataGrid rows={rows} columns={columns} rowKey={(r) => r.session_id} defaultSort={{ key: 'sealed', dir: 'desc' }}
                empty="No RDP recordings yet."
                actions={(r) => <Link className="c2-btn c2-btn-primary c2-btn-sm" to={`/rdp/recordings/${encodeURIComponent(r.session_id)}`}>▶ Replay</Link>}
              />
            )}
          </Panel>
        </div>
      </div>
    </AppShell>
  )
}

type Verdict =
  | { kind: 'idle' }
  | { kind: 'checking' }
  | { kind: 'ok'; keyId: string }
  | { kind: 'broken'; sig: boolean; hash: boolean }
  | { kind: 'error'; msg: string }

function RDPReplayView({ sessionId }: { sessionId: string }) {
  const [verdict, setVerdict] = useState<Verdict>({ kind: 'idle' })
  const [meta, setMeta] = useState<RDPReplayMeta | null>(null)

  const onMeta = useCallback((m: RDPReplayMeta) => setMeta(m), [])

  const verify = useCallback(() => {
    setVerdict({ kind: 'checking' })
    fetch(`/api/rdp/recordings/${encodeURIComponent(sessionId)}/verify`, { credentials: 'same-origin', cache: 'no-store' })
      .then(async (r) => {
        if (!r.ok) throw new Error(`verify failed (${r.status})`)
        return r.json() as Promise<{ ok: boolean; signature_valid: boolean; hash_match: boolean; key_id: string }>
      })
      .then((v) => setVerdict(v.ok ? { kind: 'ok', keyId: v.key_id } : { kind: 'broken', sig: v.signature_valid, hash: v.hash_match }))
      .catch((e: unknown) => setVerdict({ kind: 'error', msg: e instanceof Error ? e.message : String(e) }))
  }, [sessionId])

  return (
    <AppShell requireAuth={false}>
      <div className="c2-page">
        <PageHeader
          crumbs={[{ label: 'Recordings', to: '/rdp/recordings' }, { label: sessionId }]}
          title="RDP replay"
          badge={<VerifyBadge verdict={verdict} />}
          subtitle={<>Replaying <code>{sessionId}</code></>}
          actions={
            <button className="c2-btn c2-btn-ghost" onClick={verify} disabled={verdict.kind === 'checking'}>
              {verdict.kind === 'checking' ? 'Verifying…' : 'Verify WORM seal'}
            </button>
          }
        />
        <div className="c2-page-body">
          <div className="c2-rec-layout">
            <Panel title="Playback" className="c2-rec-main">
              <div className="c2-panel-pad">
                <RDPReplayCanvas sessionId={sessionId} onMeta={onMeta} />
              </div>
            </Panel>
            <div className="c2-rec-side">
              <Panel title="Metadata">
                <KeyValueList items={metadataItems(sessionId, meta, verdict)} />
              </Panel>
              <SealPanel verdict={verdict} />
            </div>
          </div>
          <p style={{ marginTop: 4 }}><Link to="/rdp/recordings" className="c2-btn c2-btn-ghost">← All recordings</Link></p>
        </div>
      </div>
    </AppShell>
  )
}

function metadataItems(sessionId: string, meta: RDPReplayMeta | null, verdict: Verdict): KVItem[] {
  const items: KVItem[] = [
    { key: 'Session', value: <code>{sessionId}</code> },
  ]
  if (meta) {
    const m = meta.meta
    items.push({ key: 'Subject', value: m.subject ? <code>{m.subject}</code> : <span className="c2-ink-3">—</span> })
    items.push({ key: 'Target', value: <Link to={`/targets/${encodeURIComponent(m.target)}`} className="c2-grid-mono">{m.target}</Link> })
    items.push({ key: 'Protocol', value: m.protocol ?? <span className="c2-ink-3">—</span> })
    items.push({ key: 'Started', value: m.at ? new Date(m.at).toLocaleString() : <span className="c2-ink-3">—</span> })
    items.push({ key: 'Frames', value: <span className="c2-mono">{meta.frameCount}</span> })
    items.push({ key: 'Inputs', value: <span className="c2-mono">{meta.inputCount}</span> })
  } else {
    items.push({ key: 'Detail', value: <span className="c2-ink-3">loading…</span> })
  }
  if (verdict.kind === 'ok') {
    items.push({ key: 'Key id', value: <code>{verdict.keyId}</code> })
  }
  return items
}

// SealPanel re-expands the tamper-evidence verdict (re-condensed in pass 1):
// signature + hash result, plus an escalation note when the seal is broken.
function SealPanel({ verdict }: { verdict: Verdict }) {
  if (verdict.kind === 'idle') {
    return (
      <Panel title="Tamper evidence">
        <div className="c2-panel-pad">
          <p className="c2-ink-3" style={{ margin: 0, fontSize: 12.5 }}>
            Run <b>Verify WORM seal</b> to check the ed25519 signature + content hash of this sealed bundle.
          </p>
        </div>
      </Panel>
    )
  }
  if (verdict.kind === 'checking') {
    return (
      <Panel title="Tamper evidence">
        <div className="c2-panel-pad"><p className="c2-ink-3" style={{ margin: 0 }}>Verifying WORM seal…</p></div>
      </Panel>
    )
  }
  if (verdict.kind === 'error') {
    return (
      <Panel title="Tamper evidence">
        <div className="c2-panel-pad">
          <div className="c2-note c2-note-mute">
            <p className="c2-note-title">Verify error</p>
            <p className="c2-mono" style={{ margin: 0, fontSize: 12 }}>{verdict.msg}</p>
          </div>
        </div>
      </Panel>
    )
  }
  if (verdict.kind === 'ok') {
    return (
      <Panel title="Tamper evidence" actions={<StatusBadge tone="online">intact</StatusBadge>}>
        <KeyValueList items={[
          { key: 'Signature', value: <StatusBadge tone="online">valid</StatusBadge> },
          { key: 'Content hash', value: <StatusBadge tone="online">match</StatusBadge> },
          { key: 'Key id', value: <code>{verdict.keyId}</code> },
        ]} />
      </Panel>
    )
  }
  // broken — surface which check failed + escalation note.
  return (
    <Panel title="Tamper evidence" actions={<StatusBadge tone="danger">TAMPERED</StatusBadge>}>
      <div className="c2-panel-pad">
        <div className="c2-note c2-note-danger">
          <p className="c2-note-title">⚠ WORM seal broken</p>
          <p style={{ margin: '0 0 8px' }}>
            This recording failed verification. Escalate to security — do not treat the playback as authoritative.
          </p>
          <KeyValueList items={[
            { key: 'Signature', value: <StatusBadge tone={verdict.sig ? 'online' : 'danger'}>{verdict.sig ? 'valid' : 'invalid'}</StatusBadge> },
            { key: 'Content hash', value: <StatusBadge tone={verdict.hash ? 'online' : 'danger'}>{verdict.hash ? 'match' : 'mismatch'}</StatusBadge> },
          ]} />
        </div>
      </div>
    </Panel>
  )
}

function VerifyBadge({ verdict }: { verdict: Verdict }) {
  switch (verdict.kind) {
    case 'idle':
    case 'checking':
      return null
    case 'ok':
      return <StatusBadge tone="online">intact (key {verdict.keyId})</StatusBadge>
    case 'broken':
      return <StatusBadge tone="danger" title={`sig=${verdict.sig} hash=${verdict.hash}`}>TAMPERED</StatusBadge>
    case 'error':
      return <StatusBadge tone="danger">verify error: {verdict.msg}</StatusBadge>
  }
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

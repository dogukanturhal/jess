// Targets — the inventory catalog grid at /targets. Admins see the unified
// /api/admin/catalog; operators see targets derived from their own session +
// request history (same visibility the SPA always had). Supports the rail
// sub-row deep-links (?protocol=ssh|rdp|db) plus tag / criticality / protocol
// filters carried over from the old Admin → Targets tab.
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import {
  adminClearRecording,
  adminListCatalog,
  adminListRecordingSettings,
  adminSetRecording,
  type CatalogTarget,
  type RecordingSetting,
} from '../api/admin'
import { isAdmin, type Me } from '../api/me'
import { fetchMyRequests } from '../api/requests'
import { fetchMySessions } from '../api/sessions'
import { useMe } from '../hooks/useMe'
import { AppShell, Column, DataGrid, PageHeader, Panel, StatusBadge } from '../components/c2'
import { RequestForm } from '../components/RequestForm'
import { Dialog } from '../components/c2/Dialog'
import { CriticalityBadge, protocolGroupOf, SourceBadge, TargetConnect } from '../components/c2/TargetConnect'

export function Targets() {
  const auth = useMe()
  const me: Me | null = auth.kind === 'signed_in' ? auth.me : null
  return <AppShell>{me && <TargetsBody me={me} />}</AppShell>
}

function TargetsBody({ me }: { me: Me }) {
  const admin = isAdmin(me)
  const [params, setParams] = useSearchParams()
  const protoGroup = params.get('protocol') ?? '' // ssh | rdp | db (rail sub)
  const [rows, setRows] = useState<CatalogTarget[] | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [tagFilter, setTagFilter] = useState('')
  const [critFilter, setCritFilter] = useState('')
  const [protoFilter, setProtoFilter] = useState('')
  const [requestId, setRequestId] = useState<string | null>(null)
  // Per-target EFFECTIVE recording decision (admin override or catalog default),
  // keyed by target id. Admins toggle this inline (adminSetRecording) — it's the
  // catalog "Recording" control. Empty for non-admins.
  const [recSettings, setRecSettings] = useState<Record<string, RecordingSetting>>({})

  useEffect(() => {
    const ctrl = new AbortController()
    if (admin) {
      adminListCatalog(ctrl.signal)
        .then((r) => setRows(r ?? []))
        .catch((e) => { if (e?.name !== 'AbortError') setErr(e instanceof Error ? e.message : String(e)) })
      adminListRecordingSettings(ctrl.signal)
        .then((list) => {
          if (ctrl.signal.aborted) return
          const m: Record<string, RecordingSetting> = {}
          for (const s of list ?? []) m[s.target_id] = s
          setRecSettings(m)
        })
        .catch(() => { /* non-fatal — column falls back to catalog `recorded` */ })
    } else {
      Promise.allSettled([fetchMySessions(50, ctrl.signal), fetchMyRequests(ctrl.signal)]).then((res) => {
        if (ctrl.signal.aborted) return
        const seen = new Map<string, CatalogTarget>()
        const [s, r] = res
        if (s.status === 'fulfilled') for (const x of s.value) {
          if (x.target_id && !seen.has(x.target_id)) seen.set(x.target_id, { id: x.target_id, protocol: x.protocol ?? '', address: '', recorded: !!x.recording_path })
        }
        if (r.status === 'fulfilled') for (const x of r.value) {
          if (x.target_id && !seen.has(x.target_id)) seen.set(x.target_id, { id: x.target_id, protocol: '', address: '' })
        }
        setRows([...seen.values()])
      })
    }
    return () => ctrl.abort()
  }, [admin])

  const filtered = useMemo(() => {
    return (rows ?? []).filter((t) => {
      if (protoGroup && protocolGroupOf(t) !== protoGroup) return false
      if (critFilter && (t.criticality ?? '') !== critFilter) return false
      if (protoFilter && (t.protocol ?? '') !== protoFilter) return false
      if (tagFilter) {
        const hay = (t.tags ?? []).join(',').toLowerCase()
        if (!hay.includes(tagFilter.toLowerCase())) return false
      }
      return true
    })
  }, [rows, protoGroup, critFilter, protoFilter, tagFilter])

  const sourceCounts = useMemo(() => (rows ?? []).reduce<Record<string, number>>((acc, t) => {
    const s = t.source ?? 'unknown'; acc[s] = (acc[s] ?? 0) + 1; return acc
  }, {}), [rows])

  // Set a per-target recording override (admin). Optimistic; reconciles to the
  // server's returned effective value, reverts on failure.
  const setRecording = useCallback(async (id: string, recorded: boolean) => {
    const prev = recSettings[id]
    setRecSettings((m) => ({ ...m, [id]: { ...(prev ?? { target_id: id, catalog_default: recorded }), recorded, source: 'override' } }))
    try {
      const updated = await adminSetRecording(id, recorded)
      setRecSettings((m) => ({ ...m, [id]: updated }))
    } catch {
      setRecSettings((m) => ({ ...m, [id]: prev ?? { target_id: id, recorded: !recorded, source: 'catalog', catalog_default: !recorded } }))
    }
  }, [recSettings])

  // Clear the override → revert to the catalog (GitOps) default.
  const clearRecording = useCallback(async (id: string) => {
    try {
      const updated = await adminClearRecording(id)
      setRecSettings((m) => ({ ...m, [id]: updated }))
    } catch { /* leave as-is on failure */ }
  }, [])

  const columns: Column<CatalogTarget>[] = [
    { key: 'id', header: 'Target', sortValue: (t) => t.id, cell: (t) => <Link to={`/targets/${encodeURIComponent(t.id)}`} className="c2-grid-mono">{t.id}</Link> },
    ...(admin ? [{ key: 'source', header: 'Source', sortValue: (t: CatalogTarget) => t.source ?? '', cell: (t: CatalogTarget) => <SourceBadge source={t.source} /> }] : []),
    { key: 'protocol', header: 'Protocol', sortValue: (t) => t.protocol ?? '', cell: (t) => <span className="c2-grid-mute">{t.protocol || '—'}</span> },
    { key: 'address', header: 'Address', sortValue: (t) => t.address ?? '', cell: (t) => t.address ? <span className="c2-grid-mono">{t.address}</span> : <span className="c2-ink-3">—</span> },
    admin
      ? {
          key: 'recorded', header: 'Recording',
          sortValue: (t: CatalogTarget) => ((recSettings[t.id]?.recorded ?? t.recorded) ? 1 : 0),
          cell: (t: CatalogTarget) => (
            <RecordingCell
              setting={recSettings[t.id]}
              fallbackRecorded={!!t.recorded}
              onToggle={(v) => setRecording(t.id, v)}
              onRevert={() => clearRecording(t.id)}
            />
          ),
        }
      : { key: 'recorded', header: 'Recorded', sortValue: (t: CatalogTarget) => (t.recorded ? 1 : 0), cell: (t: CatalogTarget) => t.recorded ? <StatusBadge tone="online">on</StatusBadge> : <span className="c2-ink-3">—</span> },
    { key: 'criticality', header: 'Criticality', sortValue: (t) => t.criticality ?? '', cell: (t) => <CriticalityBadge value={t.criticality} /> },
    { key: 'tags', header: 'Tags', cell: (t) => (
      <>
        {(t.tags ?? []).slice(0, 4).map((tag) => <span key={tag} className="c2-tag">{tag}</span>)}
        {(t.tags ?? []).length > 4 && <span className="c2-ink-3">+{(t.tags ?? []).length - 4}</span>}
        {(t.tags ?? []).length === 0 && <span className="c2-ink-3">—</span>}
      </>
    ) },
    ...(admin ? [{ key: 'seen', header: 'Last seen', sortValue: (t: CatalogTarget) => t.last_seen ?? '', cell: (t: CatalogTarget) => <span className="c2-grid-mute">{t.last_seen ? new Date(t.last_seen).toLocaleString() : '—'}</span> }] : []),
  ]

  return (
    <div className="c2-page">
      <PageHeader
        crumbs={[{ label: 'Inventory', to: '/' }, { label: 'Targets' }]}
        title="Targets"
        badge={rows ? <StatusBadge tone="mute" dot={false}>{filtered.length}</StatusBadge> : undefined}
        subtitle={admin ? 'Every target jess can broker, merged across discovery providers' : 'Targets you have accessed'}
      />
      <div className="c2-page-body">
        <Panel
          title={protoGroup ? `Catalog · ${protoGroup.toUpperCase()}` : 'Catalog'}
          subtitle={admin && rows ? Object.entries(sourceCounts).sort().map(([s, n]) => `${s}: ${n}`).join(' · ') || undefined : undefined}
        >
          <div className="c2-toolbar">
            <input className="c2-input" type="search" placeholder="Filter by tag…" value={tagFilter} onChange={(e) => setTagFilter(e.target.value)} />
            <select className="c2-select" value={critFilter} onChange={(e) => setCritFilter(e.target.value)}>
              <option value="">All criticalities</option>
              <option value="low">low</option><option value="medium">medium</option>
              <option value="high">high</option><option value="critical">critical</option>
            </select>
            <select className="c2-select" value={protoFilter} onChange={(e) => setProtoFilter(e.target.value)}>
              <option value="">All protocols</option>
              <option value="ssh">ssh</option><option value="rdp">rdp</option>
              <option value="postgres">postgres</option><option value="mysql">mysql</option><option value="tcp">tcp</option>
            </select>
            {protoGroup && (
              <button className="c2-btn c2-btn-ghost c2-btn-sm" onClick={() => { const p = new URLSearchParams(params); p.delete('protocol'); setParams(p) }}>
                Clear {protoGroup.toUpperCase()} filter ✕
              </button>
            )}
          </div>
          {err ? (
            <div className="c2-grid-empty">Couldn't load catalog: {err}</div>
          ) : rows === null ? (
            <div className="c2-loading">Loading targets…</div>
          ) : (
            <DataGrid
              rows={filtered}
              columns={columns}
              rowKey={(t) => t.id}
              defaultSort={{ key: 'id', dir: 'asc' }}
              empty="No targets match the current filters."
              actions={(t) => <TargetConnect target={t} onRequestAccess={(id) => setRequestId(id)} />}
            />
          )}
        </Panel>
      </div>

      {requestId && (
        <Dialog title={`Request access — ${requestId}`} onClose={() => setRequestId(null)}>
          <p className="c2-field-hint">Submit a JIT grant request for <code>{requestId}</code> (or comma-separate more).</p>
          <RequestForm />
        </Dialog>
      )}
    </div>
  )
}

// RecordingCell — the admin per-target recording control in the Catalog. The
// toggle sets an override (adminSetRecording); the hint shows whether the current
// value is the GitOps catalog default or an admin override (with a revert link).
// Sessions honour the EFFECTIVE value (controller resolveEffectiveRecorded for
// SSH/DB; jess-web for RDP — ADR 0052), so this toggle actually changes whether a
// session records.
function RecordingCell({
  setting,
  fallbackRecorded,
  onToggle,
  onRevert,
}: {
  setting?: RecordingSetting
  fallbackRecorded: boolean
  onToggle: (recorded: boolean) => void
  onRevert: () => void
}) {
  const recorded = setting?.recorded ?? fallbackRecorded
  const isOverride = setting?.source === 'override'
  return (
    <div className="c2-rec-cell">
      <button
        type="button"
        role="switch"
        aria-checked={recorded}
        aria-label={recorded ? 'Recording enabled — click to disable' : 'Recording disabled — click to enable'}
        title={recorded ? 'Recording ON — click to disable for this target' : 'Recording OFF — click to enable for this target'}
        className={`c2-rec-toggle${recorded ? ' is-on' : ''}`}
        onClick={() => onToggle(!recorded)}
      >
        <span className="c2-rec-knob" aria-hidden="true" />
      </button>
      <span className="c2-rec-src">
        {isOverride ? (
          <>override · <button type="button" className="c2-linkbtn" onClick={onRevert}>revert to default</button></>
        ) : (
          'catalog default'
        )}
      </span>
    </div>
  )
}

// Overview — the signed-in inventory dashboard at /.
//
// KPI tiles (targets by protocol, live sessions, pending requests, recordings)
// + the Targets DataGrid (catalog for admins via /api/admin/catalog; the
// operator's accessible/recent targets derived from their own sessions +
// requests otherwise) + compact recent-sessions / recent-requests panels.
//
// Connect ▾ + Request-access actions reuse the existing routes/endpoints.
// Anonymous browsers never reach here — AppShell renders the C2 sign-in screen.
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { adminListCatalog, type CatalogTarget } from '../api/admin'
import { isAdmin, type Me } from '../api/me'
import { fetchMyRequests, type RequestView } from '../api/requests'
import { fetchMySessions, type SessionView } from '../api/sessions'
import { useMe } from '../hooks/useMe'
import {
  AppShell, Column, DataGrid, KpiRow, KpiTile, PageHeader, Panel, StatusBadge, StatusDot,
} from '../components/c2'
import { ConnectForm } from '../components/ConnectForm'
import { RequestForm } from '../components/RequestForm'
import { Dialog } from '../components/c2/Dialog'
import { CriticalityBadge, protocolGroupOf, TargetConnect } from '../components/c2/TargetConnect'

export function Overview() {
  const auth = useMe()
  const me: Me | null = auth.kind === 'signed_in' ? auth.me : null
  return (
    <AppShell>
      {me && <OverviewBody me={me} />}
    </AppShell>
  )
}

function OverviewBody({ me }: { me: Me }) {
  const admin = isAdmin(me)
  const [catalog, setCatalog] = useState<CatalogTarget[] | null>(null)
  const [catalogErr, setCatalogErr] = useState<string | null>(null)
  const [sessions, setSessions] = useState<SessionView[]>([])
  const [requests, setRequests] = useState<RequestView[]>([])
  const [dialog, setDialog] = useState<null | 'connect' | 'request'>(null)

  useEffect(() => {
    const ctrl = new AbortController()
    // Recent sessions + requests (operator-scoped; same endpoints as before).
    fetchMySessions(50, ctrl.signal).then(setSessions).catch(() => { /* best-effort */ })
    fetchMyRequests(ctrl.signal).then(setRequests).catch(() => { /* best-effort */ })
    return () => ctrl.abort()
  }, [])

  useEffect(() => {
    if (!admin) return
    const ctrl = new AbortController()
    adminListCatalog(ctrl.signal)
      .then((rows) => setCatalog(rows ?? []))
      .catch((e) => { if (e?.name !== 'AbortError') setCatalogErr(messageOf(e)) })
    return () => ctrl.abort()
  }, [admin])

  // Operator-visible target list when not admin: derive from their own
  // sessions + requests (the same data the connect/request autocomplete uses).
  const derivedTargets: CatalogTarget[] = useMemo(() => {
    if (admin) return catalog ?? []
    const seen = new Map<string, CatalogTarget>()
    for (const s of sessions) {
      if (!s.target_id) continue
      if (!seen.has(s.target_id)) {
        seen.set(s.target_id, { id: s.target_id, protocol: s.protocol ?? '', address: '', recorded: !!s.recording_path })
      }
    }
    for (const r of requests) {
      if (!r.target_id) continue
      if (!seen.has(r.target_id)) seen.set(r.target_id, { id: r.target_id, protocol: '', address: '' })
    }
    return [...seen.values()]
  }, [admin, catalog, sessions, requests])

  const counts = useMemo(() => {
    const base = admin ? (catalog ?? []) : derivedTargets
    const c = { total: base.length, ssh: 0, rdp: 0, db: 0, other: 0 }
    for (const t of base) {
      const g = protocolGroupOf(t)
      c[g]++
    }
    return c
  }, [admin, catalog, derivedTargets])

  const liveSessions = sessions.filter((s) => s.active).length
  const pending = requests.filter((r) => r.state === 'pending').length
  const recordings = sessions.filter((s) => !!s.recording_path).length

  return (
    <div className="c2-page">
      <PageHeader
        crumbs={[{ label: 'Inventory' }]}
        title="Overview"
        subtitle={admin ? 'Fleet-wide inventory + control surface' : `Signed in as ${me.email}`}
        actions={
          <>
            <button className="c2-btn c2-btn-ghost" onClick={() => setDialog('request')}>Request access</button>
            <button className="c2-btn c2-btn-primary" onClick={() => setDialog('connect')}>Open session</button>
          </>
        }
      />

      <div className="c2-page-body">
        <KpiRow>
          <KpiTile label="Targets" value={counts.total} hint={`${counts.ssh} SSH · ${counts.rdp} RDP · ${counts.db} DB`} icon="◫" to="/targets" />
          <KpiTile label="Live sessions" value={liveSessions} hint={`${sessions.length} total`} icon="◐" accent={liveSessions > 0} to={admin ? '/admin/sessions' : undefined} />
          <KpiTile label="Pending requests" value={pending} hint={admin ? 'awaiting your decision' : 'awaiting approval'} icon="✓" to={admin ? '/admin/requests' : undefined} />
          <KpiTile label="Recordings" value={recordings} hint="tamper-evident WORM" icon="▶" to="/rdp/recordings" />
        </KpiRow>

        <Panel
          title="Targets"
          subtitle={admin ? 'Merged across every discovery provider' : 'Targets you have touched recently'}
          actions={admin ? <Link to="/admin/catalog" className="c2-btn c2-btn-ghost c2-btn-sm">Full catalog →</Link> : undefined}
        >
          {catalogErr ? (
            <div className="c2-grid-empty">Couldn't load catalog: {catalogErr}</div>
          ) : (
            <TargetsOverviewGrid
              rows={derivedTargets}
              loading={admin && catalog === null}
              onRequestAccess={(id) => { setDialog('request'); void id }}
            />
          )}
        </Panel>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16 }}>
          <Panel title="Recent sessions" subtitle="Your last brokered sessions">
            <RecentSessionsGrid rows={sessions.slice(0, 8)} />
          </Panel>
          <Panel title="Recent requests" subtitle="Your last grant requests">
            <RecentRequestsGrid rows={[...requests].sort((a, b) => b.requested_at.localeCompare(a.requested_at)).slice(0, 8)} />
          </Panel>
        </div>
      </div>

      {dialog === 'connect' && (
        <Dialog title="Open a session" onClose={() => setDialog(null)}>
          <p className="c2-field-hint">Use a JIT grant you already hold, or admin direct-connect (platform_admin + MFA).</p>
          <ConnectForm />
        </Dialog>
      )}
      {dialog === 'request' && (
        <Dialog title="Request access" onClose={() => setDialog(null)}>
          <p className="c2-field-hint">Submit a JIT grant request. Your approver is paged; you get an id to track.</p>
          <RequestForm />
        </Dialog>
      )}
    </div>
  )
}

function TargetsOverviewGrid({
  rows, loading, onRequestAccess,
}: {
  rows: CatalogTarget[]; loading: boolean; onRequestAccess: (id: string) => void
}) {
  if (loading) return <div className="c2-loading">Loading targets…</div>
  const columns: Column<CatalogTarget>[] = [
    {
      key: 'id', header: 'Target',
      sortValue: (t) => t.id,
      cell: (t) => <Link to={`/targets/${encodeURIComponent(t.id)}`} className="c2-grid-mono">{t.id}</Link>,
    },
    {
      key: 'protocol', header: 'Protocol', sortValue: (t) => t.protocol ?? '',
      cell: (t) => <span className="c2-grid-mute">{t.protocol || '—'}</span>,
    },
    {
      key: 'address', header: 'Address', sortValue: (t) => t.address ?? '',
      cell: (t) => t.address ? <span className="c2-grid-mono">{t.address}</span> : <span className="c2-ink-3">—</span>,
    },
    {
      key: 'recorded', header: 'Recorded', sortValue: (t) => (t.recorded ? 1 : 0),
      cell: (t) => t.recorded
        ? <StatusBadge tone="online">on</StatusBadge>
        : <span className="c2-ink-3">—</span>,
    },
    {
      key: 'criticality', header: 'Criticality', sortValue: (t) => t.criticality ?? '',
      cell: (t) => <CriticalityBadge value={t.criticality} />,
    },
  ]
  return (
    <DataGrid
      rows={rows}
      columns={columns}
      rowKey={(t) => t.id}
      defaultSort={{ key: 'id', dir: 'asc' }}
      empty="No targets yet. Open or request a session to populate your inventory."
      actions={(t) => <TargetConnect target={t} onRequestAccess={onRequestAccess} />}
    />
  )
}

function RecentSessionsGrid({ rows }: { rows: SessionView[] }) {
  const columns: Column<SessionView>[] = [
    {
      key: 'target', header: 'Target', sortValue: (s) => s.target_id,
      cell: (s) => (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
          <StatusDot tone={s.active ? 'online' : 'offline'} pulse={s.active} />
          <Link to={`/targets/${encodeURIComponent(s.target_id)}`} className="c2-grid-mono">{s.target_id}</Link>
        </span>
      ),
    },
    { key: 'proto', header: 'Proto', cell: (s) => <span className="c2-grid-mute">{s.protocol || '—'}</span> },
    {
      key: 'dur', header: 'Duration', numeric: true, sortValue: (s) => s.duration_seconds,
      cell: (s) => <span className="c2-grid-mute">{fmtDur(s.duration_seconds)}{s.active ? ' live' : ''}</span>,
    },
    {
      key: 'rec', header: '', cell: (s) => s.recording_path
        ? <Link to={`/recordings/${encodeURIComponent(s.id)}`} title="Play recording">▶</Link>
        : null,
    },
  ]
  return <DataGrid rows={rows} columns={columns} rowKey={(s) => s.id} empty="No sessions yet." />
}

function RecentRequestsGrid({ rows }: { rows: RequestView[] }) {
  const columns: Column<RequestView>[] = [
    { key: 'target', header: 'Target', sortValue: (r) => r.target_id, cell: (r) => <span className="c2-grid-mono">{r.target_id}</span> },
    { key: 'state', header: 'State', cell: (r) => <RequestStateBadge state={r.state} /> },
    {
      key: 'when', header: 'When', numeric: true, sortValue: (r) => r.requested_at,
      cell: (r) => <span className="c2-grid-mute">{fmtWhen(r.requested_at)}</span>,
    },
  ]
  return <DataGrid rows={rows} columns={columns} rowKey={(r) => r.id} empty="No requests yet." />
}

export function RequestStateBadge({ state }: { state: string }) {
  const tone =
    state === 'approved' ? 'online' :
    state === 'denied' ? 'danger' :
    state === 'pending' ? 'warn' : 'mute'
  return <StatusBadge tone={tone as 'online' | 'danger' | 'warn' | 'mute'}>{state}</StatusBadge>
}

export function fmtDur(sec: number): string {
  if (sec < 60) return `${Math.max(0, Math.floor(sec))}s`
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${Math.floor(sec % 60)}s`
  return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`
}
export function fmtWhen(iso: string): string {
  const t = new Date(iso)
  if (Number.isNaN(t.getTime())) return iso
  const diff = (Date.now() - t.getTime()) / 1000
  if (diff < 60) return 'just now'
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return t.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}
function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

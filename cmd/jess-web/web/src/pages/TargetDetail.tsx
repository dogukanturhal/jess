// TargetDetail — object-detail view at /targets/:id.
//
// DetailTabs: Summary (KeyValueList from catalog/derived data), Sessions
// (datagrid of this target's sessions), Recordings (datagrid → playback),
// ACL/Policy (best-effort from available data — grants for this target if
// the caller is admin, else a note). Connect ▾ in the page header.
//
// Data sources, all existing endpoints:
//   /api/admin/catalog        (admin) → target metadata
//   fetchMySessions()         → this operator's sessions, filtered to :id
//   adminListSessions()       (admin) → fleet sessions, filtered to :id
//   adminListGrants()         (admin) → ACL tab grants, filtered to :id
import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { adminListCatalog, adminListGrants, adminListSessions, type CatalogTarget, type GrantView } from '../api/admin'
import { isAdmin, type Me } from '../api/me'
import { fetchMySessions, type SessionView } from '../api/sessions'
import { useMe } from '../hooks/useMe'
import {
  AppShell, Column, DataGrid, DetailTabs, KeyValueList, PageHeader, Panel, StatusBadge, StatusDot,
} from '../components/c2'
import { CriticalityBadge, SourceBadge, TargetConnect } from '../components/c2/TargetConnect'
import { fmtDur, fmtWhen } from './Overview'

type TabKey = 'summary' | 'sessions' | 'recordings' | 'acl'

export function TargetDetail() {
  const auth = useMe()
  const me: Me | null = auth.kind === 'signed_in' ? auth.me : null
  return <AppShell>{me && <TargetDetailBody me={me} />}</AppShell>
}

function TargetDetailBody({ me }: { me: Me }) {
  const { id = '' } = useParams<{ id: string }>()
  const admin = isAdmin(me)
  const [tab, setTab] = useState<TabKey>('summary')
  const [target, setTarget] = useState<CatalogTarget | null>(null)
  const [sessions, setSessions] = useState<SessionView[]>([])
  const [grants, setGrants] = useState<GrantView[] | null>(null)

  useEffect(() => {
    const ctrl = new AbortController()
    if (admin) {
      adminListCatalog(ctrl.signal).then((rows) => {
        const hit = rows.find((t) => t.id === id)
        if (hit) setTarget(hit)
      }).catch(() => { /* best-effort */ })
      adminListSessions(ctrl.signal).then((rows) => setSessions(rows.filter((s) => s.target_id === id))).catch(() => { /* best-effort */ })
      adminListGrants(ctrl.signal).then((rows) => setGrants(rows.filter((g) => g.target_id === id))).catch(() => setGrants([]))
    } else {
      fetchMySessions(50, ctrl.signal).then((rows) => setSessions(rows.filter((s) => s.target_id === id))).catch(() => { /* best-effort */ })
    }
    return () => ctrl.abort()
  }, [admin, id])

  // Fall back to deriving protocol/recorded from this target's sessions if the
  // catalog entry isn't available (e.g. operator without catalog access).
  const resolved: CatalogTarget = useMemo(() => {
    if (target) return target
    const s = sessions[0]
    return { id, protocol: s?.protocol ?? '', address: '', recorded: sessions.some((x) => !!x.recording_path) }
  }, [target, sessions, id])

  const recordings = sessions.filter((s) => !!s.recording_path)
  const live = sessions.some((s) => s.active)

  return (
    <div className="c2-page">
      <PageHeader
        crumbs={[{ label: 'Inventory', to: '/' }, { label: 'Targets', to: '/targets' }, { label: id }]}
        title={<span className="c2-mono">{id}</span>}
        badge={<StatusBadge tone={live ? 'online' : 'mute'} title={live ? 'live session active' : 'no live session'}>{live ? 'live' : 'idle'}</StatusBadge>}
        subtitle={resolved.protocol ? `${resolved.protocol} target` : undefined}
        actions={<TargetConnect target={resolved} size="md" />}
      />
      <div className="c2-page-body">
        <Panel>
          <DetailTabs
            active={tab}
            onChange={(k) => setTab(k as TabKey)}
            tabs={[
              { key: 'summary', label: 'Summary' },
              { key: 'sessions', label: 'Sessions', count: sessions.length },
              { key: 'recordings', label: 'Recordings', count: recordings.length },
              { key: 'acl', label: 'ACL' },
            ]}
          />
          {tab === 'summary' && <SummaryTab t={resolved} admin={admin} live={live} sessionCount={sessions.length} />}
          {tab === 'sessions' && <SessionsTab rows={sessions} />}
          {tab === 'recordings' && <RecordingsTab rows={recordings} />}
          {tab === 'acl' && <AclTab grants={grants} admin={admin} />}
        </Panel>
      </div>
    </div>
  )
}

function SummaryTab({ t, admin, live, sessionCount }: { t: CatalogTarget; admin: boolean; live: boolean; sessionCount: number }) {
  return (
    <KeyValueList items={[
      { key: 'Target id', value: <span className="c2-mono">{t.id}</span> },
      { key: 'Name', value: t.name ?? <span className="c2-ink-3">—</span> },
      { key: 'Protocol', value: t.protocol || <span className="c2-ink-3">—</span> },
      { key: 'Address', value: t.address ? <span className="c2-mono">{t.address}</span> : <span className="c2-ink-3">—</span> },
      { key: 'Region', value: t.region ?? <span className="c2-ink-3">—</span> },
      { key: 'Recorded', value: t.recorded ? <StatusBadge tone="online">on</StatusBadge> : <span className="c2-ink-3">off</span> },
      { key: 'Criticality', value: <CriticalityBadge value={t.criticality} /> },
      { key: 'Tags', value: (t.tags ?? []).length ? (t.tags ?? []).map((x) => <span key={x} className="c2-tag">{x}</span>) : <span className="c2-ink-3">—</span> },
      ...(admin ? [
        { key: 'Source', value: <SourceBadge source={t.source} /> },
        { key: 'Last seen', value: t.last_seen ? new Date(t.last_seen).toLocaleString() : <span className="c2-ink-3">—</span> },
      ] : []),
      { key: 'Live now', value: live ? <StatusBadge tone="online">live</StatusBadge> : <span className="c2-ink-3">no</span> },
      { key: 'Sessions seen', value: sessionCount },
    ]} />
  )
}

function SessionsTab({ rows }: { rows: SessionView[] }) {
  const columns: Column<SessionView>[] = [
    { key: 'state', header: '', width: 24, cell: (s) => <StatusDot tone={s.active ? 'online' : 'offline'} pulse={s.active} /> },
    { key: 'id', header: 'Session', sortValue: (s) => s.id, cell: (s) => <span className="c2-grid-mono">{s.id.slice(0, 16)}…</span> },
    { key: 'subject', header: 'Operator', sortValue: (s) => s.subject, cell: (s) => <span className="c2-grid-mute">{s.subject}</span> },
    { key: 'proto', header: 'Proto', cell: (s) => <span className="c2-grid-mute">{s.protocol || '—'}</span> },
    { key: 'dur', header: 'Duration', numeric: true, sortValue: (s) => s.duration_seconds, cell: (s) => <span className="c2-grid-mute">{fmtDur(s.duration_seconds)}{s.active ? ' live' : ''}</span> },
    { key: 'when', header: 'Started', numeric: true, sortValue: (s) => s.started_at, cell: (s) => <span className="c2-grid-mute">{fmtWhen(s.started_at)}</span> },
  ]
  return (
    <DataGrid rows={rows} columns={columns} rowKey={(s) => s.id} defaultSort={{ key: 'when', dir: 'desc' }}
      empty="No sessions recorded for this target."
      actions={(s) => s.recording_path ? <Link className="c2-btn c2-btn-ghost c2-btn-sm" to={`/recordings/${encodeURIComponent(s.id)}`}>▶ Play</Link> : null}
    />
  )
}

function RecordingsTab({ rows }: { rows: SessionView[] }) {
  const columns: Column<SessionView>[] = [
    { key: 'id', header: 'Session', sortValue: (s) => s.id, cell: (s) => <span className="c2-grid-mono">{s.id.slice(0, 20)}…</span> },
    { key: 'path', header: 'Bundle', cell: (s) => <span className="c2-grid-mono c2-grid-mute">{s.recording_path}</span> },
    { key: 'when', header: 'Started', numeric: true, sortValue: (s) => s.started_at, cell: (s) => <span className="c2-grid-mute">{fmtWhen(s.started_at)}</span> },
  ]
  return (
    <DataGrid rows={rows} columns={columns} rowKey={(s) => s.id} defaultSort={{ key: 'when', dir: 'desc' }}
      empty="No recordings for this target."
      actions={(s) => <Link className="c2-btn c2-btn-primary c2-btn-sm" to={`/recordings/${encodeURIComponent(s.id)}`}>▶ Play</Link>}
    />
  )
}

function AclTab({ grants, admin }: { grants: GrantView[] | null; admin: boolean }) {
  if (!admin) {
    return (
      <div style={{ padding: 16 }}>
        <div className="c2-note c2-note-mute">
          Access for this target is governed by JIT grants. Request access from the
          target's Connect ▾ menu; admins manage live grants in <Link to="/admin/grants">Grants</Link>.
        </div>
      </div>
    )
  }
  if (grants === null) return <div className="c2-loading">Loading grants…</div>
  const columns: Column<GrantView>[] = [
    { key: 'subject', header: 'Subject', sortValue: (g) => g.subject, cell: (g) => <span className="c2-grid-mute">{g.subject}</span> },
    { key: 'id', header: 'Grant', cell: (g) => <span className="c2-grid-mono">{g.id.slice(0, 16)}…</span> },
    { key: 'by', header: 'Approved by', cell: (g) => <span className="c2-grid-mute">{g.approved_by}</span> },
    { key: 'exp', header: 'Expires', numeric: true, sortValue: (g) => g.expires_at, cell: (g) => <span className="c2-grid-mute">{new Date(g.expires_at).toLocaleString()}</span> },
  ]
  return <DataGrid rows={grants} columns={columns} rowKey={(g) => g.id} empty="No active grants for this target." />
}

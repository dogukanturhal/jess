// Discovery review queue — ADR 0052 Phase F. Auto-discovered candidates land in
// the JessPendingTarget queue (phase=Pending, audit-only) and an admin approves
// (→ brokerable JessTarget) or rejects them here. Tier-0 RDP candidates can't be
// approved (the controller enforces the hard-guard; the UI disables the action).
import { useCallback, useEffect, useState } from 'react'
import {
  adminApprovePending,
  adminListPending,
  adminRejectPending,
  type PendingCandidate,
} from '../api/admin'
import { isAdmin, type Me } from '../api/me'
import { useMe } from '../hooks/useMe'
import { AppShell, Button, Column, DataGrid, PageHeader, Panel, StatusBadge } from '../components/c2'
import { CriticalityBadge } from '../components/c2/TargetConnect'

export function Pending() {
  const auth = useMe()
  const me: Me | null = auth.kind === 'signed_in' ? auth.me : null
  return <AppShell>{me && <PendingBody me={me} />}</AppShell>
}

function PendingBody({ me }: { me: Me }) {
  const admin = isAdmin(me)
  const [rows, setRows] = useState<PendingCandidate[] | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState<Record<string, boolean>>({})

  const load = useCallback(() => {
    const ctrl = new AbortController()
    adminListPending(ctrl.signal)
      .then((r) => setRows(r ?? []))
      .catch((e) => { if (e?.name !== 'AbortError') setErr(e instanceof Error ? e.message : String(e)) })
    return () => ctrl.abort()
  }, [])
  useEffect(() => { if (admin) return load() }, [admin, load])

  const act = async (name: string, action: 'approve' | 'reject') => {
    setBusy((b) => ({ ...b, [name]: true }))
    setErr(null)
    try {
      if (action === 'approve') await adminApprovePending(name)
      else await adminRejectPending(name)
      setRows((rs) => (rs ?? []).filter((r) => r.name !== name)) // optimistic remove
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
      load() // reconcile to server truth on failure
    } finally {
      setBusy((b) => ({ ...b, [name]: false }))
    }
  }

  if (!admin) {
    return (
      <div className="c2-page"><div className="c2-page-body">
        <div className="c2-note c2-note-warn">platform_admin required to review discovered targets.</div>
      </div></div>
    )
  }

  const pending = (rows ?? []).filter((t) => (t.phase ?? 'Pending') === 'Pending')

  const columns: Column<PendingCandidate>[] = [
    { key: 'name', header: 'Candidate', sortValue: (t) => t.name, cell: (t) => <span className="c2-grid-mono">{t.name}</span> },
    { key: 'protocol', header: 'Protocol', sortValue: (t) => t.protocol, cell: (t) => <span className="c2-grid-mute">{t.protocol}</span> },
    { key: 'criticality', header: 'Criticality', sortValue: (t) => t.criticality ?? '', cell: (t) => <CriticalityBadge value={t.criticality} /> },
    { key: 'address', header: 'Address', sortValue: (t) => t.address, cell: (t) => <span className="c2-grid-mono">{t.address}</span> },
    { key: 'source', header: 'Source', sortValue: (t) => t.source ?? '', cell: (t) => <span className="c2-grid-mute">{t.source || '—'}</span> },
  ]

  return (
    <div className="c2-page">
      <PageHeader
        crumbs={[{ label: 'Control', to: '/' }, { label: 'Discovery review' }]}
        title="Discovery review"
        badge={rows ? <StatusBadge tone="mute" dot={false}>{pending.length}</StatusBadge> : undefined}
        subtitle="Auto-discovered candidates awaiting approval (audit-only — nothing is brokerable until approved)"
      />
      <div className="c2-page-body">
        <Panel
          title="Pending candidates"
          actions={<Button variant="ghost" size="sm" onClick={load}>Refresh</Button>}
        >
          {err && <div className="c2-note c2-note-danger" style={{ marginBottom: 10 }}>{err}</div>}
          {rows === null ? (
            <div className="c2-loading">Loading review queue…</div>
          ) : pending.length === 0 ? (
            <div className="c2-grid-empty">No candidates awaiting review. New discoveries appear here.</div>
          ) : (
            <DataGrid
              rows={pending}
              columns={columns}
              rowKey={(t) => t.name}
              defaultSort={{ key: 'name', dir: 'asc' }}
              empty="No candidates awaiting review."
              actions={(t) => {
                const tier0RDP = t.protocol === 'rdp' && t.criticality === 'critical'
                return (
                  <span style={{ display: 'inline-flex', gap: 6 }}>
                    <Button
                      variant="primary"
                      size="sm"
                      disabled={busy[t.name] || tier0RDP}
                      title={tier0RDP ? 'Tier-0 RDP can never be brokered (ADR 0052 hard-guard)' : 'Promote to a brokerable target'}
                      onClick={() => act(t.name, 'approve')}
                    >
                      Approve
                    </Button>
                    <Button variant="danger" size="sm" disabled={busy[t.name]} onClick={() => act(t.name, 'reject')}>
                      Reject
                    </Button>
                  </span>
                )
              }}
            />
          )}
        </Panel>
      </div>
    </div>
  )
}

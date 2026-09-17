// ConnectResolver — the grant-aware "Connect" flow.
//
// THE PROBLEM IT SOLVES: production access is grant-gated (ZSP — zero standing
// privilege). /ws/rdp-live rejects an empty grant ("a grant id is required"),
// and the gateway strips the WS close-frame reason, so the old grant-less
// "Connect → RDP" deep-link always fail-closed as a confusing generic
// "WebSocket transport error". This dialog RESOLVES a grant before it ever
// opens the console, so the operator lands on a working session — or a clear,
// actionable explanation of why they can't yet.
//
// FLOW (all over existing endpoints — no backend change):
//   1. List the operator's active grants for this target — derived from
//      /api/my/requests (state=approved, grant_id present, target matches,
//      expires_at in the future). Pick one → navigate to the console with
//      ?grant=<id>.
//   2. If none active → offer "Request access" (reuses the RequestForm submit +
//      approval polling; the moment a request is approved its grant surfaces in
//      the list above, ready to Connect) AND, for platform_admin, "Issue grant
//      (admin)" which mints a grant for me.subject + connects immediately.
//   3. Always show WHY a grant is needed (grant-gated / ZSP) + the target +
//      protocol, so the gate is legible instead of a silent failure.
//
// Accessibility: hosted in the shared <Dialog> (focus lands on the first
// control, Esc + backdrop close, aria-modal). All actions are buttons/inputs
// reachable by keyboard.
import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Dialog } from './c2/Dialog'
import { Button } from './c2/Button'
import { StatusBadge } from './c2'
import { adminIssueGrant, AdminError } from '../api/admin'
import { isAdmin, type Me } from '../api/me'
import {
  activeGrantsForTarget,
  fetchMyRequests,
  GrantsError,
  type RequestView,
} from '../api/requests'
import { RequestForm } from './RequestForm'

// Protocol metadata for the dialog header + console routing.
type ProtoKind = 'ssh' | 'rdp' | 'db'

function classifyProto(proto: string): ProtoKind | null {
  const p = proto.toLowerCase()
  if (p === 'ssh') return 'ssh'
  if (p === 'rdp') return 'rdp'
  if (p === 'postgres' || p === 'mysql') return 'db'
  return null
}

const PROTO_LABEL: Record<ProtoKind, string> = {
  ssh: 'SSH session',
  rdp: 'RDP desktop',
  db: 'database console',
}

// Build the console URL for a resolved grant. The console pages all read
// ?grant= (RDP.tsx, Session, DBConsole) and open the WS there, so a refresh
// re-creates the connection cleanly.
function consoleHref(kind: ProtoKind, targetId: string, grantId: string, rawProto: string): string {
  const t = encodeURIComponent(targetId)
  const g = encodeURIComponent(grantId)
  switch (kind) {
    case 'ssh':
      return `/session?target=${t}&grant=${g}`
    case 'rdp':
      return `/rdp/${t}?grant=${g}`
    case 'db':
      return `/db-console?target=${t}&protocol=${encodeURIComponent(rawProto.toLowerCase())}&grant=${g}`
  }
}

// Time-left label for a grant, e.g. "expires in 27m".
function expiresIn(iso: string, now = Date.now()): string {
  const ms = new Date(iso).getTime() - now
  if (Number.isNaN(ms)) return iso
  if (ms <= 0) return 'expired'
  const mins = Math.floor(ms / 60000)
  if (mins < 1) return 'expires in <1m'
  if (mins < 60) return `expires in ${mins}m`
  const h = Math.floor(mins / 60)
  return `expires in ${h}h ${mins % 60}m`
}

type LoadState =
  | { kind: 'loading' }
  | { kind: 'ready'; grants: RequestView[] }
  | { kind: 'err'; msg: string }

type IssueState =
  | { kind: 'idle' }
  | { kind: 'issuing' }
  | { kind: 'err'; msg: string }

export function ConnectResolver({
  target,
  me,
  onClose,
}: {
  target: { id: string; protocol?: string }
  me: Me | null
  onClose: () => void
}) {
  const navigate = useNavigate()
  const kind = classifyProto(target.protocol ?? '')
  const rawProto = (target.protocol ?? '').toLowerCase()
  const admin = isAdmin(me)

  const [state, setState] = useState<LoadState>({ kind: 'loading' })
  const [issue, setIssue] = useState<IssueState>({ kind: 'idle' })
  const [adminTtlMin, setAdminTtlMin] = useState(30)
  const [showRequest, setShowRequest] = useState(false)
  const abortRef = useRef<AbortController | null>(null)

  const reload = useCallback(() => {
    abortRef.current?.abort()
    const ctrl = new AbortController()
    abortRef.current = ctrl
    setState({ kind: 'loading' })
    fetchMyRequests(ctrl.signal)
      .then((reqs) => {
        if (ctrl.signal.aborted) return
        setState({ kind: 'ready', grants: activeGrantsForTarget(reqs, target.id) })
      })
      .catch((e: unknown) => {
        if (ctrl.signal.aborted) return
        const msg = e instanceof GrantsError ? e.message : e instanceof Error ? e.message : String(e)
        setState({ kind: 'err', msg })
      })
  }, [target.id])

  useEffect(() => {
    reload()
    return () => abortRef.current?.abort()
  }, [reload])

  // Re-poll for newly-approved grants while the dialog is open, so a request
  // approved out-of-band (or via the in-dialog RequestForm) surfaces its grant
  // here without the operator reopening the dialog.
  useEffect(() => {
    const t = window.setInterval(() => {
      if (document.hidden) return
      reload()
    }, 5000)
    return () => window.clearInterval(t)
  }, [reload])

  const goConnect = useCallback(
    (grantId: string) => {
      if (!kind) return
      onClose()
      navigate(consoleHref(kind, target.id, grantId, rawProto))
    },
    [kind, navigate, onClose, rawProto, target.id],
  )

  async function onIssueAdmin() {
    if (!me) return
    setIssue({ kind: 'issuing' })
    try {
      const grant = await adminIssueGrant(me.subject, target.id, adminTtlMin * 60)
      if (grant.grant_id) goConnect(grant.grant_id)
      else setIssue({ kind: 'err', msg: 'grant issued but no grant id was returned' })
    } catch (e) {
      const msg = e instanceof AdminError ? `${e.status === 403 ? 'forbidden' : `HTTP ${e.status}`}: ${e.message}` : e instanceof Error ? e.message : String(e)
      setIssue({ kind: 'err', msg })
    }
  }

  const protoLabel = kind ? PROTO_LABEL[kind] : (target.protocol ?? 'this protocol')
  const title = <span>Connect — <span className="c2-mono">{target.id}</span></span>

  // Non-brokered protocols (tcp, etc.) have no web console — say so plainly.
  if (!kind) {
    return (
      <Dialog title={title} onClose={onClose} width={520}>
        <div className="c2-note c2-note-mute">
          <p className="c2-note-title">No web console for <code>{target.protocol || 'this protocol'}</code></p>
          <p style={{ margin: 0 }}>
            Use the jessctl CLI: <code className="c2-mono">jessctl {rawProto || 'tcp'}-bridge {target.id}</code>.
            It resolves a grant the same way (request access first if you don't hold one).
          </p>
        </div>
      </Dialog>
    )
  }

  const grants = state.kind === 'ready' ? state.grants : []
  const hasGrants = grants.length > 0

  return (
    <Dialog
      title={title}
      onClose={onClose}
      width={560}
      footer={
        <>
          <span className="c2-eyebrow">grant-gated · zero standing privilege</span>
          <span className="c2-toolbar-spacer" />
          <Button variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
        </>
      }
    >
      {/* WHY a grant is needed — keep the gate legible. */}
      <div className="c2-note c2-note-info" role="note">
        <p className="c2-note-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <StatusBadge tone="info" dot={false}>{rawProto.toUpperCase()}</StatusBadge>
          {protoLabel} on <span className="c2-mono">{target.id}</span>
        </p>
        <p style={{ margin: 0 }}>
          This target is <strong>grant-gated</strong>. The broker rejects a connection
          without an active just-in-time grant — pick one below, or request/issue access.
        </p>
      </div>

      {state.kind === 'loading' && <div className="c2-loading">Resolving your active grants…</div>}
      {state.kind === 'err' && (
        <div className="c2-note c2-note-danger" role="alert">
          <p className="c2-note-title">Couldn't load your grants</p>
          <p style={{ margin: 0 }}>{state.msg}</p>
          <p style={{ margin: '8px 0 0' }}>
            <Button variant="ghost" size="sm" onClick={reload}>Retry</Button>
          </p>
        </div>
      )}

      {state.kind === 'ready' && (
        <>
          {hasGrants ? (
            <div>
              <p className="c2-eyebrow" style={{ marginBottom: 8 }}>your active grants for this target</p>
              <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
                {grants.map((g) => (
                  <li
                    key={g.grant_id}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 10,
                      padding: '8px 10px', borderRadius: 6, border: '1px solid var(--hxm-line)',
                    }}
                  >
                    <StatusBadge tone="online">approved</StatusBadge>
                    <span className="c2-mono c2-ink-1" title={g.grant_id}>{(g.grant_id ?? '').slice(0, 12)}…</span>
                    <span className="c2-ink-3" style={{ fontSize: 11.5 }}>{expiresIn(g.expires_at)}</span>
                    <span className="c2-toolbar-spacer" style={{ marginLeft: 'auto' }} />
                    <Button variant="primary" size="sm" onClick={() => goConnect(g.grant_id!)}>Connect →</Button>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <div className="c2-note c2-note-warn" role="status">
              <p className="c2-note-title">No active grant for this target</p>
              <p style={{ margin: 0 }}>
                You don't currently hold a grant for <span className="c2-mono">{target.id}</span>.
                {admin ? ' Issue one directly below.' : ' Request access below.'}
              </p>
            </div>
          )}

          {/* Paths to obtain a grant. Admins lead with — and ONLY get — the
              self-issue flow (filing a request for an admin to approve is the
              detour we removed). Non-admins get the request-access path. */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {admin ? (
              <div>
                <p className="c2-eyebrow" style={{ marginBottom: 8 }}>issue grant (admin)</p>
                <p className="c2-field-hint" style={{ marginBottom: 8 }}>
                  Mint a grant for yourself (<span className="c2-mono">{me?.subject}</span>) and connect immediately.
                  Recorded as an admin direct-connect in the audit chain.
                </p>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  <label htmlFor="cr-admin-ttl" className="c2-field-hint" style={{ margin: 0 }}>TTL (min)</label>
                  <input
                    id="cr-admin-ttl"
                    className="c2-input"
                    type="number"
                    min={1}
                    max={1440}
                    value={adminTtlMin}
                    onChange={(e) => setAdminTtlMin(Number(e.target.value) || 30)}
                    style={{ width: 70, height: 28 }}
                    disabled={issue.kind === 'issuing'}
                  />
                  <Button
                    variant="primary"
                    size="sm"
                    onClick={onIssueAdmin}
                    disabled={issue.kind === 'issuing'}
                  >
                    {issue.kind === 'issuing' ? 'Issuing…' : 'Issue grant & connect →'}
                  </Button>
                </div>
                {issue.kind === 'err' && (
                  <div className="c2-note c2-note-danger" role="alert" style={{ marginTop: 10 }}>{issue.msg}</div>
                )}
              </div>
            ) : !showRequest ? (
              /* Request access — reuses the RequestForm submit + approval polling.
                 When the request is approved, the 5s reload above surfaces the new
                 grant in the list, ready to Connect. */
              <Button variant="ghost" size="sm" onClick={() => setShowRequest(true)} style={{ alignSelf: 'flex-start' }}>
                Request access…
              </Button>
            ) : (
              <div>
                <p className="c2-eyebrow" style={{ marginBottom: 8 }}>request a just-in-time grant</p>
                <RequestForm initialTarget={target.id} compact />
                <p className="c2-field-hint" style={{ marginTop: 8 }}>
                  Once an approver grants it, the grant appears above — click Connect to open the {protoLabel}.
                </p>
              </div>
            )}
          </div>
        </>
      )}
    </Dialog>
  )
}

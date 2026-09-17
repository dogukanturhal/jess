// Request access form — Phase 5e-3 (submit) + 5e-4 (polling) + 5e-12
// (multi-target fan-out, SPA-only — no schema change).
//
// Operator can ask for access to N targets in one submit. We send N
// parallel POST /api/requests (one per target id, sharing the same
// reason text), then poll every non-terminal request id and render a
// row per target with its own state pill + grant id.
//
// Why SPA-only fan-out, not jit_requests.target_ids text[] column:
//   * each target keeps its own audit row (1:1 request:grant) — better
//     SOC 2 evidence than a synthetic batch row
//   * no DB migration risk on in-flight rows
//   * controller HTTP API stays single-target — jessctl + admin CLIs
//     don't need to know about the batch concept
//   * admin approve/deny semantics unchanged (still one row at a time;
//     a future Admin SPA "approve all by submitter+reason within 30s"
//     button is pure UI sugar)
//
// Polling cadence per request (unchanged from 5e-4):
//   - 2s for the first 60s
//   - 8s after that
//   - Stops on terminal state OR after 30min
import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { GrantsError, fetchRequest, isTerminalState, submitRequest, type RequestView } from '../api/requests'
import { useTargetSuggestions } from '../hooks/useTargetSuggestions'
import { notify, requestPermissionOnce } from '../lib/notify'

type Outcome =
  | { kind: 'idle' }
  | { kind: 'submitting' }
  | { kind: 'tracking'; reqs: Record<string, RequestView>; order: string[]; failed: SubmitFailure[] }
  | { kind: 'err'; status: number; msg: string }

interface SubmitFailure {
  target: string
  status: number
  msg: string
}

const POLL_FAST_MS = 2_000
const POLL_FAST_BUDGET_MS = 60_000
const POLL_SLOW_MS = 8_000
const POLL_TOTAL_BUDGET_MS = 30 * 60_000

// Split the operator's free-form target field into a clean,
// deduplicated array. Accepts comma / whitespace / newline as
// delimiters — operators tend to paste from spreadsheets, jira,
// or just type "host-a, host-b host-c".
function parseTargets(raw: string): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const piece of raw.split(/[,\s]+/)) {
    const t = piece.trim()
    if (!t) continue
    if (seen.has(t)) continue
    seen.add(t)
    out.push(t)
  }
  return out
}

export function RequestForm({
  initialTarget = '',
  compact = false,
}: {
  // Prefill the target field (used by the Connect resolver, which already
  // knows the target the operator wants). The operator can still edit it
  // or comma-separate additional targets.
  initialTarget?: string
  // Compact = embedded in the Connect resolver dialog: hide the SOC 2
  // helper sub-labels to keep the dialog tight. The submit + polling +
  // receipt behaviour is identical.
  compact?: boolean
} = {}) {
  const [target, setTarget] = useState(initialTarget)
  const [reason, setReason] = useState('')
  const [outcome, setOutcome] = useState<Outcome>({ kind: 'idle' })
  const pollAbortRef = useRef<AbortController | null>(null)
  const suggestions = useTargetSuggestions()

  useEffect(() => {
    return () => pollAbortRef.current?.abort()
  }, [])

  const startPolling = useCallback((initial: RequestView[]) => {
    pollAbortRef.current?.abort()
    const ctrl = new AbortController()
    pollAbortRef.current = ctrl
    const startedAt = performance.now()
    // last-known-state per id, so we only notify on transition.
    const lastState = new Map<string, string>()
    initial.forEach((r) => lastState.set(r.id, r.state))

    const tick = async () => {
      if (ctrl.signal.aborted) return
      const elapsed = performance.now() - startedAt
      if (elapsed > POLL_TOTAL_BUDGET_MS) return

      // Pull the current view from React state via the setter's
      // updater form — avoids capturing a stale `reqs` snapshot.
      const idsToPoll: string[] = []
      setOutcome((prev) => {
        if (prev.kind !== 'tracking') return prev
        for (const id of prev.order) {
          const r = prev.reqs[id]
          if (r && !isTerminalState(r.state)) idsToPoll.push(id)
        }
        return prev
      })
      if (idsToPoll.length === 0) return // everything terminal — stop

      const results = await Promise.allSettled(
        idsToPoll.map((id) => fetchRequest(id, ctrl.signal)),
      )
      if (ctrl.signal.aborted) return
      const updates: Record<string, RequestView> = {}
      const droppedIds: string[] = []
      results.forEach((res, idx) => {
        const id = idsToPoll[idx]
        if (res.status === 'fulfilled') {
          updates[id] = res.value
        } else if (res.reason instanceof GrantsError && res.reason.status === 404) {
          droppedIds.push(id)
        }
        // any other failure: ignore this tick, retry next interval
      })

      setOutcome((prev) => {
        if (prev.kind !== 'tracking') return prev
        const reqs = { ...prev.reqs, ...updates }
        // Fire desktop notifications on state transitions.
        for (const id of Object.keys(updates)) {
          const next = updates[id]
          const prevState = lastState.get(id)
          if (next.state !== prevState && isTerminalState(next.state)) {
            const t = next.target_id
            const title =
              next.state === 'approved' ? `✓ approved — ${t}` :
                next.state === 'denied' ? `✗ denied — ${t}` :
                  `request expired — ${t}`
            const body =
              next.state === 'approved' ? `grant ${next.grant_id ?? ''}` :
                next.state === 'denied' ? (next.decided_reason ?? 'denied') :
                  'no longer actionable'
            notify(title, { body, tag: `req-${id}` })
          }
          lastState.set(id, next.state)
        }
        // Drop 404s from the order list so the UI stops showing them.
        const order = prev.order.filter((id) => !droppedIds.includes(id))
        return { kind: 'tracking', reqs, order, failed: prev.failed }
      })

      const next = elapsed < POLL_FAST_BUDGET_MS ? POLL_FAST_MS : POLL_SLOW_MS
      window.setTimeout(tick, next)
    }
    window.setTimeout(tick, POLL_FAST_MS)
  }, [])

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    const targets = parseTargets(target)
    const r = reason.trim()
    if (targets.length === 0 || !r) return
    setOutcome({ kind: 'submitting' })
    requestPermissionOnce().catch(() => { /* intentional */ })

    const results = await Promise.allSettled(
      targets.map((t) => submitRequest({ target_id: t, reason: r })),
    )
    const reqs: Record<string, RequestView> = {}
    const order: string[] = []
    const failed: SubmitFailure[] = []
    results.forEach((res, idx) => {
      const t = targets[idx]
      if (res.status === 'fulfilled') {
        reqs[res.value.id] = res.value
        order.push(res.value.id)
      } else {
        const status = res.reason instanceof GrantsError ? res.reason.status : 0
        const msg = res.reason instanceof Error ? res.reason.message : String(res.reason)
        failed.push({ target: t, status, msg })
      }
    })
    if (order.length === 0 && failed.length > 0) {
      // All N failed with same shape → show a single error banner,
      // not an empty tracking view. Use the first failure's status
      // as the headline; the body enumerates all failures.
      setOutcome({
        kind: 'err',
        status: failed[0].status,
        msg: failed.length === 1
          ? failed[0].msg
          : `${failed.length} of ${targets.length} requests failed: ${failed.map((f) => `${f.target} (${f.msg})`).join('; ')}`,
      })
      return
    }
    setOutcome({ kind: 'tracking', reqs, order, failed })
    setTarget('')
    setReason('')
    const nonTerminal = order.map((id) => reqs[id]).filter((rv) => !isTerminalState(rv.state))
    if (nonTerminal.length > 0) startPolling(nonTerminal)
  }

  return (
    <>
      <form className="c2-form" onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div className="c2-field">
          <label htmlFor="jw-req-target">Target id(s)</label>
          <input
            id="jw-req-target"
            name="target_id"
            type="text"
            className="c2-input c2-input-mono"
            autoComplete="off"
            list="jw-req-target-suggestions"
            required
            placeholder="node-app-01  (or comma/space-separate multiple: node-app-01, node-cp-01)"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />
          <datalist id="jw-req-target-suggestions">
            {suggestions.map((t) => (
              <option key={t} value={t} />
            ))}
          </datalist>
        </div>
        <div className="c2-field">
          <label htmlFor="jw-req-reason">{compact ? 'Reason' : 'Reason (SOC 2 evidence)'}</label>
          <input
            id="jw-req-reason"
            name="reason"
            type="text"
            className="c2-input"
            autoComplete="off"
            required
            placeholder='e.g. "INC-4421 — debug Linkerd OOM"'
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
        </div>
        <button
          type="submit"
          className="c2-btn c2-btn-primary"
          style={{ alignSelf: 'flex-start' }}
          disabled={outcome.kind === 'submitting'}
        >
          {outcome.kind === 'submitting' ? 'Submitting…' : 'Request access →'}
        </button>
      </form>

      {outcome.kind === 'tracking' && (
        <RequestBatchReceipt order={outcome.order} reqs={outcome.reqs} failed={outcome.failed} />
      )}
      {outcome.kind === 'err' && <RequestErrorBanner status={outcome.status} msg={outcome.msg} />}
    </>
  )
}

function RequestBatchReceipt({
  order,
  reqs,
  failed,
}: {
  order: string[]
  reqs: Record<string, RequestView>
  failed: SubmitFailure[]
}) {
  const total = order.length
  const counts = {
    pending: 0,
    approved: 0,
    denied: 0,
    expired: 0,
    other: 0,
  }
  for (const id of order) {
    const r = reqs[id]
    if (!r) continue
    if (r.state in counts) counts[r.state as keyof typeof counts]++
    else counts.other++
  }
  const allOne = total === 1
  return (
    <div className="c2-note c2-note-info" role="status" style={{ marginTop: 14 }}>
      <p className="c2-note-title">
        {allOne
          ? (reqs[order[0]]?.state === 'approved' ? 'Request approved' :
            reqs[order[0]]?.state === 'denied' ? 'Request denied' :
              reqs[order[0]]?.state === 'expired' ? 'Request expired' :
                'Request submitted')
          : `${total} request${total === 1 ? '' : 's'} tracked`}
      </p>
      {!allOne && (
        <p className="c2-ink-2" style={{ margin: '0 0 8px', fontSize: 12 }}>
          {counts.approved > 0 && <>{counts.approved} approved · </>}
          {counts.pending > 0 && <>{counts.pending} pending · </>}
          {counts.denied > 0 && <>{counts.denied} denied · </>}
          {counts.expired > 0 && <>{counts.expired} expired</>}
        </p>
      )}
      <ul style={{ listStyle: 'none', margin: '8px 0 0', padding: 0, display: 'flex', flexDirection: 'column', gap: 6 }}>
        {order.map((id) => {
          const r = reqs[id]
          if (!r) return null
          return (
            <li key={id} id={`req-${id}`} style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12 }}>
              <span className="c2-mono c2-ink-1" style={{ minWidth: 120 }}>{r.target_id}</span>
              <span className={pillClassFor(r.state)}><span className="c2-badge-dot" />{r.state}</span>
              <span className="c2-mono c2-ink-3">
                {r.state === 'approved' && r.grant_id && <>grant <code>{r.grant_id}</code></>}
                {r.state === 'denied' && r.decided_reason && <>{r.decided_reason}</>}
                {r.state === 'pending' && <>approver paged</>}
              </span>
            </li>
          )
        })}
      </ul>
      {failed.length > 0 && (
        <p className="c2-ink-2" style={{ marginTop: 10, fontSize: 12 }}>
          {failed.length} target{failed.length === 1 ? '' : 's'} failed to submit:{' '}
          {failed.map((f) => (
            <span key={f.target}><code>{f.target}</code> ({f.msg}) </span>
          ))}
        </p>
      )}
    </div>
  )
}

function RequestErrorBanner({ status, msg }: { status: number; msg: string }) {
  return (
    <div className="c2-note c2-note-danger" role="alert" style={{ marginTop: 14 }}>
      <p className="c2-note-title">Request failed</p>
      <p style={{ margin: 0, fontSize: 12 }}>
        {status > 0 ? <>HTTP {status} — </> : null}
        {msg}
      </p>
    </div>
  )
}

function pillClassFor(state: string): string {
  switch (state) {
    case 'approved':
      return 'c2-badge c2-badge-online'
    case 'denied':
      return 'c2-badge c2-badge-danger'
    case 'expired':
      return 'c2-badge c2-badge-mute'
    case 'pending':
      return 'c2-badge c2-badge-warn'
    default:
      return 'c2-badge c2-badge-mute'
  }
}

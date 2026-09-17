// Browser SQL console — query editor + result grid over the brokered
// Postgres/MySQL relay.
//
// THE ARCHITECTURE (mirrors the SSH Session page's identity model): the browser
// is a dumb renderer. It POSTs {target, grant, protocol, sql} to jess-web's
// /api/db/query; jess-web opens a brokered relay session to the worker DB broker
// (the operator's real Falcon-ID identity flows into the OperatorRequest) and
// runs the statement as a real DB client THROUGH the relay — so the worker still
// records every statement to the WORM query log and enforces the per-statement
// policy. A policy denial comes back as a normal error result, rendered in the
// status bar.
//
// One statement per run (matches the server: one brokered session per query,
// fail-closed). Cmd/Ctrl+Enter runs.
//
// PASS 2: a first-class C2 SQL console — object header (target + protocol),
// a paneled query editor with a Run toolbar, results rendered in the pass-1
// DataGrid (columns from result.columns + NULL handling + truncation), and a
// status bar carrying rows / rows-affected / elapsed_ms + the WORM query-log
// badge. The /api/db/query path, NULL handling, and policy-denial-as-error are
// unchanged.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { DBQueryError, runQuery, type DBProtocol, type DBQueryResult } from '../api/db'
import {
  AppShell,
  ConsoleFrame,
  ConsoleStat,
  Column,
  DataGrid,
  Panel,
  StatusBadge,
  useConsoleDock,
} from '../components/c2'

type RunState =
  | { kind: 'idle' }
  | { kind: 'running' }
  | { kind: 'ok'; result: DBQueryResult }
  | { kind: 'error'; message: string }

function isDBProtocol(p: string): p is DBProtocol {
  return p === 'postgres' || p === 'mysql'
}

interface DBConsoleSessionProps {
  target: string
  grant: string
  protocol: DBProtocol
  /** hand the session to the dock taskbar. */
  onMinimize: () => void
  /** tear the console down (unmount). */
  onClose: () => void
}

// DBConsoleSession — the SQL console body (editor + result grid), extracted from
// the /db-console route so it's hosted by the cross-nav ConsoleDock and survives
// navigation: the typed statement + last result stay alive when minimized.
function DBConsoleSession({ target, grant, protocol, onMinimize, onClose }: DBConsoleSessionProps) {
  const protoParam = protocol // keep the existing identifier; downstream usage unchanged

  const [sql, setSql] = useState('')
  const [state, setState] = useState<RunState>({ kind: 'idle' })
  const abortRef = useRef<AbortController | null>(null)

  // Distinguish multiple console tabs in the OS task switcher / tab strip.
  useEffect(() => {
    document.title = target ? `SQL · ${target} · jess` : 'SQL console · jess'
    return () => { document.title = 'jess' }
  }, [target])

  const run = useCallback(() => {
    if (!target || !isDBProtocol(protoParam)) return
    if (sql.trim() === '') return
    abortRef.current?.abort()
    const ctrl = new AbortController()
    abortRef.current = ctrl
    setState({ kind: 'running' })
    runQuery({ target, grant, protocol: protoParam, sql }, ctrl.signal)
      .then((result) => {
        if (ctrl.signal.aborted) return
        // A DB-level / policy error rides back inside the 200 result body.
        if (result.error) {
          setState({ kind: 'error', message: result.error })
          return
        }
        setState({ kind: 'ok', result })
      })
      .catch((e: unknown) => {
        if (ctrl.signal.aborted) return
        setState({ kind: 'error', message: messageOf(e) })
      })
  }, [target, grant, protoParam, sql])

  useEffect(() => () => abortRef.current?.abort(), [])

  function onKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault()
      run()
    }
  }

  const running = state.kind === 'running'
  return (
      <ConsoleFrame
        protocol={protoParam}
        target={target}
        status={
          grant
            ? { tone: 'info', label: `grant ${grant.slice(0, 8)}`, title: 'JIT grant authorizing this session' }
            : { tone: 'warn', label: 'admin-direct', title: 'No grant — admin-direct-connect (requires platform_admin + MFA)' }
        }
        onDisconnect={onClose}
        onMinimize={onMinimize}
        disconnectLabel="Close"
        statusbar={<StatusBar state={state} protocol={protoParam} />}
      >
        {/* The SQL console stage is a scrollable two-pane layout (editor + grid),
            not a single full-bleed viewport — but it lives in the same frame. */}
        <div className="c2-sql-stage">
          <Panel
            title="Statement"
            subtitle="One statement per run · every statement is policy-checked + WORM-recorded at the relay"
            actions={
              <>
                <span className="c2-kbd">⌘/Ctrl + ↵</span>
                <button className="c2-btn c2-btn-primary c2-btn-sm" onClick={run} disabled={running || sql.trim() === ''}>
                  {running ? 'Running…' : '▸ Run'}
                </button>
              </>
            }
          >
            <div className="c2-panel-pad">
              <label htmlFor="jw-sql-editor" className="c2-eyebrow" style={{ display: 'block', marginBottom: 6 }}>
                {protoParam} editor
              </label>
              <textarea
                id="jw-sql-editor"
                className="c2-textarea"
                value={sql}
                onChange={(e) => setSql(e.target.value)}
                onKeyDown={onKeyDown}
                spellCheck={false}
                autoCapitalize="off"
                autoCorrect="off"
                placeholder={protoParam === 'postgres' ? 'SELECT * FROM pg_stat_activity LIMIT 50;' : 'SELECT * FROM information_schema.tables LIMIT 50;'}
                style={{ minHeight: 130 }}
              />
            </div>
          </Panel>

          <ResultPanel state={state} />
        </div>
      </ConsoleFrame>
  )
}

// DBConsole — the /db-console route is now a thin LAUNCHER (mirrors RDP/SSH):
// confirm sign-in, validate the target + DB protocol, register the SQL console
// into the app-root ConsoleDock, and redirect to the inventory. The console then
// survives navigation — Minimize drops it to the session tray (editor + last
// result preserved), Close unmounts it. Re-opening the same target foregrounds
// the existing console (dock.open idempotent).
export function DBConsole() {
  const [params] = useSearchParams()
  const target = params.get('target') ?? ''
  const grant = params.get('grant') ?? ''
  const protoParam = (params.get('protocol') ?? params.get('proto') ?? '').toLowerCase()
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
    if (auth !== 'ok' || !target || !isDBProtocol(protoParam) || launched.current) return
    launched.current = true
    const id = `db:${protoParam}:${target}${grant ? `:${grant}` : ''}`
    open({
      id,
      title: target,
      proto: 'SQL',
      node: (
        <DBConsoleSession
          key={id}
          target={target}
          grant={grant}
          protocol={protoParam}
          onMinimize={minimize}
          onClose={() => close(id)}
        />
      ),
    })
    navigate('/targets', { replace: true })
  }, [auth, target, grant, protoParam, open, minimize, close, navigate])

  if (auth === 'anon') return <AppShell variant="console" />
  if (!target) {
    return (
      <AppShell variant="console" requireAuth={false}>
        <div className="c2-console-body">
          <div className="c2-note c2-note-mute">
            No target. Open the SQL console from a Postgres or MySQL target's
            Connect ▾ action in <Link to="/admin/catalog">Catalog</Link>.
          </div>
        </div>
      </AppShell>
    )
  }
  if (!isDBProtocol(protoParam)) {
    return (
      <AppShell variant="console" requireAuth={false}>
        <div className="c2-console-body">
          <div className="c2-note c2-note-warn">
            The SQL console only brokers <code>postgres</code> and <code>mysql</code> targets.
            Got <code>{protoParam || '(none)'}</code>.
          </div>
        </div>
      </AppShell>
    )
  }
  return (
    <AppShell variant="console" requireAuth={false}>
      <div className="c2-console-body">
        <div className="c2-note c2-note-mute">Opening the {protoParam} console for {target}…</div>
      </div>
    </AppShell>
  )
}

function ResultPanel({ state }: { state: RunState }) {
  const subtitle =
    state.kind === 'ok'
      ? resultSummary(state.result)
      : state.kind === 'running'
        ? 'brokering one statement…'
        : state.kind === 'error'
          ? 'statement failed'
          : 'run a statement to see results'
  return (
    <Panel title="Result" subtitle={subtitle} className="c2-sql-result">
      {state.kind === 'idle' && (
        <p className="c2-ink-3 c2-panel-pad" style={{ fontSize: 12.5, margin: 0 }}>
          Reads return a result grid; writes return an affected-row count. Statements
          blocked by the relay policy come back as an error here.
        </p>
      )}
      {state.kind === 'running' && (
        <p className="c2-ink-3 c2-panel-pad" style={{ fontSize: 12.5, margin: 0 }}>Running through the broker…</p>
      )}
      {state.kind === 'error' && (
        <div className="c2-panel-pad">
          <div className="c2-note c2-note-danger" role="alert">
            <p className="c2-note-title">⚠ query error</p>
            <p className="c2-mono" style={{ margin: 0, fontSize: 12, whiteSpace: 'pre-wrap' }}>{state.message}</p>
          </div>
        </div>
      )}
      {state.kind === 'ok' && <ResultBody result={state.result} />}
    </Panel>
  )
}

function resultSummary(r: DBQueryResult): string {
  if (r.columns.length === 0) {
    return `${r.rows_affected} row${r.rows_affected === 1 ? '' : 's'} affected · ${r.elapsed_ms} ms`
  }
  return `${r.rows.length} row${r.rows.length === 1 ? '' : 's'}${r.truncated ? ' (truncated)' : ''} · ${r.elapsed_ms} ms`
}

// A SQL result row carried alongside its original index (DataGrid needs a key).
interface GridRow {
  i: number
  cells: (string | null)[]
}

function ResultBody({ result }: { result: DBQueryResult }) {
  // Non-SELECT (no columns): just an affected-rows summary.
  if (result.columns.length === 0) {
    return (
      <div className="c2-panel-pad">
        <p style={{ margin: 0 }}>
          <StatusBadge tone="online">ok</StatusBadge>
          {' '}{result.rows_affected} row{result.rows_affected === 1 ? '' : 's'} affected
        </p>
        {result.command_tag && (
          <p className="c2-ink-3 c2-mono" style={{ fontSize: 12, marginTop: 6 }}>{result.command_tag}</p>
        )}
      </div>
    )
  }
  return <ResultGrid result={result} />
}

function ResultGrid({ result }: { result: DBQueryResult }) {
  const rows: GridRow[] = useMemo(
    () => result.rows.map((cells, i) => ({ i, cells })),
    [result.rows],
  )
  // # column + one column per result column. Cells preserve NULL semantics
  // (italic muted "NULL") exactly as the prior renderer did.
  const columns: Column<GridRow>[] = useMemo(() => {
    const out: Column<GridRow>[] = [
      {
        key: '#',
        header: '#',
        numeric: true,
        width: 1,
        cell: (r) => <span className="c2-grid-mute">{r.i + 1}</span>,
      },
    ]
    result.columns.forEach((c, ci) => {
      out.push({
        key: `${c}-${ci}`,
        header: <span className="c2-mono">{c}</span>,
        cell: (r) => {
          const cell = r.cells[ci]
          return cell === null
            ? <span className="c2-ink-3" style={{ fontStyle: 'italic' }}>NULL</span>
            : <span className="c2-grid-mono">{cell}</span>
        },
      })
    })
    return out
  }, [result.columns])

  return (
    <div className="c2-sql-grid-wrap">
      <DataGrid rows={rows} columns={columns} rowKey={(r) => String(r.i)} empty="No rows returned." />
    </div>
  )
}

function StatusBar({ state, protocol }: { state: RunState; protocol: DBProtocol }) {
  return (
    <>
      {state.kind === 'ok' ? (
        <OkStatus result={state.result} protocol={protocol} />
      ) : state.kind === 'error' ? (
        <span className="c2-console-stat">
          <StatusBadge tone="danger">error</StatusBadge>
          <span className="c2-ink-3">statement failed — see result panel</span>
        </span>
      ) : state.kind === 'running' ? (
        <span className="c2-console-stat">
          <StatusBadge tone="warn">running</StatusBadge>
          <span className="c2-ink-3">brokering one statement…</span>
        </span>
      ) : (
        <span className="c2-console-stat">
          <StatusBadge tone="mute" dot={false}>idle</StatusBadge>
          <span className="c2-ink-3">{protocol} via broker</span>
        </span>
      )}
      <span className="c2-toolbar-spacer" />
      <ConsoleStat label="WORM" title="Every brokered statement is appended to the relay's tamper-evident query log">
        <span style={{ color: 'var(--c2-online)' }}>query-log on</span>
      </ConsoleStat>
      <ConsoleStat label="Policy" title="The worker enforces a per-statement Rego policy; a denial returns as an error row">
        <span style={{ color: 'var(--c2-accent)' }}>per-statement</span>
      </ConsoleStat>
    </>
  )
}

function OkStatus({ result, protocol }: { result: DBQueryResult; protocol: DBProtocol }) {
  const reads = result.columns.length > 0
  return (
    <span className="c2-console-stat">
      <StatusBadge tone="online">ok</StatusBadge>
      <span className="c2-ink-2">
        {reads ? `${result.rows.length} row${result.rows.length === 1 ? '' : 's'} returned` : `${result.rows_affected} affected`}
        {result.truncated && reads && <> · <StatusBadge tone="warn">truncated</StatusBadge></>}
        {' · '}<b style={{ color: 'var(--hxm-ink-1)', fontFamily: 'var(--hxm-f-mono)' }}>{result.elapsed_ms} ms</b>
        {' · '}{protocol}
        {result.command_tag && <> · <span className="c2-mono">{result.command_tag}</span></>}
      </span>
    </span>
  )
}

function messageOf(e: unknown): string {
  if (e instanceof DBQueryError) return e.status === 401 ? 'sign-in expired — reload to re-authenticate' : `${e.message}`
  if (e instanceof Error) return e.message
  return String(e)
}

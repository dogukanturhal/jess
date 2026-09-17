// Browser SQL console API client. Backs the /db-console route. The single
// endpoint POSTs a statement to jess-web's /api/db/query handler, which runs it
// through the brokered Postgres/MySQL relay (server-side — the browser never
// speaks raw wire) and returns the result set as JSON.
//
// Server-side enforcement is authoritative: statement policy + the WORM query
// log live at the worker relay. A policy denial comes back as a normal
// {error: "..."} result, not an HTTP error — the console renders it in the
// status bar like any other DB error.

export type DBProtocol = 'postgres' | 'mysql'

export interface DBQueryRequest {
  target: string
  grant: string
  protocol: DBProtocol
  sql: string
}

// A row cell is `null` for SQL NULL, otherwise the value's text form. The grid
// renders text; it does not re-type the column.
export type DBCell = string | null

export interface DBQueryResult {
  columns: string[]
  rows: DBCell[][]
  rows_affected: number
  command_tag?: string
  truncated?: boolean
  elapsed_ms: number
  error?: string
}

export class DBQueryError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
    this.name = 'DBQueryError'
  }
}

// runQuery POSTs one statement and returns the parsed result. A 2xx with an
// `error` field is a DB/policy-level error (returned to the caller in the
// result, not thrown) — the console shows it inline. A non-2xx (auth, bad
// request, dial failure) throws DBQueryError.
export async function runQuery(req: DBQueryRequest, signal?: AbortSignal): Promise<DBQueryResult> {
  const r = await fetch('/api/db/query', {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
    signal,
  })
  const raw = await r.text()
  let parsed: unknown = null
  try {
    parsed = raw.length > 0 ? JSON.parse(raw) : null
  } catch {
    // fall through to status-based error below
  }
  if (!r.ok) {
    const msg =
      typeof parsed === 'object' && parsed !== null && 'error' in parsed &&
      typeof (parsed as { error: unknown }).error === 'string'
        ? (parsed as { error: string }).error
        : `HTTP ${r.status}`
    throw new DBQueryError(r.status, msg)
  }
  return parsed as DBQueryResult
}

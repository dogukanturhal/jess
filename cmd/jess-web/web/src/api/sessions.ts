// Recent-sessions surface — backed by /api/my/sessions which proxies
// to the controller's GET /sessions?mine=true (Phase 5e-6). The SPA
// renders the response in the Landing page's "Recent sessions" card.

export interface SessionView {
  id: string
  subject: string
  target_id: string
  grant_id?: string
  protocol?: string
  started_at: string // RFC3339
  ended_at?: string
  close_reason?: string
  recording_path?: string
  controller_id?: string
  duration_seconds: number
  active: boolean
  // Phase 5e-10 bytes counters (final on close; 0 while session is
  // active because the controller persists them at teardown).
  bytes_in: number
  bytes_out: number
}

export class SessionsError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
    this.name = 'SessionsError'
  }
}

export async function fetchMySessions(limit = 10, signal?: AbortSignal): Promise<SessionView[]> {
  const r = await fetch(`/api/my/sessions?limit=${limit}`, {
    credentials: 'same-origin',
    cache: 'no-store',
    signal,
  })
  const raw = await r.text()
  let parsed: unknown = null
  try {
    parsed = raw.length > 0 ? JSON.parse(raw) : null
  } catch {
    // status-based fallback
  }
  if (!r.ok) {
    const msg =
      typeof parsed === 'object' && parsed !== null && 'error' in parsed && typeof (parsed as { error: unknown }).error === 'string'
        ? ((parsed as { error: string }).error)
        : `HTTP ${r.status}`
    throw new SessionsError(r.status, msg)
  }
  return (parsed as SessionView[]) ?? []
}

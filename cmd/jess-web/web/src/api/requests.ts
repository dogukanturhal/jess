// JIT grant-request surface — backed by /api/requests on the Go server,
// which proxies to the controller's admin port using the cookie-session's
// Falcon-ID Bearer (see cmd/jess-web/grants.go).

export interface SubmitRequestBody {
  target_id: string
  reason: string
  request_ttl_minutes?: number
}

export interface RequestView {
  id: string
  subject: string
  target_id: string
  reason: string
  requested_at: string // RFC3339
  state: 'pending' | 'approved' | 'denied' | string
  decided_by?: string
  decided_at?: string
  decided_reason?: string
  grant_id?: string
  expires_at: string
}

export class GrantsError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
    this.name = 'GrantsError'
  }
}

export async function submitRequest(body: SubmitRequestBody, signal?: AbortSignal): Promise<RequestView> {
  return fetchJSON<RequestView>('/api/requests', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal,
  })
}

// List the caller's own recent requests (Phase 5e-5). Backed by the
// controller's GET /requests?mine=true via jess-web's proxy. Sorted
// server-side by requested_at desc — the SPA renders the slice as-is.
export async function fetchMyRequests(signal?: AbortSignal): Promise<RequestView[]> {
  return fetchJSON<RequestView[]>('/api/my/requests', { signal })
}

// Fetch a single request by id. Phase 5e-4 controller addition.
// Returns the current RequestView; throws GrantsError on non-OK with
// the controller-supplied error message (or HTTP status fallback).
//
// 404 here means EITHER the request never existed OR it exists but
// doesn't belong to the caller — the controller deliberately doesn't
// distinguish, to avoid leaking the existence of other operators'
// requests (same privacy posture as GitHub/GitLab APIs).
export async function fetchRequest(id: string, signal?: AbortSignal): Promise<RequestView> {
  return fetchJSON<RequestView>(`/api/requests/${encodeURIComponent(id)}`, { signal })
}

async function fetchJSON<T>(url: string, init: RequestInit): Promise<T> {
  const r = await fetch(url, {
    credentials: 'same-origin',
    cache: 'no-store',
    ...init,
  })
  const raw = await r.text()
  let parsed: unknown = null
  try {
    parsed = raw.length > 0 ? JSON.parse(raw) : null
  } catch {
    // intentional — fall through to status-based message
  }
  if (!r.ok) {
    const msg =
      typeof parsed === 'object' && parsed !== null && 'error' in parsed && typeof (parsed as { error: unknown }).error === 'string'
        ? ((parsed as { error: string }).error)
        : `HTTP ${r.status}`
    throw new GrantsError(r.status, msg)
  }
  return parsed as T
}

// A request is "settled" once it has transitioned out of pending. The SPA
// polling loop stops when this is true.
export function isTerminalState(state: string): boolean {
  return state === 'approved' || state === 'denied' || state === 'expired'
}

// activeGrantsForTarget filters the caller's own requests down to the ones
// that currently authorise a connection to `targetId`: state=approved, a
// non-empty grant_id, the target matches, and expires_at is still in the
// future. Sorted soonest-expiring first so the picker defaults to the grant
// the operator should burn before it lapses. Backs the Connect resolver.
export function activeGrantsForTarget(reqs: RequestView[], targetId: string, now = Date.now()): RequestView[] {
  return reqs
    .filter((r) =>
      r.state === 'approved' &&
      !!r.grant_id &&
      r.target_id === targetId &&
      new Date(r.expires_at).getTime() > now,
    )
    .sort((a, b) => new Date(a.expires_at).getTime() - new Date(b.expires_at).getTime())
}

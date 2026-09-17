// Admin API client — backs the SPA /admin route. All endpoints proxy
// to the controller admin port via jess-web's /api/admin/* handlers,
// which enforce a server-side platform_admin gate (the SPA also gates
// the route client-side but the proxy is authoritative).

import { type RequestView } from './requests'
import type { SessionView } from './sessions'

export interface GrantView {
  id: string
  subject: string
  target_id: string
  approved_by: string
  issued_at: string  // RFC3339
  expires_at: string // RFC3339
}

export class AdminError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
    this.name = 'AdminError'
  }
}

async function adminJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, {
    credentials: 'same-origin',
    cache: 'no-store',
    ...init,
  })
  if (r.status === 204) return undefined as unknown as T
  const raw = await r.text()
  let parsed: unknown = null
  try {
    parsed = raw.length > 0 ? JSON.parse(raw) : null
  } catch {
    // fall through
  }
  if (!r.ok) {
    const msg =
      typeof parsed === 'object' && parsed !== null && 'error' in parsed && typeof (parsed as { error: unknown }).error === 'string'
        ? ((parsed as { error: string }).error)
        : `HTTP ${r.status}`
    throw new AdminError(r.status, msg)
  }
  return parsed as T
}

// Unified discovery catalog — GET /api/admin/catalog → controller's
// /admin/catalog aggregator across every DiscoveryProvider. platform_admin
// gated server-side. Shape mirrors the controller's CatalogTarget.
export interface CatalogTarget {
  id: string
  name?: string
  protocol: string
  address: string
  region?: string
  recorded?: boolean
  criticality?: string
  tags?: string[]
  source?: string
  last_seen?: string
}

export function adminListCatalog(signal?: AbortSignal): Promise<CatalogTarget[]> {
  return adminJSON<CatalogTarget[]>('/api/admin/catalog', { signal })
}

export function adminListRequests(state?: string, signal?: AbortSignal): Promise<RequestView[]> {
  const q = state ? `?state=${encodeURIComponent(state)}` : ''
  return adminJSON<RequestView[]>(`/api/admin/requests${q}`, { signal })
}

export function adminApproveRequest(id: string, ttlSeconds: number): Promise<RequestView> {
  return adminJSON<RequestView>(`/api/admin/requests/${encodeURIComponent(id)}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ttl_seconds: ttlSeconds }),
  })
}

export function adminDenyRequest(id: string, reason: string): Promise<RequestView> {
  return adminJSON<RequestView>(`/api/admin/requests/${encodeURIComponent(id)}/deny`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason }),
  })
}

export function adminListSessions(signal?: AbortSignal): Promise<SessionView[]> {
  return adminJSON<SessionView[]>('/api/admin/sessions?limit=50', { signal })
}



export function adminListGrants(signal?: AbortSignal): Promise<GrantView[]> {
  return adminJSON<GrantView[]>('/api/admin/grants', { signal })
}

export function adminRevokeGrant(id: string): Promise<void> {
  return adminJSON<void>(`/api/admin/grants/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

// adminIssueGrant — issue a JIT grant for `subject` on `target` for `ttlSeconds`
// in ONE call and resolve to the freshly-minted grant id, so a platform_admin
// can connect immediately. platform_admin only (the BFF proxy + controller both
// gate the role).
//
// Posts directly to the controller's POST /grants via jess-web's BFF
// (cmd/jess-web/admin.go handleAdminGrants now forwards POST). This replaces the
// old request→approve composition: an admin no longer has to file a request and
// approve their own request — i.e. no detour through the admin console to reach
// their own session. Still Zero-Standing-Privilege: the controller time-boxes
// the grant (ttl ≤ 24h), stamps ApprovedBy=sub:<caller> from the verified token,
// and records the mint in the WORM audit chain like any other grant.
//
// The controller returns a GrantView (`id` = the grant id). We augment it with
// `grant_id` (= id) so existing callers can read `grant.grant_id` unchanged.
export async function adminIssueGrant(
  subject: string,
  targetId: string,
  ttlSeconds: number,
  signal?: AbortSignal,
): Promise<GrantView & { grant_id: string }> {
  const g = await adminJSON<GrantView>('/api/admin/grants', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subject, target_id: targetId, ttl_seconds: ttlSeconds }),
    signal,
  })
  if (!g.id) {
    throw new AdminError(502, 'grant issued but no grant id was returned by the controller')
  }
  return { ...g, grant_id: g.id }
}

// Phase 5e-16 cross-session WORM audit chain. ok=false means at least
// one row was tampered, deleted, or inserted — admin must investigate.
export interface ChainBreak {
  session_id: string
  position: number
  reason: 'row_hash_mismatch' | 'prev_row_hash_mismatch' | 'prev_row_hash_orphan' | string
  expected?: string
  got?: string
}
export interface ChainReport {
  ok: boolean
  total: number
  genesis_hash?: string
  head_hash?: string
  breaks?: ChainBreak[]
}

export function adminVerifyChain(signal?: AbortSignal): Promise<ChainReport> {
  return adminJSON<ChainReport>('/api/admin/audit/chain/verify', { signal })
}

// Phase 5f-2b RDP probe — controller-side reachability check on a
// target. SSRF-guarded server-side (RFC1918 only, ports 3389/13389).
// Useful before an operator opens a session through the upcoming
// web-RDP broker.
export interface RDPProbeReport {
  target: string
  reachable: boolean
  connection_confirm: boolean
  negotiated_protocol?: string
  negotiated_flags?: number
  failure_code?: number
  failure_reason?: string
  nla_required: boolean
  tls_supported: boolean
  duration_ms: number
  error?: string
}

export function adminRDPProbe(target: string, signal?: AbortSignal): Promise<RDPProbeReport> {
  return adminJSON<RDPProbeReport>(
    `/api/admin/rdp-probe?target=${encodeURIComponent(target)}`,
    { signal },
  )
}

// Phase 5f-2d catalog-wide RDP probe sweep.
export interface SweepResult {
  target_id: string
  target_name?: string
  address: string
  region?: string
  probe: RDPProbeReport
}
export interface SweepResponse {
  total: number
  reachable: number
  failed: number
  results: SweepResult[]
  elapsed_ms: number
}

export function adminRDPProbeSweep(signal?: AbortSignal): Promise<SweepResponse> {
  return adminJSON<SweepResponse>('/api/admin/rdp-probe/sweep', { signal })
}

// Per-target recording enable/disable — admin-controlled RUNTIME override on
// top of the catalog's GitOps `recorded` default.
//
//   recorded        = the EFFECTIVE value sessions honour
//   source          = "override" (admin set it) | "catalog" (GitOps default)
//   catalog_default = the GitOps baseline a DELETE would revert to
//
// Set via adminSetRecording (PUT) / cleared via adminClearRecording (DELETE).
// All three are platform_admin-gated server-side; the controller stamps
// updated_by from the verified token and audits every change.
export interface RecordingSetting {
  target_id: string
  target_name?: string
  protocol?: string
  recorded: boolean        // effective
  source: 'override' | 'catalog'
  catalog_default: boolean // GitOps baseline
  updated_by?: string
  updated_at?: string      // RFC3339
}

export function adminListRecordingSettings(signal?: AbortSignal): Promise<RecordingSetting[]> {
  return adminJSON<RecordingSetting[]>('/api/admin/recording-settings', { signal })
}

// ADR 0052 discovery review queue — auto-discovered candidates awaiting an
// operator decision. `phase` is Pending (awaiting review), Rejected, or "".
export interface PendingCandidate {
  name: string
  protocol: string
  address: string
  criticality?: string
  source?: string
  phase?: string
  reason?: string
  discovered_at?: string
}

export function adminListPending(signal?: AbortSignal): Promise<PendingCandidate[]> {
  return adminJSON<PendingCandidate[]>('/api/admin/pending', { signal })
}

// Promote a candidate to a brokerable JessTarget (operator decision). The
// controller still refuses a Tier-0 RDP candidate (ADR 0052 hard-guard).
export function adminApprovePending(name: string): Promise<{ name: string; approved: boolean; by: string }> {
  return adminJSON(`/api/admin/pending/${encodeURIComponent(name)}/approve`, { method: 'POST' })
}

export function adminRejectPending(name: string): Promise<{ name: string; rejected: boolean; by: string }> {
  return adminJSON(`/api/admin/pending/${encodeURIComponent(name)}/reject`, { method: 'POST' })
}

export function adminSetRecording(targetId: string, recorded: boolean): Promise<RecordingSetting> {
  return adminJSON<RecordingSetting>(`/api/admin/recording-settings/${encodeURIComponent(targetId)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recorded }),
  })
}

// Clear the override → target reverts to its catalog (GitOps) default.
export function adminClearRecording(targetId: string): Promise<RecordingSetting> {
  return adminJSON<RecordingSetting>(`/api/admin/recording-settings/${encodeURIComponent(targetId)}`, {
    method: 'DELETE',
  })
}

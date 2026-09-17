// Recording tamper-evidence verify — Phase 5e-14.
//
// Controller endpoint: GET /sessions/{id}/recording/verify
// jess-web proxy: GET /api/my/sessions/{id}/recording/verify (mirrors
// /api/my/sessions/{id}/recording path — same owner-or-admin gate;
// 503 when controller has no verifier configured).
//
// The badge reads `ok` alone — both signature_valid AND hash_match
// must hold AND the verifier must have completed without error. UX
// callers can still inspect signature_valid + hash_match individually
// to render "signature OK, content tampered" vs "signature INVALID".

export interface VerifyResponse {
  session_id: string
  ok: boolean
  signature_valid: boolean
  hash_match: boolean
  // Phase 5e-20: cross-link to the WORM session chain. True when
  // either the manifest claim matches the live row_hash OR the
  // bundle predates 5e-20 (no claim to check).
  chain_link_ok: boolean
  chain_link_expected?: string
  chain_link_got?: string
  key_id?: string
  sealed_at?: string // RFC3339
  content_bytes: number
  content_sha256?: string
  error?: string
}

export class VerifyError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
    this.name = 'VerifyError'
  }
}

export async function verifyRecording(sessionId: string, signal?: AbortSignal): Promise<VerifyResponse> {
  const r = await fetch(`/api/my/sessions/${encodeURIComponent(sessionId)}/recording/verify`, {
    credentials: 'same-origin',
    cache: 'no-store',
    signal,
  })
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
        ? (parsed as { error: string }).error
        : `HTTP ${r.status}`
    throw new VerifyError(r.status, msg)
  }
  return parsed as VerifyResponse
}

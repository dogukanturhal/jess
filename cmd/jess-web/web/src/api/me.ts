// Falcon-ID operator identity surface — backed by /api/me on the Go server.
// Returns null on 401 (anonymous) or 503 (OIDC disabled in dev). Throws on
// any other non-OK response so the caller can show a real error.

export interface Me {
  subject: string
  email: string
  roles: string[]
  amr?: string[] // OIDC amr (RFC 8176): mfa | otp | totp | hwk | pwd | …
  expires_at: string // RFC3339
}

// Strong-auth methods that satisfy the controller's step-up gate for
// admin-direct-connect. Mirrors the production
// JESS_ADMIN_DIRECT_CONNECT_REQUIRE_AMR default list. If the operator's
// token amr contains ANY of these, they can direct-connect; otherwise
// the SPA shows a "Step up with MFA" prompt that triggers
// /auth/login?acr_values=mfa.
export const STEP_UP_METHODS = ['mfa', 'otp', 'totp', 'hwk', 'webauthn'] as const

export function hasStepUp(me: Me | null): boolean {
  if (!me?.amr) return false
  return me.amr.some((m) => (STEP_UP_METHODS as readonly string[]).includes(m))
}

export async function fetchMe(signal?: AbortSignal): Promise<Me | null> {
  const r = await fetch('/api/me', {
    credentials: 'same-origin',
    cache: 'no-store',
    signal,
  })
  if (r.status === 401 || r.status === 503) return null
  if (!r.ok) throw new Error(`me HTTP ${r.status}`)
  return (await r.json()) as Me
}

// isAdmin checks the verified roles claim for the platform_admin role.
// Mirrors the controller's AdminAutoGrantRole + admin handler gate so
// the SPA can show admin-only surfaces without round-tripping. Server
// is still the authoritative gate; client check is a UX nicety.
export function isAdmin(me: Me | null): boolean {
  if (!me) return false
  return me.roles.includes('platform_admin')
}

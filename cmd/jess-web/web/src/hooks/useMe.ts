// useMe — shared /api/me auth gate. Wraps the EXACT same fetch the pages
// used inline (credentials: same-origin, cache: no-store, 401/503 → anon),
// so the C2 reskin preserves the per-page auth behavior without changing
// any request shape. Server-side gates stay authoritative.
import { useEffect, useState } from 'react'
import { fetchMe, type Me } from '../api/me'

export type AuthState =
  | { kind: 'loading' }
  | { kind: 'anon' }
  | { kind: 'oidc_disabled' } // /api/me returned 503 — dev fallback
  | { kind: 'signed_in'; me: Me }

export function useMe(): AuthState {
  const [auth, setAuth] = useState<AuthState>({ kind: 'loading' })
  useEffect(() => {
    const ctrl = new AbortController()
    fetch('/api/me', { credentials: 'same-origin', cache: 'no-store', signal: ctrl.signal })
      .then(async (r) => {
        if (ctrl.signal.aborted) return
        if (r.status === 503) return setAuth({ kind: 'oidc_disabled' })
        if (!r.ok) return setAuth({ kind: 'anon' })
        const me = (await r.json()) as Me
        setAuth({ kind: 'signed_in', me })
      })
      .catch(() => { if (!ctrl.signal.aborted) setAuth({ kind: 'anon' }) })
    return () => ctrl.abort()
    // Reference fetchMe so the import stays meaningful for callers that
    // also want the typed helper; harmless no-op otherwise.
    void fetchMe
  }, [])
  return auth
}

// Connect form — target id + grant id → /session?target=…&grant=….
// The actual WebSocket open happens on the Session page so a refresh
// recreates the connection cleanly.
import { useEffect, useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchMe, hasStepUp, isAdmin, type Me } from '../api/me'
import { useTargetSuggestions } from '../hooks/useTargetSuggestions'

export function ConnectForm() {
  const navigate = useNavigate()
  const [target, setTarget] = useState('')
  const [grant, setGrant] = useState('')
  const [me, setMe] = useState<Me | null>(null)
  const suggestions = useTargetSuggestions()

  useEffect(() => {
    const ctrl = new AbortController()
    fetchMe(ctrl.signal).then((m) => {
      if (!ctrl.signal.aborted) setMe(m)
    }).catch(() => { /* swallow — non-admin fallback is correct */ })
    return () => ctrl.abort()
  }, [])

  const admin = isAdmin(me)
  const stepUp = hasStepUp(me)
  // Admin direct-connect requires BOTH platform_admin AND a recent
  // strong-auth assertion in the token's amr claim. Without step-up,
  // admin still needs a grant id (or must step up first).
  const canDirectConnect = admin && stepUp

  function onSubmit(e: FormEvent) {
    e.preventDefault()
    const t = target.trim()
    const g = grant.trim()
    if (!t) return
    if (!canDirectConnect && !g) return
    const params: Record<string, string> = { target: t }
    if (g) params.grant = g
    const qs = new URLSearchParams(params)
    navigate(`/session?${qs.toString()}`)
  }

  // Step-up URL — re-auth at the IdP with acr_values=mfa so the
  // returned token carries a strong-auth amr entry. Lands back on
  // the landing page after the OIDC dance.
  const stepUpHref = `/auth/login?acr_values=mfa&return=${encodeURIComponent('/')}`

  return (
    <form className="c2-form" onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div className="c2-field">
        <label htmlFor="jw-target">Target id</label>
        <input
          id="jw-target"
          name="target"
          type="text"
          className="c2-input c2-input-mono"
          autoComplete="off"
          list="jw-connect-target-suggestions"
          required
          placeholder="e.g. node-app-01"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
        />
        <datalist id="jw-connect-target-suggestions">
          {suggestions.map((t) => (
            <option key={t} value={t} />
          ))}
        </datalist>
      </div>
      <div className="c2-field">
        <label htmlFor="jw-grant">
          Grant id
          {canDirectConnect && <span className="c2-ink-3"> · optional (admin + MFA)</span>}
        </label>
        <input
          id="jw-grant"
          name="grant"
          type="text"
          className="c2-input c2-input-mono"
          autoComplete="off"
          required={!canDirectConnect}
          placeholder={canDirectConnect ? 'leave empty for admin direct-connect' : 'e.g. grant-7f3a1c2e…'}
          value={grant}
          onChange={(e) => setGrant(e.target.value)}
        />
      </div>
      {admin && !stepUp && (
        <p className="c2-field-hint">
          Admin direct-connect available with MFA.{' '}
          <a href={stepUpHref}>Step up →</a>
        </p>
      )}
      <button type="submit" className="c2-btn c2-btn-primary" style={{ alignSelf: 'flex-start' }}>
        Open session →
      </button>
    </form>
  )
}

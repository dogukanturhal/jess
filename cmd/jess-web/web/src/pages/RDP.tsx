// RDP route — ADR 0051 P2c. This is now a thin LAUNCHER: it registers the live
// RDP session into the app-root ConsoleDock and redirects to the inventory, so
// the session (the real ConsoleFrame + RDPCanvas, now in pages/RDPSession.tsx)
// is hosted by the dock and survives navigation. Opening the same target again
// just foregrounds the already-connected session (dock.open is idempotent).
//
// The session node carries its own onMinimize / onClose wired to the dock:
// Minimize → taskbar (stays connected), Disconnect → unmount (closes the WS).
import { useEffect, useRef, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { AppShell, ConsoleOverlay, useConsoleDock } from '../components/c2'
import { RDPSession } from './RDPSession'

type Auth = 'loading' | 'anon' | 'signed_in'

export function RDP() {
  const { targetId } = useParams<{ targetId: string }>()
  const [params] = useSearchParams()
  const grantId = params.get('grant') ?? undefined
  const [auth, setAuth] = useState<Auth>('loading')
  const navigate = useNavigate()
  const { open, minimize, close } = useConsoleDock()
  // Guard against double-launch within a single mount (StrictMode double-invokes
  // effects in dev; the redirect also unmounts us, but belt-and-suspenders).
  const launched = useRef(false)

  useEffect(() => {
    const ctrl = new AbortController()
    fetch('/api/me', { credentials: 'same-origin', cache: 'no-store', signal: ctrl.signal })
      .then((r) => setAuth(r.ok ? 'signed_in' : 'anon'))
      .catch(() => setAuth('anon'))
    return () => ctrl.abort()
  }, [])

  useEffect(() => {
    if (auth !== 'signed_in' || !targetId || launched.current) return
    launched.current = true
    const id = `rdp:${targetId}${grantId ? `:${grantId}` : ''}`
    // open() is idempotent on id — if this target is already docked (e.g. the
    // operator re-clicked it), the original node stays mounted and is simply
    // foregrounded; the node below is only used on first open.
    open({
      id,
      title: targetId,
      proto: 'RDP',
      node: (
        <RDPSession
          key={id}
          targetId={targetId}
          grantId={grantId}
          onMinimize={minimize}
          onClose={() => close(id)}
        />
      ),
    })
    // Hand the page back to the inventory; the session now lives in the dock,
    // shown full-bleed over /targets until the operator minimizes it.
    navigate('/targets', { replace: true })
  }, [auth, targetId, grantId, open, minimize, close, navigate])

  // Pre-redirect / unauthenticated states. Once signed-in the effect redirects
  // immediately, so this only flashes for a frame (or shows the sign-in shell).
  if (auth === 'anon') return <AppShell variant="console" />
  if (!targetId) {
    return (
      <AppShell variant="console" requireAuth={false}>
        <div className="c2-console-body"><div className="c2-note c2-note-warn">No target id.</div></div>
      </AppShell>
    )
  }
  return (
    <AppShell variant="console" requireAuth={false}>
      <div className="c2-console-body">
        <ConsoleOverlay spinner title="Opening console">
          <p className="c2-console-overlay-msg">Launching the RDP session for <span className="c2-mono">{targetId}</span>…</p>
        </ConsoleOverlay>
      </div>
    </AppShell>
  )
}

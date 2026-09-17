// ConsoleDock — an app-root host that lifts LIVE remote-console sessions out of
// their route so they survive navigation. A session opened from /rdp/:targetId
// (and, later, /session, /db-console) is registered here and rendered by the
// dock, which lives OUTSIDE <Routes> in main.tsx — so the session's React node
// (and therefore its WebSocket / decoders) stays MOUNTED while the operator
// browses other pages. That is the whole point: "minimize to background, keep
// the session connected, come back later".
//
// State model:
//   sessions[]  — every live console, each carrying its already-mounted node.
//   activeId    — the one session shown full-bleed over the page; null = all
//                 minimized (the operator sees the underlying route + the
//                 taskbar, and can restore any session from the taskbar).
//
// The dock adds NO window chrome of its own — the session's ConsoleFrame keeps
// its toolbar (minimize / windowed / fullscreen / disconnect). The frame's
// Minimize button hands off to dock.minimize() (see ConsoleFrame `onMinimize`),
// and its Disconnect calls dock.close(), which unmounts the node → the canvas's
// unmount effect closes the WS. The taskbar at the bottom is the cross-nav
// restore surface.
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react'
import { Close } from '@carbon/icons-react'

export interface ConsoleSession {
  /** stable identity (e.g. `rdp:<targetId>`); opening the same id is idempotent. */
  id: string
  /** human label for the taskbar pill (the target id / address). */
  title: string
  /** uppercase protocol chip for the taskbar (RDP / SSH / SQL). */
  proto: string
  /** the already-built session node — kept mounted by the dock across navs. */
  node: ReactNode
}

interface DockApi {
  sessions: ConsoleSession[]
  activeId: string | null
  /** register (or, if the id already exists, just re-show) a live session. */
  open: (s: ConsoleSession) => void
  /** bring an existing session to the foreground. */
  show: (id: string) => void
  /** send the foreground session to the background (taskbar) — stays connected. */
  minimize: () => void
  /** tear a session down — unmounts the node, which closes its transport. */
  close: (id: string) => void
}

const DockContext = createContext<DockApi | null>(null)

export function useConsoleDock(): DockApi {
  const ctx = useContext(DockContext)
  if (!ctx) throw new Error('useConsoleDock must be used within <ConsoleDockProvider>')
  return ctx
}

export function ConsoleDockProvider({ children }: { children: ReactNode }) {
  const [sessions, setSessions] = useState<ConsoleSession[]>([])
  const [activeId, setActiveId] = useState<string | null>(null)

  // Idempotent on id: re-opening a session that's already docked keeps the
  // ORIGINAL node (so the live WS is never remounted) and simply foregrounds it.
  const open = useCallback((s: ConsoleSession) => {
    setSessions((prev) => (prev.some((x) => x.id === s.id) ? prev : [...prev, s]))
    setActiveId(s.id)
  }, [])
  const show = useCallback((id: string) => setActiveId(id), [])
  const minimize = useCallback(() => setActiveId(null), [])
  const close = useCallback((id: string) => {
    setSessions((prev) => prev.filter((x) => x.id !== id))
    setActiveId((cur) => (cur === id ? null : cur))
  }, [])

  const value = useMemo<DockApi>(
    () => ({ sessions, activeId, open, show, minimize, close }),
    [sessions, activeId, open, show, minimize, close],
  )
  return <DockContext.Provider value={value}>{children}</DockContext.Provider>
}

// ConsoleDock — the host + taskbar. Rendered once at app root (outside Routes).
// Each session node is ALWAYS mounted; CSS (display) decides which is on top.
// That keeps every backgrounded session's transport alive.
export function ConsoleDock() {
  const { sessions, activeId, show, close } = useConsoleDock()
  if (sessions.length === 0) return null
  // The tray is a BACKGROUND-sessions tray: it lists only sessions that are NOT
  // currently foregrounded. The active session is already on screen full-bleed,
  // so showing a tray pill for it too is redundant + reads as "minimized while
  // also full-screen". Minimizing the foreground session (ConsoleFrame's
  // Minimize button → dock.minimize) drops it here; clicking its pill restores
  // it. When the only session is foregrounded, the tray is empty → hidden.
  const backgrounded = sessions.filter((s) => s.id !== activeId)
  return (
    <>
      {sessions.map((s) => (
        <div
          key={s.id}
          className="c2-dock-host"
          // display:none keeps the node mounted (live) but hidden; only the
          // active session renders. React never unmounts these on activeId change.
          style={{ display: s.id === activeId ? 'flex' : 'none' }}
          aria-hidden={s.id !== activeId}
        >
          {s.node}
        </div>
      ))}
      {backgrounded.length > 0 && (
        <div className="c2-dock-taskbar" role="toolbar" aria-label="Backgrounded console sessions">
          <span className="c2-dock-taskbar-label">Live sessions</span>
          {backgrounded.map((s) => (
            <div key={s.id} className="c2-dock-pill">
              <button
                type="button"
                className="c2-dock-pill-main"
                onClick={() => show(s.id)}
                title={`Show ${s.proto} · ${s.title} (still connected)`}
              >
                <span className="c2-dock-pill-dot" aria-hidden="true" />
                <span className="c2-dock-pill-proto">{s.proto}</span>
                <span className="c2-dock-pill-title">{s.title}</span>
              </button>
              <button
                type="button"
                className="c2-dock-pill-x"
                onClick={() => close(s.id)}
                title={`Disconnect ${s.proto} · ${s.title}`}
                aria-label={`Disconnect ${s.title}`}
              >
                <Close size={14} />
              </button>
            </div>
          ))}
        </div>
      )}
    </>
  )
}

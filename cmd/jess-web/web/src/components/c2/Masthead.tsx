// Masthead — Carbon UI Shell <Header> command bar: hex logo + wordmark, a
// global "search" action that opens the existing CommandPalette (via a custom
// event so the palette stays globally mounted), the pending-requests alert
// action (admin → /admin/requests), the theme toggle, and the user menu
// (email + admin link + sign-out). Identity comes from /api/me via the
// AuthState the shell holds — no request shapes change.
//
// Rendered as the children of a Carbon <Header> by AppShell (which owns the
// HeaderContainer + menu button + SideNav). This file supplies HeaderName +
// HeaderGlobalBar contents.
import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  HeaderGlobalAction,
  HeaderGlobalBar,
  HeaderName,
} from '@carbon/react'
import { Asleep, Light, Notification, Search as SearchIcon } from '@carbon/icons-react'
import { isAdmin, type Me } from '../../api/me'
import { JessWordmark } from './Brand'

// Open the command palette from anywhere. The palette listens for this event.
export const OPEN_PALETTE_EVENT = 'jess:open-palette'
export function openCommandPalette() {
  window.dispatchEvent(new CustomEvent(OPEN_PALETTE_EVENT))
}

// MastheadContent — slotted INTO a Carbon <Header> by AppShell.
export function Masthead({ me, alerts }: { me: Me | null; alerts: number | null }) {
  const admin = isAdmin(me)
  const navigate = useNavigate()
  return (
    <>
      {/* prefix="" suppresses Carbon HeaderName's default "IBM" prefix span
          (the prop defaults to "IBM" when omitted — that's the stray text by
          the logo). The JESS wordmark SVG is the only brand mark we want. */}
      <HeaderName href="/" prefix="" onClick={onNav(navigate, '/')}>
        <JessWordmark height={16} className="c2-brand-wordmark" title="Jess" />
      </HeaderName>

      <button
        type="button"
        className="c2-masthead-search"
        onClick={openCommandPalette}
        aria-label="Search targets and commands"
      >
        <SearchIcon size={16} aria-hidden="true" />
        <span>Search targets, commands…</span>
        <span className="c2-kbd-hint"><span className="c2-kbd">⌘K</span></span>
      </button>

      <HeaderGlobalBar>
        {admin && (
          <HeaderGlobalAction
            aria-label={alerts ? `${alerts} pending request${alerts === 1 ? '' : 's'}` : 'Pending requests'}
            tooltipAlignment="end"
            onClick={() => navigate('/admin/requests')}
          >
            <span style={{ position: 'relative', display: 'inline-flex' }}>
              <Notification size={20} />
              {alerts != null && alerts > 0 && (
                <span className="c2-icon-badge">{alerts > 99 ? '99+' : alerts}</span>
              )}
            </span>
          </HeaderGlobalAction>
        )}
        <ThemeAction />
        <UserMenu me={me} admin={admin} />
      </HeaderGlobalBar>
    </>
  )
}

function onNav(navigate: ReturnType<typeof useNavigate>, to: string) {
  return (e: React.MouseEvent) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey) return
    e.preventDefault()
    navigate(to)
  }
}

// ThemeAction — flips Carbon g100 ⇄ g10 by toggling data attributes on <html>;
// the SCSS bridge re-themes everything off those. Persists in localStorage
// under the same key the old ThemeToggle used, so the preference carries over.
function ThemeAction() {
  const [dark, setDark] = useState(() => readDark())
  useEffect(() => {
    const root = document.documentElement
    root.setAttribute('data-carbon-theme', dark ? 'g100' : 'g10')
    root.setAttribute('data-theme', dark ? 'dark' : 'light')
    try {
      localStorage.setItem('jess.theme', dark ? 'dark' : 'light')
    } catch { /* best effort */ }
  }, [dark])
  return (
    <HeaderGlobalAction
      aria-label={dark ? 'Switch to light theme' : 'Switch to dark theme'}
      tooltipAlignment="end"
      onClick={() => setDark((v) => !v)}
    >
      {dark ? <Light size={20} /> : <Asleep size={20} />}
    </HeaderGlobalAction>
  )
}

function readDark(): boolean {
  try {
    const stored = localStorage.getItem('jess.theme')
    if (stored === 'light') return false
    if (stored === 'dark') return true
  } catch { /* ignore */ }
  if (window.matchMedia?.('(prefers-color-scheme: light)').matches) return false
  return true // default dark (C2 console)
}

function UserMenu({ me, admin }: { me: Me | null; admin: boolean }) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement | null>(null)
  const navigate = useNavigate()

  useEffect(() => {
    if (!open) return
    function onDocClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    function onKey(e: KeyboardEvent) { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onDocClick)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDocClick)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  if (!me) {
    const ret = encodeURIComponent(window.location.pathname + window.location.search)
    return (
      <a className="c2-btn c2-btn-primary c2-btn-sm" href={`/auth/login?return=${ret}`} style={{ alignSelf: 'center', margin: '0 0.5rem' }}>
        Sign in
      </a>
    )
  }

  const initials = (me.email || me.subject || '?').slice(0, 2)
  return (
    <div className="c2-usermenu" ref={ref}>
      <button
        type="button"
        className="c2-usermenu-trigger"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
      >
        <span className="c2-avatar">{initials}</span>
        <span className="c2-usermenu-caret">▾</span>
      </button>
      {open && (
        <div className="c2-usermenu-pop" role="menu">
          <div className="c2-usermenu-head">
            <div className="c2-usermenu-email">{me.email}</div>
            <div className="c2-usermenu-role">
              {admin ? 'platform_admin' : (me.roles[0] ?? 'operator')}
            </div>
          </div>
          {admin && (
            <button
              type="button"
              role="menuitem"
              className="c2-usermenu-item"
              onClick={() => { setOpen(false); navigate('/admin/requests') }}
            >
              Admin console
            </button>
          )}
          {/* Sign-out stays a real POST to /auth/logout (server clears the
              cookie session) — byte-identical behavior. */}
          <form action="/auth/logout" method="POST">
            <button type="submit" role="menuitem" className="c2-usermenu-item is-danger">
              Sign out
            </button>
          </form>
        </div>
      )}
    </div>
  )
}

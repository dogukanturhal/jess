// Command palette — Cmd+K / Ctrl+K. Modal overlay with a search input
// and filtered action list. Keyboard-first: ↑/↓ moves selection, Enter
// executes, Esc closes. Click outside also closes.
//
// Why pure-React (no cmdk / kbar / etc.): the action set is small
// (<30 items even with target-suggestions expanded), the filter is
// substring not fuzzy, no dep churn for what's essentially a list
// with keyboard nav. Keeps the SPA bundle small.
//
// Globally mounted at the app root so any page can fire it. Actions
// that depend on context (admin: show admin nav) gate on me/isAdmin
// the same way the rest of the SPA does.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchMe, isAdmin, type Me } from '../api/me'
import { useTargetSuggestions } from '../hooks/useTargetSuggestions'
import { OPEN_PALETTE_EVENT } from './c2/Masthead'

interface Action {
  id: string
  label: string
  hint?: string
  run: () => void
}

export function CommandPalette() {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [me, setMe] = useState<Me | null>(null)
  const [active, setActive] = useState(0)
  const inputRef = useRef<HTMLInputElement | null>(null)
  const listRef = useRef<HTMLUListElement | null>(null)
  const navigate = useNavigate()
  const suggestions = useTargetSuggestions()

  // Lazy-fetch me only once (used to gate admin actions).
  useEffect(() => {
    const ctrl = new AbortController()
    fetchMe(ctrl.signal).then((m) => {
      if (!ctrl.signal.aborted) setMe(m)
    }).catch(() => { /* intentional */ })
    return () => ctrl.abort()
  }, [])

  // Global keyboard trigger. Cmd+K on Mac, Ctrl+K elsewhere. Also
  // intercept "/" outside an input — common Vim-style search prefix
  // some operators muscle-memory expect.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const meta = e.metaKey || e.ctrlKey
      if (meta && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setOpen((v) => !v)
        return
      }
      if (open && e.key === 'Escape') {
        e.preventDefault()
        setOpen(false)
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open])

  // Masthead search button opens the palette via this custom event so the
  // palette stays globally mounted + decoupled from the shell chrome.
  useEffect(() => {
    function onOpen() { setOpen(true) }
    window.addEventListener(OPEN_PALETTE_EVENT, onOpen)
    return () => window.removeEventListener(OPEN_PALETTE_EVENT, onOpen)
  }, [])

  // Focus the input when opening.
  useEffect(() => {
    if (open) {
      setQuery('')
      setActive(0)
      // Defer to next tick so the input is in the DOM.
      window.setTimeout(() => inputRef.current?.focus(), 0)
    }
  }, [open])

  const close = useCallback(() => setOpen(false), [])

  const run = useCallback((a: Action) => {
    close()
    // Defer so close() commits before navigation triggers (some
    // routes re-render the modal-mounting tree).
    window.setTimeout(a.run, 0)
  }, [close])

  // Build the action list. Stable references keep the filter cheap.
  const allActions = useMemo<Action[]>(() => {
    const base: Action[] = [
      { id: 'nav-home', label: 'Go to overview', hint: 'inventory dashboard', run: () => navigate('/') },
      { id: 'nav-targets', label: 'Go to targets', hint: 'inventory', run: () => navigate('/targets') },
      { id: 'nav-requests', label: 'Go to requests', hint: 'platform_admin only', run: () => navigate('/admin/requests') },
      { id: 'nav-sessions', label: 'Go to sessions', hint: 'platform_admin only', run: () => navigate('/admin/sessions') },
      { id: 'nav-grants', label: 'Go to grants', hint: 'platform_admin only', run: () => navigate('/admin/grants') },
      { id: 'nav-catalog', label: 'Go to catalog', hint: 'platform_admin only', run: () => navigate('/admin/catalog') },
      { id: 'nav-devices', label: 'Go to device pre-registration', hint: 'platform_admin only', run: () => navigate('/admin/devices') },
      { id: 'nav-audit', label: 'Go to audit', hint: 'platform_admin only', run: () => navigate('/admin/audit') },
      { id: 'nav-recordings', label: 'Go to recordings', run: () => navigate('/rdp/recordings') },
      { id: 'sign-out', label: 'Sign out', hint: 'clears session', run: () => { window.location.href = '/auth/logout' } },
      { id: 'theme', label: 'Toggle theme', hint: 'light ⇄ dark', run: () => {
        const cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light'
        document.documentElement.setAttribute('data-theme', cur)
        try { localStorage.setItem('jess.theme', cur) } catch { /* intentional */ }
      } },
    ]
    // Per-target shortcuts pulled from operator history.
    const perTarget: Action[] = suggestions.flatMap((t) => [
      { id: `open-${t}`, label: `Open session on ${t}`, hint: 'needs grant id or admin direct-connect', run: () => navigate(`/session?target=${encodeURIComponent(t)}`) },
    ])
    return [...base, ...perTarget]
  }, [navigate, suggestions])

  // Filter by substring + gate admin-only on isAdmin.
  const filtered = useMemo<Action[]>(() => {
    const adminOK = isAdmin(me)
    const adminOnly = new Set(['nav-requests', 'nav-sessions', 'nav-grants', 'nav-catalog', 'nav-devices', 'nav-audit'])
    const q = query.trim().toLowerCase()
    return allActions.filter((a) => {
      if (adminOnly.has(a.id) && !adminOK) return false
      if (q === '') return true
      return a.label.toLowerCase().includes(q) || (a.hint?.toLowerCase().includes(q) ?? false)
    })
  }, [allActions, query, me])

  // Bound active index to filtered length.
  useEffect(() => {
    if (active >= filtered.length) setActive(Math.max(0, filtered.length - 1))
  }, [filtered, active])

  if (!open) return null

  return (
    <div className="jw-cmdk-backdrop" onClick={close} role="presentation">
      <div
        className="jw-cmdk"
        role="dialog"
        aria-label="Command palette"
        onClick={(e) => e.stopPropagation()}
      >
        <input
          ref={inputRef}
          type="text"
          className="jw-cmdk-input"
          placeholder="Type a command — admin / target / theme…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'ArrowDown') {
              e.preventDefault()
              setActive((i) => Math.min(filtered.length - 1, i + 1))
            } else if (e.key === 'ArrowUp') {
              e.preventDefault()
              setActive((i) => Math.max(0, i - 1))
            } else if (e.key === 'Enter') {
              e.preventDefault()
              const a = filtered[active]
              if (a) run(a)
            }
          }}
        />
        <ul className="jw-cmdk-list" ref={listRef}>
          {filtered.length === 0 && (
            <li className="jw-cmdk-empty">No matches</li>
          )}
          {filtered.map((a, i) => (
            <li
              key={a.id}
              className={i === active ? 'jw-cmdk-item jw-cmdk-item-active' : 'jw-cmdk-item'}
              onMouseEnter={() => setActive(i)}
              onClick={() => run(a)}
            >
              <span>{a.label}</span>
              {a.hint && <span className="jw-ink-3" style={{ fontSize: 11 }}>{a.hint}</span>}
            </li>
          ))}
        </ul>
        <div className="jw-cmdk-footer">
          <span><kbd>↑</kbd><kbd>↓</kbd> nav</span>
          <span><kbd>↵</kbd> run</span>
          <span><kbd>Esc</kbd> close</span>
        </div>
      </div>
    </div>
  )
}

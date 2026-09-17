// TargetConnect — the row-level "Connect ▾" action used in the Targets grid +
// target detail.
//
// GRANT-AWARE CONNECT (RDP fix + SSH/DB consistency): the primary "Connect"
// item no longer deep-links to a grant-less console URL (which fail-closes on
// grant-gated targets — /ws/rdp-live rejects an empty grant, and the gateway
// strips the WS close reason so the operator only sees a generic transport
// error). Instead it opens the ConnectResolver dialog, which resolves a grant
// (pick an active one / request access / admin-issue) BEFORE navigating to the
// console with ?grant=<id>. Routing targets are unchanged: SSH → /session,
// RDP → /rdp/:id, postgres/mysql → /db-console; non-brokered protocols stay
// CLI-only (the resolver explains the jessctl path).
//
// Still offers the legacy "Request access" deep-link item (Targets.tsx wires
// onRequestAccess to its own dialog) for back-compat.
import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { fetchMe, type Me } from '../../api/me'
import type { CatalogTarget } from '../../api/admin'
import { ConnectResolver } from '../ConnectResolver'

export function TargetConnect({
  target,
  onRequestAccess,
  size = 'sm',
}: {
  target: { id: string; protocol?: string }
  onRequestAccess?: (id: string) => void
  size?: 'sm' | 'md'
}) {
  const [open, setOpen] = useState(false)
  const [resolving, setResolving] = useState(false)
  const [me, setMe] = useState<Me | null>(null)
  const ref = useRef<HTMLDivElement | null>(null)
  const menuRef = useRef<HTMLDivElement | null>(null)
  // The menu is portaled to <body> (see below) so it can't be clipped by the
  // table's overflow container; we therefore position it manually from the
  // trigger button's viewport rect.
  const [menuPos, setMenuPos] = useState<{ top: number; left: number; minWidth: number } | null>(null)
  const proto = (target.protocol ?? '').toLowerCase()

  const toggleMenu = () => {
    setOpen((v) => {
      const next = !v
      if (next && ref.current) {
        const r = ref.current.getBoundingClientRect()
        setMenuPos({ top: r.bottom + 4, left: r.left, minWidth: r.width })
      }
      return next
    })
  }

  // Lazily resolve identity so the resolver's admin-issue path works from any
  // call site (Targets / TargetDetail / Admin catalog) without threading `me`
  // through props. Anonymous / 503 → null (non-admin resolver behaviour).
  useEffect(() => {
    const ctrl = new AbortController()
    fetchMe(ctrl.signal).then((m) => { if (!ctrl.signal.aborted) setMe(m) }).catch(() => { /* non-admin fallback */ })
    return () => ctrl.abort()
  }, [])

  useEffect(() => {
    if (!open) return
    function onDoc(e: MouseEvent) {
      const t = e.target as Node
      // The menu is portaled out of `ref`, so check both the trigger and the menu.
      if (ref.current?.contains(t) || menuRef.current?.contains(t)) return
      setOpen(false)
    }
    function onReflow() { setOpen(false) }
    document.addEventListener('mousedown', onDoc)
    // The portaled menu is positioned from a one-shot rect; close it on
    // scroll/resize rather than letting it float at a stale location.
    window.addEventListener('scroll', onReflow, true)
    window.addEventListener('resize', onReflow)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      window.removeEventListener('scroll', onReflow, true)
      window.removeEventListener('resize', onReflow)
    }
  }, [open])

  const brokered = proto === 'ssh' || proto === 'rdp' || proto === 'postgres' || proto === 'mysql'
  const connectLabel =
    proto === 'ssh' ? 'Open SSH session' :
    proto === 'rdp' ? 'Open RDP canvas' :
    (proto === 'postgres' || proto === 'mysql') ? `Open ${proto.toUpperCase()} console` :
    null

  const sizeCls = size === 'sm' ? 'c2-btn-sm' : ''

  return (
    <>
      <div className="c2-btn-split" ref={ref}>
        <button
          type="button"
          className={`c2-btn c2-btn-primary ${sizeCls}`}
          onClick={toggleMenu}
          aria-haspopup="menu"
          aria-expanded={open}
        >
          Connect <span style={{ fontSize: 9 }}>▾</span>
        </button>
        {open && menuPos && createPortal(
          <div
            ref={menuRef}
            className="c2-btn-split-menu"
            role="menu"
            style={{ position: 'fixed', top: menuPos.top, left: menuPos.left, right: 'auto', bottom: 'auto', minWidth: menuPos.minWidth, zIndex: 9000 }}
          >
            {brokered && connectLabel ? (
              <button
                className="c2-menu-item"
                role="menuitem"
                onClick={() => { setOpen(false); setResolving(true) }}
                title="Resolve a just-in-time grant, then open the console"
              >
                {connectLabel}
                <span className="c2-menu-item-hint">{proto}</span>
              </button>
            ) : (
              <button className="c2-menu-item" disabled role="menuitem" title={`${proto.toUpperCase()} targets use the jessctl CLI: jessctl ${proto}-bridge ${target.id}`}>
                jessctl only
                <span className="c2-menu-item-hint">{proto || '—'}</span>
              </button>
            )}
            {onRequestAccess && (
              <button
                className="c2-menu-item"
                role="menuitem"
                onClick={() => { setOpen(false); onRequestAccess(target.id) }}
              >
                Request access…
              </button>
            )}
          </div>,
          document.body,
        )}
      </div>
      {resolving && (
        <ConnectResolver target={target} me={me} onClose={() => setResolving(false)} />
      )}
    </>
  )
}

// SourceBadge — colours the discovery provider name.
export function SourceBadge({ source }: { source?: string }) {
  return <span className="c2-tag">{source ?? 'unknown'}</span>
}

// CriticalityCell renders criticality as a toned badge.
export function CriticalityBadge({ value }: { value?: string }) {
  if (!value) return <span className="c2-ink-3">—</span>
  const v = value.toLowerCase()
  const tone =
    v === 'critical' ? 'c2-badge-danger' :
    v === 'high' ? 'c2-badge-warn' :
    v === 'medium' ? 'c2-badge-info' :
    'c2-badge-mute'
  return <span className={`c2-badge ${tone}`} style={{ paddingLeft: 7 }}>{value}</span>
}

export function protocolGroupOf(t: CatalogTarget): 'ssh' | 'rdp' | 'db' | 'other' {
  const p = (t.protocol ?? '').toLowerCase()
  if (p === 'ssh') return 'ssh'
  if (p === 'rdp') return 'rdp'
  if (p === 'postgres' || p === 'mysql') return 'db'
  return 'other'
}

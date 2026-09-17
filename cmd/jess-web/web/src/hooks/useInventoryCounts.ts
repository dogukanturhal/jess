// useInventoryCounts — powers the inventory rail badges + masthead alert
// indicator. Best-effort: every source is optional and failures degrade to
// the previous/zero value (the rail must never error out the whole shell).
//
// Sources (all existing endpoints, unchanged shapes):
//   /api/admin/catalog        → per-protocol target counts (admin only)
//   adminListRequests('pending') → pending-request alert count (admin only)
//   adminListSessions()       → live session count (admin only)
//   fetchMySessions()         → live session count fallback for operators
//
// Admin-only endpoints 403 for non-admins; we swallow that and the rail just
// shows no counts for those groups (same data visibility the SPA already had).
import { useEffect, useState } from 'react'
import { adminListRequests, adminListSessions } from '../api/admin'
import { fetchMySessions } from '../api/sessions'

export interface InventoryCounts {
  targets: { total: number; ssh: number; rdp: number; db: number; other: number } | null
  liveSessions: number | null
  pendingRequests: number | null
}

const EMPTY: InventoryCounts = { targets: null, liveSessions: null, pendingRequests: null }

export function useInventoryCounts(isAdmin: boolean, refreshMs = 30_000): InventoryCounts {
  const [counts, setCounts] = useState<InventoryCounts>(EMPTY)

  useEffect(() => {
    let alive = true
    const ctrl = new AbortController()

    async function loadTargets() {
      if (!isAdmin) return
      try {
        const r = await fetch('/api/admin/catalog', { credentials: 'same-origin', cache: 'no-store', signal: ctrl.signal })
        if (!r.ok) return
        const rows = (await r.json()) as Array<{ protocol?: string }>
        const t = { total: rows.length, ssh: 0, rdp: 0, db: 0, other: 0 }
        for (const row of rows) {
          const p = (row.protocol ?? '').toLowerCase()
          if (p === 'ssh') t.ssh++
          else if (p === 'rdp') t.rdp++
          else if (p === 'postgres' || p === 'mysql') t.db++
          else t.other++
        }
        if (alive) setCounts((prev) => ({ ...prev, targets: t }))
      } catch { /* best-effort */ }
    }

    async function loadSessions() {
      try {
        if (isAdmin) {
          const rows = await adminListSessions(ctrl.signal)
          const live = rows.filter((s) => s.active).length
          if (alive) setCounts((prev) => ({ ...prev, liveSessions: live }))
        } else {
          const rows = await fetchMySessions(50, ctrl.signal)
          const live = rows.filter((s) => s.active).length
          if (alive) setCounts((prev) => ({ ...prev, liveSessions: live }))
        }
      } catch { /* best-effort */ }
    }

    async function loadRequests() {
      if (!isAdmin) return
      try {
        const rows = await adminListRequests('pending', ctrl.signal)
        if (alive) setCounts((prev) => ({ ...prev, pendingRequests: rows.length }))
      } catch { /* best-effort */ }
    }

    function loadAll() {
      void loadTargets()
      void loadSessions()
      void loadRequests()
    }
    loadAll()
    const t = window.setInterval(loadAll, refreshMs)
    return () => {
      alive = false
      ctrl.abort()
      window.clearInterval(t)
    }
  }, [isAdmin, refreshMs])

  return counts
}

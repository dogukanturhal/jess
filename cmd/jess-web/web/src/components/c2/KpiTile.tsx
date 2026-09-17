// KpiTile — dashboard stat tile on Carbon Tile / ClickableTile. Optional `to`
// makes the whole tile a router link (used to deep-link a KPI to its inventory
// rail route); SPA routing is preserved by intercepting ClickableTile's click.
import type { MouseEvent, ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { ClickableTile, Tile } from '@carbon/react'

export function KpiTile({
  label,
  value,
  hint,
  icon,
  accent = false,
  to,
}: {
  label: ReactNode
  value: ReactNode
  hint?: ReactNode
  icon?: ReactNode
  accent?: boolean
  to?: string
}) {
  const navigate = useNavigate()
  const inner = (
    <>
      <span className="c2-kpi-label">
        {icon && <span className="c2-kpi-icon">{icon}</span>}
        {label}
      </span>
      <span className="c2-kpi-value">{value}</span>
      {hint != null && <span className="c2-kpi-hint">{hint}</span>}
    </>
  )
  const cls = `c2-kpi${accent ? ' c2-kpi-accent' : ''}`
  if (to) {
    // ClickableTile renders an <a href>; intercept the click to route
    // client-side (preserving SPA nav) while keeping the real href so
    // middle-click / open-in-new-tab still works.
    return (
      <ClickableTile
        href={to}
        className={cls}
        onClick={(e: MouseEvent<HTMLAnchorElement>) => {
          if (e.metaKey || e.ctrlKey || e.shiftKey || e.button === 1) return
          e.preventDefault()
          navigate(to)
        }}
      >
        {inner}
      </ClickableTile>
    )
  }
  return <Tile className={cls}>{inner}</Tile>
}

export function KpiRow({ children }: { children: ReactNode }) {
  return <div className="c2-kpi-row">{children}</div>
}

// Panel — bordered surface (Carbon Tile) with an optional header (title + sub +
// actions). The body slot is unpadded by default so DataGrids sit flush; use
// `pad` for key-value / prose content. Carbon Tile's own padding is zeroed so
// the existing c2-panel-head / c2-panel-pad rules drive the internal spacing.
import type { ReactNode } from 'react'
import { Tile } from '@carbon/react'

export function Panel({
  title,
  subtitle,
  icon,
  actions,
  pad = false,
  children,
  className,
}: {
  title?: ReactNode
  subtitle?: ReactNode
  icon?: ReactNode
  actions?: ReactNode
  pad?: boolean
  children?: ReactNode
  className?: string
}) {
  const hasHead = title != null || actions != null || subtitle != null
  return (
    <Tile className={`c2-panel${className ? ` ${className}` : ''}`} style={{ padding: 0 }}>
      {hasHead && (
        <header className="c2-panel-head">
          <div>
            {title != null && (
              <h2 className="c2-panel-title">
                {icon && <span className="c2-panel-icon">{icon}</span>}
                {title}
              </h2>
            )}
            {subtitle != null && <p className="c2-panel-sub">{subtitle}</p>}
          </div>
          {actions != null && <div className="c2-panel-head-actions">{actions}</div>}
        </header>
      )}
      <div className={pad ? 'c2-panel-body c2-panel-pad' : 'c2-panel-body'}>{children}</div>
    </Tile>
  )
}

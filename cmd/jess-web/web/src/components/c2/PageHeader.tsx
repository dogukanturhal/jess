// PageHeader — breadcrumb + title (+ optional badge/subtitle) + right-aligned
// action toolbar. Sticky to the top of the content scroll area.
import { Fragment, type ReactNode } from 'react'
import { Link } from 'react-router-dom'

export interface Crumb {
  label: ReactNode
  to?: string
}

export function PageHeader({
  crumbs,
  title,
  badge,
  subtitle,
  actions,
}: {
  crumbs?: Crumb[]
  title: ReactNode
  badge?: ReactNode
  subtitle?: ReactNode
  actions?: ReactNode
}) {
  return (
    <div className="c2-page-header">
      {crumbs && crumbs.length > 0 && (
        <nav className="c2-breadcrumb" aria-label="Breadcrumb">
          {crumbs.map((c, i) => (
            <Fragment key={i}>
              {i > 0 && <span className="c2-breadcrumb-sep">▸</span>}
              {c.to ? <Link to={c.to}>{c.label}</Link> : <span>{c.label}</span>}
            </Fragment>
          ))}
        </nav>
      )}
      <div className="c2-page-header-row">
        <div style={{ minWidth: 0 }}>
          <h1 className="c2-page-title">
            {title}
            {badge}
          </h1>
          {subtitle != null && <p className="c2-page-subtitle">{subtitle}</p>}
        </div>
        {actions != null && <div className="c2-page-actions">{actions}</div>}
      </div>
    </div>
  )
}

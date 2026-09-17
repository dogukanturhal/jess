// InventoryRail — Carbon UI Shell <SideNav> left command-center navigation.
// Grouped: Targets (expandable Carbon SideNavMenu with per-protocol SSH/RDP/DB
// sub-rows), Sessions (live), Recordings; Control group (Requests/Grants/
// Catalog/Audit) when platform_admin. Active route → Carbon's isActive styling.
//
// The same props are preserved (admin, collapsed, counts, targetsOpen, …) so
// AppShell's localStorage-backed collapse/targets state still drives it. Carbon
// SideNav owns its own rail/expanded visuals; `expanded` is wired to the
// inverse of `collapsed` so the existing collapse toggle keeps working.
import {
  SideNav,
  SideNavItems,
  SideNavLink,
  SideNavMenu,
  SideNavMenuItem,
} from '@carbon/react'
import {
  Catalog,
  ChartColumn,
  ChevronLeft,
  ChevronRight,
  DataBase,
  Devices,
  Events,
  InventoryManagement,
  ScreenMap,
  Terminal,
  WatsonHealthTextAnnotationToggle,
} from '@carbon/icons-react'
import { useLocation, useNavigate } from 'react-router-dom'
import type { InventoryCounts } from '../../hooks/useInventoryCounts'

interface Props {
  admin: boolean
  /** icon-rail mode — show icons only, no labels. */
  collapsed: boolean
  /** Carbon SideNav expanded state. On wide viewports this tracks the inverse
      of `collapsed`; on narrow viewports it's the overlay open/close state the
      hamburger drives. Defaults to `!collapsed` so existing callers behave as
      before. */
  expanded?: boolean
  /** narrow viewport — Carbon renders the rail as an off-canvas overlay. */
  overlay?: boolean
  onToggleCollapse: () => void
  counts: InventoryCounts
  targetsOpen: boolean
  onToggleTargets: () => void
}

function isActive(pathname: string, to: string, exact = false): boolean {
  if (exact) return pathname === to
  return pathname === to || pathname.startsWith(to + '/')
}

export function InventoryRail({
  admin,
  collapsed,
  expanded,
  overlay = false,
  onToggleCollapse,
  counts,
  targetsOpen,
}: Props) {
  // Default `expanded` to the inverse of collapsed for callers that don't pass
  // it (preserves the pre-hamburger behavior). On narrow/overlay viewports the
  // rail must show full labels when open, so it's never an icon-rail there.
  const railExpanded = expanded ?? !collapsed
  const railIsRail = overlay ? false : collapsed
  // onToggleTargets is part of Props (AppShell still passes it) but Carbon's
  // SideNavMenu owns its own expand/collapse — we seed it with the persisted
  // `targetsOpen` via defaultExpanded instead of driving it externally.
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const t = counts.targets

  // SPA nav: keep the real href (middle-click / new-tab) but route client-side.
  const go = (to: string) => (e: React.MouseEvent) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey) return
    e.preventDefault()
    navigate(to)
  }

  return (
    <SideNav
      aria-label="Inventory navigation"
      expanded={railExpanded}
      isRail={railIsRail}
      isPersistent={!overlay}
      className="c2-rail"
    >
      <SideNavItems>
        {/* Targets — expandable group with per-protocol sub-rows */}
        <SideNavMenu
          title="Targets"
          renderIcon={ScreenMap}
          defaultExpanded={targetsOpen}
          isActive={isActive(pathname, '/targets') || isActive(pathname, '/', true)}
        >
          <SideNavMenuItem href="/targets" isActive={isActive(pathname, '/targets', true)} onClick={go('/targets')}>
            All targets{t != null ? ` · ${t.total}` : ''}
          </SideNavMenuItem>
          <SideNavMenuItem href="/targets?protocol=ssh" onClick={go('/targets?protocol=ssh')}>
            SSH{t != null ? ` · ${t.ssh}` : ''}
          </SideNavMenuItem>
          <SideNavMenuItem href="/targets?protocol=rdp" onClick={go('/targets?protocol=rdp')}>
            RDP{t != null ? ` · ${t.rdp}` : ''}
          </SideNavMenuItem>
          <SideNavMenuItem href="/targets?protocol=db" onClick={go('/targets?protocol=db')}>
            Databases{t != null ? ` · ${t.db}` : ''}
          </SideNavMenuItem>
        </SideNavMenu>

        <SideNavLink
          renderIcon={Terminal}
          href="/admin/sessions"
          isActive={isActive(pathname, '/admin/sessions')}
          onClick={go('/admin/sessions')}
        >
          Sessions{counts.liveSessions != null ? ` · ${counts.liveSessions}` : ''}
        </SideNavLink>
        <SideNavLink
          renderIcon={DataBase}
          href="/rdp/recordings"
          isActive={isActive(pathname, '/rdp/recordings') || isActive(pathname, '/recordings')}
          onClick={go('/rdp/recordings')}
        >
          Recordings
        </SideNavLink>

        {admin && (
          <>
            <SideNavLink
              renderIcon={Events}
              href="/admin/requests"
              isActive={isActive(pathname, '/admin/requests')}
              onClick={go('/admin/requests')}
            >
              Requests{counts.pendingRequests != null ? ` · ${counts.pendingRequests}` : ''}
            </SideNavLink>
            <SideNavLink
              renderIcon={WatsonHealthTextAnnotationToggle}
              href="/admin/grants"
              isActive={isActive(pathname, '/admin/grants')}
              onClick={go('/admin/grants')}
            >
              Grants
            </SideNavLink>
            <SideNavLink
              renderIcon={Catalog}
              href="/admin/catalog"
              isActive={isActive(pathname, '/admin/catalog')}
              onClick={go('/admin/catalog')}
            >
              Catalog
            </SideNavLink>
            <SideNavLink
              renderIcon={InventoryManagement}
              href="/admin/pending"
              isActive={isActive(pathname, '/admin/pending')}
              onClick={go('/admin/pending')}
            >
              Discovery
            </SideNavLink>
            <SideNavLink
              renderIcon={Devices}
              href="/admin/devices"
              isActive={isActive(pathname, '/admin/devices')}
              onClick={go('/admin/devices')}
            >
              Devices
            </SideNavLink>
            <SideNavLink
              renderIcon={ChartColumn}
              href="/admin/audit"
              isActive={isActive(pathname, '/admin/audit')}
              onClick={go('/admin/audit')}
            >
              Audit
            </SideNavLink>
          </>
        )}

        {/* Bottom collapse toggle — a secondary control mirroring the masthead
            hamburger. Hidden on narrow/overlay where the hamburger is the only
            (and unambiguous) control. */}
        {!overlay && (
          <SideNavLink
            renderIcon={collapsed ? ChevronRight : ChevronLeft}
            href="#"
            onClick={(e: React.MouseEvent) => { e.preventDefault(); onToggleCollapse() }}
            className="c2-rail-collapse"
          >
            {collapsed ? 'Expand' : 'Collapse'}
          </SideNavLink>
        )}
      </SideNavItems>
    </SideNav>
  )
}

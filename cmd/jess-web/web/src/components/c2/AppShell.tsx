// AppShell — the C2 frame on Carbon's UI Shell: a fixed Carbon <Header>
// (masthead) + a Carbon <SideNav> inventory rail + a scrollable content slot.
// Owns rail collapse + Targets-group expansion (both persisted to localStorage)
// and the inventory counts feed — exactly as before; only the chrome is now
// Carbon's UI Shell.
//
// Variants:
//   default  → header + rail + content (management surfaces)
//   console  → header + content, NO rail (live SSH/RDP/SQL/replay pages get the
//              chrome but reclaim full width for the viewport)
//
// Anonymous browsers (anyone, any route, when requireAuth) see a clean C2
// sign-in screen instead of any inventory — the same privacy-by-default
// posture the old Landing had.
import { useEffect, useState, type ReactNode } from 'react'
import { Header, HeaderContainer, HeaderMenuButton, SkipToContent } from '@carbon/react'
import { isAdmin, type Me } from '../../api/me'
import { useInventoryCounts } from '../../hooks/useInventoryCounts'
import { useMe } from '../../hooks/useMe'
import { JessWordmark } from './Brand'
import { InventoryRail } from './InventoryRail'
import { Masthead } from './Masthead'

const COLLAPSE_KEY = 'jess.rail.collapsed'
const TARGETS_KEY = 'jess.rail.targets.open'

// Below this width the sidebar auto-collapses to the icon rail (Carbon turns
// it into an overlay too). Matches the c2.css `@media (max-width: 66rem)` rule
// so the chrome geometry and the JS view of "narrow" stay in lockstep.
const NARROW_QUERY = '(max-width: 66rem)'

// useNarrowViewport — reactive boolean for the narrow breakpoint. Used so the
// hamburger flips between "toggle the persisted icon-rail" (wide) and "open the
// Carbon overlay nav" (narrow), and so the rail auto-collapses on small screens.
function useNarrowViewport(): boolean {
  const [narrow, setNarrow] = useState(() => {
    try { return window.matchMedia(NARROW_QUERY).matches } catch { return false }
  })
  useEffect(() => {
    let mql: MediaQueryList
    try { mql = window.matchMedia(NARROW_QUERY) } catch { return }
    const onChange = (e: MediaQueryListEvent) => setNarrow(e.matches)
    setNarrow(mql.matches)
    mql.addEventListener('change', onChange)
    return () => mql.removeEventListener('change', onChange)
  }, [])
  return narrow
}

function readBool(key: string, fallback: boolean): boolean {
  try {
    const v = localStorage.getItem(key)
    if (v === '1') return true
    if (v === '0') return false
  } catch { /* ignore */ }
  return fallback
}
function writeBool(key: string, v: boolean) {
  try { localStorage.setItem(key, v ? '1' : '0') } catch { /* ignore */ }
}

export function AppShell({
  children,
  variant = 'default',
  requireAuth = true,
}: {
  children?: ReactNode
  variant?: 'default' | 'console'
  /** when false, render the shell + content even for anon (e.g. pages with
      their own in-content sign-in CTA). Default true → anon sees sign-in. */
  requireAuth?: boolean
}) {
  const auth = useMe()
  const me: Me | null = auth.kind === 'signed_in' ? auth.me : null
  const admin = isAdmin(me)
  const counts = useInventoryCounts(admin)

  const [collapsedPref, setCollapsedPref] = useState(() => readBool(COLLAPSE_KEY, false))
  const [targetsOpen, setTargetsOpen] = useState(() => readBool(TARGETS_KEY, true))
  const narrow = useNarrowViewport()

  // On narrow viewports the rail is always the icon rail (Carbon also turns it
  // into an overlay). On wide viewports it follows the operator's persisted
  // preference. The hamburger only mutates the persisted preference on wide
  // screens; on narrow it drives Carbon's overlay open/close instead.
  const collapsed = narrow || collapsedPref

  function toggleCollapse() {
    setCollapsedPref((c) => { writeBool(COLLAPSE_KEY, !c); return !c })
  }
  function toggleTargets() {
    setTargetsOpen((o) => { writeBool(TARGETS_KEY, !o); return !o })
  }

  if (auth.kind === 'loading') {
    return (
      <div className="c2-signin-screen">
        <div className="c2-signin-mark"><JessWordmark height={28} title="Jess" /></div>
      </div>
    )
  }

  if (requireAuth && me == null) {
    return <SignInScreen oidcDisabled={auth.kind === 'oidc_disabled'} />
  }

  // Console variant — Carbon Header (no rail) + full-bleed content column.
  if (variant === 'console') {
    return (
      <div className={`c2-shell is-console${collapsed ? ' is-collapsed' : ''}`}>
        <Header aria-label="Hexxlock Jess console" className="c2-shell-masthead">
          <SkipToContent />
          <Masthead me={me} alerts={counts.pendingRequests} />
        </Header>
        <div className="c2-shell-console-content">{children}</div>
      </div>
    )
  }

  // Default variant — the masthead hamburger is the primary sidebar toggle.
  //   wide   → toggles the persisted collapse (full labels ⇄ icon rail).
  //   narrow → drives Carbon's overlay SideNav open/close (the rail is an
  //            off-canvas overlay there; HeaderContainer owns isSideNavExpanded).
  return (
    <HeaderContainer
      render={({ isSideNavExpanded, onClickSideNavExpand }: {
        isSideNavExpanded: boolean
        onClickSideNavExpand: () => void
      }) => {
        // What the hamburger represents right now (for a11y labels).
        const navOpen = narrow ? isSideNavExpanded : !collapsedPref
        const onHamburger = narrow ? onClickSideNavExpand : toggleCollapse
        return (
        <div className={`c2-shell${collapsed ? ' is-collapsed' : ''}`}>
          <Header aria-label="Hexxlock Jess" className="c2-shell-masthead">
            <SkipToContent />
            <HeaderMenuButton
              aria-label={navOpen ? 'Collapse navigation' : 'Expand navigation'}
              onClick={onHamburger}
              isActive={narrow ? isSideNavExpanded : !collapsedPref}
              aria-expanded={navOpen}
            />
            <Masthead me={me} alerts={counts.pendingRequests} />
          </Header>
          <div className="c2-shell-rail">
            <InventoryRail
              admin={admin}
              collapsed={collapsed}
              expanded={narrow ? isSideNavExpanded : !collapsedPref}
              overlay={narrow}
              onToggleCollapse={toggleCollapse}
              counts={counts}
              targetsOpen={targetsOpen}
              onToggleTargets={toggleTargets}
            />
          </div>
          <div className="c2-shell-content" id="main-content">{children}</div>
        </div>
        )
      }}
    />
  )
}

// SignInScreen — clean C2 sign-in (replaces the old marketing hero).
function SignInScreen({ oidcDisabled }: { oidcDisabled: boolean }) {
  const ret = encodeURIComponent(window.location.pathname + window.location.search)
  return (
    <div className="c2-signin-screen">
      <div className="c2-signin-card">
        <div className="c2-signin-mark"><JessWordmark height={40} title="Jess" /></div>
        <p className="c2-signin-sub">
          Privileged-access command center. Every connection is bound to a
          verified Falcon-ID identity, a just-in-time grant, and a
          tamper-evident recording.
        </p>
        {oidcDisabled ? (
          <p className="c2-note c2-note-warn" style={{ textAlign: 'left' }}>
            OIDC isn't configured on this jess-web pod
            (<code>JESS_OIDC_CLIENT_ID</code> + <code>JESS_OIDC_REDIRECT_URL</code> unset).
            Sign-in won't work until the public-exposure MR is applied.
          </p>
        ) : (
          <a className="c2-btn c2-btn-primary" href={`/auth/login?return=${ret}`}>
            Sign in →
          </a>
        )}
        <div className="c2-signin-foot">ADR 0030 · no identity → no console</div>
      </div>
    </div>
  )
}

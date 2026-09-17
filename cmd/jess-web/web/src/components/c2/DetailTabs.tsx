// DetailTabs — object-detail tab strip (Summary / Sessions / Recordings / ACL).
// Controlled: caller owns the active key (so it can be URL-driven later).
//
// Built on Carbon's ContentSwitcher + Switch. ContentSwitcher is index-based,
// so we map the controlled `active` key <-> the tab index and translate
// Carbon's onChange({ index, name }) back into the caller's key-based onChange.
import type { ReactNode } from 'react'
import { ContentSwitcher, Switch } from '@carbon/react'

export interface TabDef {
  key: string
  label: ReactNode
  count?: number
}

export function DetailTabs({
  tabs,
  active,
  onChange,
}: {
  tabs: TabDef[]
  active: string
  onChange: (key: string) => void
}) {
  // Keep ContentSwitcher in sync with the controlled `active` prop on every
  // render. Fall back to 0 if `active` isn't found so we never pass -1.
  const activeIndex = Math.max(
    0,
    tabs.findIndex((t) => t.key === active),
  )

  return (
    <ContentSwitcher
      className="c2-tabs"
      size="sm"
      selectedIndex={activeIndex}
      onChange={({ index, name }) => {
        // Prefer the Switch `name` (the tab key) when present; otherwise
        // resolve the key from the selected index.
        const key =
          typeof name === 'string'
            ? name
            : typeof index === 'number'
              ? tabs[index]?.key
              : undefined
        if (key != null) onChange(key)
      }}
    >
      {tabs.map((t) => (
        <Switch key={t.key} name={t.key}>
          {t.label}
          {t.count != null && <span className="c2-tab-count">{t.count}</span>}
        </Switch>
      ))}
    </ContentSwitcher>
  )
}

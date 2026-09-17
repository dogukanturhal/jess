// KeyValueList — the Summary-tab key/value grid (dense, hairline rows).
import type { ReactNode } from 'react'

export interface KVItem {
  key: ReactNode
  value: ReactNode
}

export function KeyValueList({ items }: { items: KVItem[] }) {
  return (
    <dl className="c2-kv">
      {items.map((it, i) => (
        <div className="c2-kv-row" key={i}>
          <dt className="c2-kv-key">{it.key}</dt>
          <dd className="c2-kv-val">{it.value ?? <span className="c2-ink-3">—</span>}</dd>
        </div>
      ))}
    </dl>
  )
}

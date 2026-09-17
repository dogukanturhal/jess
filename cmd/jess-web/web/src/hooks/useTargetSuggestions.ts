// useTargetSuggestions — pulls a deduped list of target ids the operator
// has touched recently (from their own sessions + requests) so the
// connect / request forms can offer native HTML <datalist> autocomplete.
//
// Why pure-client + HTML5 <datalist>: no backend work, no fancy
// combobox library, free keyboard nav + accessibility. The dataset is
// at most a few dozen entries (operator's own history); rendering as
// <option>s is trivial.
//
// Cache: fetches once per page-mount. The user's history list is
// stable on a typical session; not worth re-polling on a timer.
import { useEffect, useState } from 'react'
import { fetchMyRequests } from '../api/requests'
import { fetchMySessions } from '../api/sessions'

export function useTargetSuggestions(): string[] {
  const [targets, setTargets] = useState<string[]>([])

  useEffect(() => {
    const ctrl = new AbortController()
    Promise.allSettled([
      fetchMyRequests(ctrl.signal),
      fetchMySessions(50, ctrl.signal),
    ]).then((results) => {
      if (ctrl.signal.aborted) return
      const set = new Set<string>()
      for (const r of results) {
        if (r.status !== 'fulfilled') continue
        for (const row of r.value as { target_id?: string }[]) {
          if (row.target_id) set.add(row.target_id)
        }
      }
      // Sorted alphabetically — predictable for the operator's eye
      // when typing. The browser's datalist UI doesn't filter our
      // sort, so this is the on-screen order.
      setTargets(Array.from(set).sort())
    })
    return () => ctrl.abort()
  }, [])

  return targets
}

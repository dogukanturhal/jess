// DataGrid — dense, sortable command-center table rendered on IBM Carbon's
// DataTable primitives (Table / TableHead / TableHeader / TableBody / …).
//
// Generic over the row type. Columns declare a header, a cell renderer, and
// optionally a `sortValue` (string | number) that powers click-to-sort on the
// header. Numeric alignment, optional row actions column, optional checkbox
// selection, and an empty state.
//
// We keep DataGrid's own sort + selection STATE (useState/useMemo) and use the
// Carbon table components purely for presentation — wiring TableHeader's
// isSortable/isSortHeader/sortDirection + TableSelectAll/TableSelectRow to the
// existing handlers. This preserves every consumer's data path and behavior.
//
// Pure presentation — it never fetches. Callers pass already-loaded rows so
// every existing data path (and its auth/error handling) is untouched.
import { useMemo, useState, type ReactNode } from 'react'
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableHeader,
  TableRow,
  TableSelectAll,
  TableSelectRow,
} from '@carbon/react'
import type { DataTableSortState } from '@carbon/react'

export interface Column<T> {
  key: string
  header: ReactNode
  /** cell renderer */
  cell: (row: T) => ReactNode
  /** value used for sorting; omit to make the column non-sortable */
  sortValue?: (row: T) => string | number
  numeric?: boolean
  width?: number | string
}

interface Props<T> {
  rows: T[]
  columns: Column<T>[]
  rowKey: (row: T) => string
  /** initial sort column key */
  defaultSort?: { key: string; dir: 'asc' | 'desc' }
  /** per-row action cell (right-aligned) */
  actions?: (row: T) => ReactNode
  /** whole-row click (e.g. open detail) */
  onRowClick?: (row: T) => void
  /** selection */
  selectable?: boolean
  selected?: Set<string>
  onSelectChange?: (next: Set<string>) => void
  isRowSelected?: (row: T) => boolean
  empty?: ReactNode
  className?: string
}

export function DataGrid<T>({
  rows,
  columns,
  rowKey,
  defaultSort,
  actions,
  onRowClick,
  selectable = false,
  selected,
  onSelectChange,
  empty = 'No rows.',
  className,
}: Props<T>) {
  const [sort, setSort] = useState<{ key: string; dir: 'asc' | 'desc' } | null>(
    defaultSort ?? null,
  )

  const sorted = useMemo(() => {
    if (!sort) return rows
    const col = columns.find((c) => c.key === sort.key)
    if (!col?.sortValue) return rows
    const sv = col.sortValue
    const factor = sort.dir === 'asc' ? 1 : -1
    return [...rows].sort((a, b) => {
      const va = sv(a)
      const vb = sv(b)
      if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * factor
      return String(va).localeCompare(String(vb)) * factor
    })
  }, [rows, sort, columns])

  function toggleSort(col: Column<T>) {
    if (!col.sortValue) return
    setSort((prev) => {
      if (!prev || prev.key !== col.key) return { key: col.key, dir: 'asc' }
      return { key: col.key, dir: prev.dir === 'asc' ? 'desc' : 'asc' }
    })
  }

  const allSelected = selectable && selected != null && sorted.length > 0 &&
    sorted.every((r) => selected.has(rowKey(r)))
  const someSelected = selectable && selected != null && selected.size > 0 && !allSelected

  function toggleAll() {
    if (!onSelectChange) return
    if (allSelected) {
      onSelectChange(new Set())
    } else {
      onSelectChange(new Set(sorted.map(rowKey)))
    }
  }
  function toggleOne(id: string) {
    if (!onSelectChange || !selected) return
    const next = new Set(selected)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    onSelectChange(next)
  }

  const colCount = columns.length + (selectable ? 1 : 0) + (actions ? 1 : 0)

  // Map our asc/desc/none → Carbon's sort state for a given column.
  function sortStateFor(col: Column<T>): DataTableSortState {
    if (!col.sortValue) return 'NONE'
    if (sort?.key !== col.key) return 'NONE'
    return sort.dir === 'asc' ? 'ASC' : 'DESC'
  }

  return (
    <TableContainer className={`c2-grid-wrap${className ? ` ${className}` : ''}`}>
      <Table size="sm" isSortable={columns.some((c) => c.sortValue != null)} className="c2-grid">
        <TableHead>
          <TableRow>
            {selectable && (
              <TableSelectAll
                id="c2-grid-select-all"
                name="c2-grid-select-all"
                aria-label="Select all rows"
                checked={!!allSelected}
                indeterminate={someSelected}
                onSelect={toggleAll}
              />
            )}
            {columns.map((col) => {
              const sortable = col.sortValue != null
              const sortDir = sortStateFor(col)
              return (
                <TableHeader
                  key={col.key}
                  className={col.numeric ? 'is-numeric' : undefined}
                  style={{
                    ...(col.width ? { width: col.width } : null),
                    ...(col.numeric ? { textAlign: 'right' as const } : null),
                  }}
                  isSortable={sortable}
                  isSortHeader={sortable && sortDir !== 'NONE'}
                  sortDirection={sortDir}
                  onClick={sortable ? () => toggleSort(col) : undefined}
                >
                  {col.header}
                </TableHeader>
              )
            })}
            {actions && <TableHeader style={{ width: 1 }} aria-label="Row actions" />}
          </TableRow>
        </TableHead>
        <TableBody>
          {sorted.length === 0 ? (
            <TableRow>
              <TableCell colSpan={colCount} className="c2-grid-empty">{empty}</TableCell>
            </TableRow>
          ) : (
            sorted.map((row) => {
              const id = rowKey(row)
              const isSel = selectable && (selected?.has(id) ?? false)
              return (
                <TableRow
                  key={id}
                  isSelected={isSel}
                  className={onRowClick ? 'is-clickable' : undefined}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                >
                  {selectable && (
                    <TableSelectRow
                      id={`c2-grid-select-${id}`}
                      name={`c2-grid-select-${id}`}
                      aria-label={`Select ${id}`}
                      checked={isSel}
                      onSelect={(e) => { e.stopPropagation(); toggleOne(id) }}
                    />
                  )}
                  {columns.map((col) => (
                    <TableCell
                      key={col.key}
                      className={col.numeric ? 'is-numeric' : undefined}
                      style={col.numeric ? { textAlign: 'right' } : undefined}
                    >
                      {col.cell(row)}
                    </TableCell>
                  ))}
                  {actions && (
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <span className="c2-grid-rowactions">{actions(row)}</span>
                    </TableCell>
                  )}
                </TableRow>
              )
            })
          )}
        </TableBody>
      </Table>
    </TableContainer>
  )
}

// Corporate device pre-registration — admin control surface on the
// /admin/devices rail route. Pre-registering a device's TPM EK-pubkey hash
// (or serial number) marks it a corporate asset so it can attest as
// TIER_CORP; non-pre-registered genuine-TPM devices stay BYOD / posture-only.
//
// Server-side gate (cmd/jess-web/admin.go requireAdmin) is authoritative; this
// also gates client-side (an "admin only" note + hidden surfaces) for UX,
// mirroring the other C2 admin pages (Pending / Admin). Local component state
// + fetch on mount — no state library.
import { useCallback, useEffect, useRef, useState } from 'react'
import { AdminError } from '../api/admin'
import {
  deleteDevicePreReg,
  importDevicePreRegs,
  listDevicePreRegs,
  listPendingDevices,
  approvePendingDevice,
  rejectPendingDevice,
  listOnboardingDevices,
  approveCorpAsset,
  type DevicePreReg as DevicePreRegRow,
  type DevicePreRegImportResult,
  type DevicePreRegImportRow,
  type PendingDevice,
  type OnboardingDevice,
} from '../api/devices'
import { isAdmin, type Me } from '../api/me'
import { useMe } from '../hooks/useMe'
import { AppShell, Button, Column, DataGrid, Dialog, PageHeader, Panel, StatusBadge } from '../components/c2'

export function DevicePreReg() {
  const auth = useMe()
  const me: Me | null = auth.kind === 'signed_in' ? auth.me : null
  return <AppShell>{me && <DevicePreRegBody me={me} />}</AppShell>
}

function DevicePreRegBody({ me }: { me: Me }) {
  const admin = isAdmin(me)
  // reloadToken is a render-cheap counter the import card bumps after a
  // successful import so the list card refetches.
  const [reloadToken, setReloadToken] = useState(0)

  if (!admin) {
    return (
      <div className="c2-page"><div className="c2-page-body">
        <div className="c2-note c2-note-warn">platform_admin required to manage corporate device pre-registrations.</div>
      </div></div>
    )
  }

  return (
    <div className="c2-page">
      <PageHeader
        crumbs={[{ label: 'Control', to: '/' }, { label: 'Devices' }]}
        title="Corporate device pre-registration"
        subtitle="Pre-registering a device's TPM EK-pubkey hash (or serial number) marks it a corporate asset so it can attest as TIER_CORP — genuine-TPM devices that are NOT pre-registered stay BYOD / posture-only."
      />
      <div className="c2-page-body">
        <ImportPanel onImported={() => setReloadToken((n) => n + 1)} />
        <OnboardingPanel reloadToken={reloadToken} onApproved={() => setReloadToken((n) => n + 1)} />
        <PendingPanel onApproved={() => setReloadToken((n) => n + 1)} />
        <ListPanel reloadToken={reloadToken} />
      </div>
    </div>
  )
}

// ----- Import panel ----------------------------------------------------

// CSV columns (header row required): ek_pubkey_hash,serial_number,
// asset_tag,model,note — all optional per row, but each row needs at
// least one of ek_pubkey_hash / serial_number (rows with neither are
// skipped + counted). Parsed client-side with a simple split; no CSV
// dependency. A textarea fallback accepts bare EK-hashes one per line.
function ImportPanel({ onImported }: { onImported: () => void }) {
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<DevicePreRegImportResult | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [skipped, setSkipped] = useState(0)
  const [hashText, setHashText] = useState('')
  const [dragging, setDragging] = useState(false)
  const fileRef = useRef<HTMLInputElement | null>(null)

  async function submit(rows: DevicePreRegImportRow[], skippedCount: number) {
    setErr(null)
    setResult(null)
    setSkipped(skippedCount)
    if (rows.length === 0) {
      setErr('No importable rows found (each row needs an EK-pubkey hash or a serial number).')
      return
    }
    setBusy(true)
    try {
      const r = await importDevicePreRegs(rows)
      setResult(r)
      onImported()
    } catch (e: unknown) {
      setErr(messageOf(e))
    } finally {
      setBusy(false)
    }
  }

  // readCsvFile parses one CSV file (picked or dropped) entirely in the browser.
  function readCsvFile(file: File) {
    const reader = new FileReader()
    reader.onload = () => {
      const { rows, skipped: skippedCount } = parseCSV(String(reader.result ?? ''))
      void submit(rows, skippedCount)
    }
    reader.onerror = () => setErr('Could not read the selected file.')
    reader.readAsText(file)
  }

  function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    readCsvFile(file)
    // Reset the input so re-selecting the same file fires onChange again.
    if (fileRef.current) fileRef.current.value = ''
  }

  function onDrop(e: React.DragEvent) {
    e.preventDefault()
    setDragging(false)
    if (busy) return
    const file = Array.from(e.dataTransfer.files).find((f) => f.name.toLowerCase().endsWith('.csv') || f.type === 'text/csv')
      ?? e.dataTransfer.files[0]
    if (file) readCsvFile(file)
  }

  function onPasteImport() {
    const { rows, skipped: skippedCount } = parseHashLines(hashText)
    void submit(rows, skippedCount)
  }

  return (
    <Panel
      title="Import devices"
      subtitle={
        <>
          Upload a CSV with the header row <code>ek_pubkey_hash,serial_number,asset_tag,model,note</code>.
          Every column is optional per row, but each row needs at least an EK-pubkey hash or a serial
          number — rows with neither are skipped. Parsed in your browser; nothing leaves the page until
          you submit.
        </>
      }
      pad
    >
      <div className="c2-field">
        <label htmlFor="jess-dev-csv">CSV file</label>
        <div
          className={`c2-dropzone${dragging ? ' is-dragging' : ''}`}
          onDragOver={(e) => { e.preventDefault(); if (!busy) setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => fileRef.current?.click()}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') fileRef.current?.click() }}
          aria-label="Drop a CSV file here or click to choose"
        >
          <span className="c2-dropzone-hint">
            {dragging ? 'Drop the CSV to import' : 'Drag & drop a CSV here, or click to choose a file'}
          </span>
          <input
            id="jess-dev-csv"
            ref={fileRef}
            type="file"
            accept=".csv"
            onChange={onFile}
            disabled={busy}
            hidden
            aria-label="CSV file of devices to pre-register"
          />
        </div>
      </div>

      <div className="c2-field" style={{ marginTop: 14 }}>
        <label htmlFor="jess-dev-hashes">Or paste EK-pubkey hashes, one per line</label>
        <textarea
          id="jess-dev-hashes"
          className="c2-textarea"
          rows={4}
          placeholder={'sha256:ab12…\nsha256:cd34…'}
          value={hashText}
          onChange={(e) => setHashText(e.target.value)}
          disabled={busy}
        />
        <span className="c2-field-hint">Each line becomes a corporate-asset entry keyed on its EK-pubkey hash.</span>
      </div>

      <div style={{ marginTop: 12 }}>
        <Button
          variant="primary"
          size="sm"
          onClick={onPasteImport}
          disabled={busy || hashText.trim() === ''}
        >
          {busy ? 'Importing…' : 'Import pasted hashes'}
        </Button>
      </div>

      {err && <div className="c2-note c2-note-danger" style={{ marginTop: 12 }}>{err}</div>}
      {result && (
        <div style={{ marginTop: 12, display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8 }}>
          <StatusBadge tone={result.errors.length === 0 ? 'online' : 'warn'} dot={false}>
            {result.errors.length === 0
              ? `imported ${result.imported}`
              : `imported ${result.imported} (with ${result.errors.length} error${result.errors.length === 1 ? '' : 's'})`}
          </StatusBadge>
          {skipped > 0 && (
            <span className="c2-grid-mute" style={{ fontSize: 12 }}>
              {skipped} row{skipped === 1 ? '' : 's'} skipped (no EK hash or serial)
            </span>
          )}
        </div>
      )}
      {result && result.errors.length > 0 && (
        <ul style={{ marginTop: 10, listStyle: 'none', padding: 0, display: 'flex', flexDirection: 'column', gap: 6 }}>
          {result.errors.slice(0, 20).map((er) => (
            <li key={`${er.row}-${er.error}`} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <StatusBadge tone="danger" dot={false}>row {er.row}</StatusBadge>
              <span className="c2-grid-mute" style={{ fontSize: 13 }}>{er.error}</span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}

// parseCSV reads a header row then maps each subsequent row onto the
// five known columns by header name (order-independent). Rows with
// neither ek_pubkey_hash nor serial_number are skipped and counted.
function parseCSV(text: string): { rows: DevicePreRegImportRow[]; skipped: number } {
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0)
  if (lines.length === 0) return { rows: [], skipped: 0 }
  const header = lines[0].split(',').map((h) => h.trim().toLowerCase())
  const idx = {
    ek_pubkey_hash: header.indexOf('ek_pubkey_hash'),
    serial_number: header.indexOf('serial_number'),
    asset_tag: header.indexOf('asset_tag'),
    model: header.indexOf('model'),
    note: header.indexOf('note'),
  }
  const rows: DevicePreRegImportRow[] = []
  let skipped = 0
  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split(',').map((c) => c.trim())
    const at = (j: number) => (j >= 0 && j < cols.length ? cols[j] : '')
    const ek = at(idx.ek_pubkey_hash)
    const serial = at(idx.serial_number)
    if (ek === '' && serial === '') {
      skipped++
      continue
    }
    const row: DevicePreRegImportRow = {}
    if (ek) row.ek_pubkey_hash = ek
    if (serial) row.serial_number = serial
    const tag = at(idx.asset_tag)
    if (tag) row.asset_tag = tag
    const model = at(idx.model)
    if (model) row.model = model
    const note = at(idx.note)
    if (note) row.note = note
    rows.push(row)
  }
  return { rows, skipped }
}

// parseHashLines maps each non-empty line to a { ek_pubkey_hash } row.
// (No skip case — empty lines are filtered, not counted.)
function parseHashLines(text: string): { rows: DevicePreRegImportRow[]; skipped: number } {
  const rows = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .map((ek_pubkey_hash) => ({ ek_pubkey_hash }))
  return { rows, skipped: 0 }
}

// ----- Onboarding panel ------------------------------------------------

// OnboardingPanel — the enroll-first, approve-later queue. Lists devices that
// have ALREADY enrolled (and are currently BYOD / posture-only because their
// EK-pubkey hash isn't in the corp-asset allowlist) straight from the
// iam_devices registry; one click approves a chosen device into a corporate
// asset (it earns TIER_CORP on its next attestation) — no pre-harvested CSV and
// no waiting for a would-be-CORP attestation to land in the TOFU queue below.
// Refetches on reloadToken so an approval (which also lands the device in the
// pre-registered list) drops the row from here.
function OnboardingPanel({ reloadToken, onApproved }: { reloadToken: number; onApproved: () => void }) {
  const [rows, setRows] = useState<OnboardingDevice[] | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [actionErr, setActionErr] = useState<string | null>(null)
  const [busyUuid, setBusyUuid] = useState<string | null>(null)
  const [confirm, setConfirm] = useState<OnboardingDevice | null>(null)

  const load = useCallback((signal?: AbortSignal) => {
    setErr(null)
    listOnboardingDevices(signal)
      .then((data) => { if (!signal?.aborted) setRows(data ?? []) })
      .catch((e: unknown) => {
        if (e instanceof DOMException && e.name === 'AbortError') return
        if (!signal?.aborted) setErr(messageOf(e))
      })
  }, [])

  useEffect(() => {
    const ctrl = new AbortController()
    load(ctrl.signal)
    return () => ctrl.abort()
  }, [reloadToken, load])

  async function approve(d: OnboardingDevice) {
    setActionErr(null); setBusyUuid(d.device_uuid)
    try {
      await approveCorpAsset(d.device_uuid, {
        ek_pubkey_hash: d.ek_pubkey_hash,
        serial_number: d.serial_number || undefined,
        model: d.model || undefined,
      })
      setConfirm(null)
      setRows((cur) => (cur ? cur.filter((r) => r.device_uuid !== d.device_uuid) : cur))
      onApproved() // bump reloadToken → pre-registered list (+ this list) refetch
    } catch (e: unknown) { setActionErr(messageOf(e)) } finally { setBusyUuid(null) }
  }

  const columns: Column<OnboardingDevice>[] = [
    { key: 'user_sub', header: 'User', sortValue: (d) => d.user_sub, cell: (d) => d.user_sub ? <span className="c2-grid-mono" title={d.user_sub}>{truncate(d.user_sub, 16)}</span> : <span className="c2-grid-mute">—</span> },
    { key: 'device_uuid', header: 'Device', sortValue: (d) => d.device_uuid, cell: (d) => d.device_uuid ? <span className="c2-grid-mono" title={d.device_uuid}>{truncate(d.device_uuid, 14)}</span> : <span className="c2-grid-mute">—</span> },
    { key: 'platform', header: 'Platform', sortValue: (d) => d.platform, cell: (d) => d.platform || <span className="c2-grid-mute">—</span> },
    { key: 'tier', header: 'Tier', sortValue: (d) => d.tier, cell: (d) => d.tier ? <StatusBadge tone="mute" dot={false}>{d.tier}</StatusBadge> : <span className="c2-grid-mute">—</span> },
    { key: 'ek_pubkey_hash', header: 'EK hash', sortValue: (d) => d.ek_pubkey_hash, cell: (d) => d.ek_pubkey_hash ? <code className="c2-grid-mono" title={d.ek_pubkey_hash}>{truncate(d.ek_pubkey_hash, 18)}</code> : <span className="c2-grid-mute">—</span> },
    { key: 'serial_number', header: 'Serial', sortValue: (d) => d.serial_number, cell: (d) => d.serial_number ? <span className="c2-grid-mono">{d.serial_number}</span> : <span className="c2-grid-mute">—</span> },
    { key: 'model', header: 'Model', sortValue: (d) => d.model, cell: (d) => d.model || <span className="c2-grid-mute">—</span> },
    { key: 'manufacturer', header: 'Manufacturer', sortValue: (d) => d.manufacturer, cell: (d) => d.manufacturer || <span className="c2-grid-mute">—</span> },
    { key: 'last_seen_at', header: 'Last seen', sortValue: (d) => d.last_seen_at ?? '', cell: (d) => d.last_seen_at ? <span className="c2-grid-mute">{new Date(d.last_seen_at).toLocaleString()}</span> : <span className="c2-grid-mute">—</span> },
  ]

  return (
    <>
      <Panel
        title={
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
            Enrolled devices · approve
            {rows && rows.length > 0 && <StatusBadge tone="warn" dot={false}>{rows.length}</StatusBadge>}
          </span>
        }
        subtitle="Devices that have already enrolled but aren't corporate assets yet (BYOD / posture-only). Approve one to add it to the corporate-asset allowlist — it earns TIER_CORP on its next attestation, no CSV needed."
        actions={<Button variant="ghost" size="sm" onClick={() => load()}>Refresh</Button>}
      >
        {actionErr && <div className="c2-note c2-note-danger" style={{ margin: '0 14px 10px' }}>{actionErr}</div>}
        {err && <div className="c2-note c2-note-danger" style={{ margin: '0 14px 10px' }}>{err}</div>}
        {rows === null && !err ? (
          <div className="c2-loading">Loading enrolled devices…</div>
        ) : (
          <DataGrid
            rows={rows ?? []}
            columns={columns}
            rowKey={(d) => d.device_uuid}
            defaultSort={{ key: 'last_seen_at', dir: 'desc' }}
            empty="No enrolled devices awaiting approval."
            actions={(d) => (
              <Button variant="primary" size="sm" disabled={busyUuid === d.device_uuid} onClick={() => setConfirm(d)}>
                Approve as corporate asset
              </Button>
            )}
          />
        )}
      </Panel>

      {confirm && (
        <Dialog
          title="Approve as corporate asset"
          onClose={() => { if (busyUuid === null) setConfirm(null) }}
          footer={
            <>
              <Button variant="ghost" size="sm" disabled={busyUuid !== null} onClick={() => setConfirm(null)}>Cancel</Button>
              <Button variant="primary" size="sm" disabled={busyUuid !== null} onClick={() => approve(confirm)}>
                {busyUuid !== null ? 'Approving…' : 'Approve as corporate asset'}
              </Button>
            </>
          }
        >
          <p className="c2-field-hint">
            This adds the device's TPM EK-pubkey hash to the corporate-asset allowlist. The device
            earns <code>TIER_CORP</code> on its next attestation. The approval is audited (who, which
            device, when).
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 12px', marginTop: 12, fontSize: 13, alignItems: 'baseline' }}>
            <span className="c2-grid-mute">User</span><span>{confirm.user_sub || '—'}</span>
            <span className="c2-grid-mute">Device</span><span className="c2-grid-mono" style={{ wordBreak: 'break-all' }}>{confirm.device_uuid}</span>
            <span className="c2-grid-mute">Tier</span><span>{confirm.tier || '—'}</span>
            <span className="c2-grid-mute">EK hash</span><code className="c2-grid-mono" style={{ wordBreak: 'break-all' }}>{confirm.ek_pubkey_hash}</code>
          </div>
        </Dialog>
      )}
    </>
  )
}

// ----- List panel ------------------------------------------------------

// PendingPanel — the TOFU auto-enroll review queue. Genuine-TPM devices that
// attested as would-be-CORP but aren't pre-registered yet; Approve promotes one
// to the corporate-asset allowlist, Reject drops it. This is the operational
// alternative to hand-collecting every device's EK-pubkey hash.
function PendingPanel({ onApproved }: { onApproved: () => void }) {
  const [rows, setRows] = useState<PendingDevice[] | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [actionErr, setActionErr] = useState<string | null>(null)
  const [busyHash, setBusyHash] = useState<string | null>(null)

  const load = useCallback((signal?: AbortSignal) => {
    setErr(null)
    listPendingDevices(signal)
      .then((data) => { if (!signal?.aborted) setRows(data ?? []) })
      .catch((e: unknown) => {
        if (e instanceof DOMException && e.name === 'AbortError') return
        if (!signal?.aborted) setErr(messageOf(e))
      })
  }, [])

  useEffect(() => {
    const ctrl = new AbortController()
    load(ctrl.signal)
    return () => ctrl.abort()
  }, [load])

  async function approve(ekHash: string) {
    setActionErr(null); setBusyHash(ekHash)
    try {
      await approvePendingDevice(ekHash)
      setRows((cur) => (cur ? cur.filter((r) => r.ek_hash !== ekHash) : cur))
      onApproved() // refresh the pre-registered list below
    } catch (e: unknown) { setActionErr(messageOf(e)) } finally { setBusyHash(null) }
  }
  async function reject(ekHash: string) {
    setActionErr(null); setBusyHash(ekHash)
    try {
      await rejectPendingDevice(ekHash)
      setRows((cur) => (cur ? cur.filter((r) => r.ek_hash !== ekHash) : cur))
    } catch (e: unknown) { setActionErr(messageOf(e)) } finally { setBusyHash(null) }
  }

  const columns: Column<PendingDevice>[] = [
    { key: 'ek_hash', header: 'EK hash', sortValue: (d) => d.ek_hash, cell: (d) => <code className="c2-grid-mono" title={d.ek_hash}>{truncate(d.ek_hash, 18)}</code> },
    { key: 'platform', header: 'Platform', sortValue: (d) => d.platform, cell: (d) => d.platform || <span className="c2-grid-mute">—</span> },
    { key: 'device_uuid', header: 'Device', sortValue: (d) => d.device_uuid, cell: (d) => d.device_uuid ? <span className="c2-grid-mono">{truncate(d.device_uuid, 14)}</span> : <span className="c2-grid-mute">—</span> },
    { key: 'count', header: 'Sightings', sortValue: (d) => d.count, cell: (d) => <span className="c2-grid-mute">{d.count}</span> },
    { key: 'first_seen', header: 'First seen', sortValue: (d) => d.first_seen, cell: (d) => d.first_seen ? <span className="c2-grid-mute">{new Date(d.first_seen).toLocaleString()}</span> : <span className="c2-grid-mute">—</span> },
  ]

  return (
    <Panel
      title={
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
          Pending review · auto-enroll
          {rows && rows.length > 0 && <StatusBadge tone="warn" dot={false}>{rows.length}</StatusBadge>}
        </span>
      }
      subtitle="Genuine-TPM devices seen attesting that would earn TIER_CORP but aren't pre-registered. Approve to add the device to the corporate-asset allowlist (it earns TIER_CORP on its next attestation) — no manual EK-hash collection needed. Reject leaves it BYOD/posture-only."
      actions={<Button variant="ghost" size="sm" onClick={() => load()}>Refresh</Button>}
    >
      {actionErr && <div className="c2-note c2-note-danger" style={{ margin: '0 14px 10px' }}>{actionErr}</div>}
      {err && <div className="c2-note c2-note-danger" style={{ margin: '0 14px 10px' }}>{err}</div>}
      {rows === null && !err ? (
        <div className="c2-loading">Loading the review queue…</div>
      ) : (
        <DataGrid
          rows={rows ?? []}
          columns={columns}
          rowKey={(d) => d.ek_hash}
          defaultSort={{ key: 'first_seen', dir: 'desc' }}
          empty="No devices awaiting review."
          actions={(d) => (
            <span style={{ display: 'inline-flex', gap: 6 }}>
              <Button variant="primary" size="sm" disabled={busyHash === d.ek_hash} onClick={() => approve(d.ek_hash)}>Approve</Button>
              <Button variant="ghost" size="sm" disabled={busyHash === d.ek_hash} onClick={() => reject(d.ek_hash)}>Reject</Button>
            </span>
          )}
        />
      )}
    </Panel>
  )
}

function ListPanel({ reloadToken }: { reloadToken: number }) {
  const [rows, setRows] = useState<DevicePreRegRow[] | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [actionErr, setActionErr] = useState<string | null>(null)

  const load = useCallback((signal?: AbortSignal) => {
    setErr(null)
    listDevicePreRegs(signal)
      .then((data) => {
        if (!signal?.aborted) setRows(data ?? [])
      })
      .catch((e: unknown) => {
        if (e instanceof DOMException && e.name === 'AbortError') return
        if (!signal?.aborted) setErr(messageOf(e))
      })
  }, [])

  useEffect(() => {
    const ctrl = new AbortController()
    load(ctrl.signal)
    return () => ctrl.abort()
  }, [reloadToken, load])

  async function remove(id: string) {
    setActionErr(null)
    // Optimistic: drop the row immediately, restore on failure.
    const prev = rows
    setRows((cur) => (cur ? cur.filter((r) => r.id !== id) : cur))
    try {
      await deleteDevicePreReg(id)
    } catch (e: unknown) {
      setActionErr(messageOf(e))
      setRows(prev ?? null)
    }
  }

  const columns: Column<DevicePreRegRow>[] = [
    {
      key: 'ek_pubkey_hash',
      header: 'EK hash',
      sortValue: (d) => d.ek_pubkey_hash,
      cell: (d) =>
        d.ek_pubkey_hash
          ? <code className="c2-grid-mono" title={d.ek_pubkey_hash}>{truncate(d.ek_pubkey_hash, 18)}</code>
          : <span className="c2-grid-mute">—</span>,
    },
    { key: 'serial_number', header: 'Serial', sortValue: (d) => d.serial_number, cell: (d) => d.serial_number ? <span className="c2-grid-mono">{d.serial_number}</span> : <span className="c2-grid-mute">—</span> },
    { key: 'asset_tag', header: 'Asset tag', sortValue: (d) => d.asset_tag, cell: (d) => d.asset_tag || <span className="c2-grid-mute">—</span> },
    { key: 'model', header: 'Model', sortValue: (d) => d.model, cell: (d) => d.model || <span className="c2-grid-mute">—</span> },
    { key: 'created_at', header: 'Created', sortValue: (d) => d.created_at, cell: (d) => d.created_at ? <span className="c2-grid-mute">{new Date(d.created_at).toLocaleString()}</span> : <span className="c2-grid-mute">—</span> },
  ]

  return (
    <Panel
      title={
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
          Pre-registered devices
          {rows && <StatusBadge tone="mute" dot={false}>{rows.length}</StatusBadge>}
        </span>
      }
      subtitle="Every device marked as a corporate asset. A device whose attestation matches an entry here can attest as TIER_CORP."
      actions={<Button variant="ghost" size="sm" onClick={() => load()}>Refresh</Button>}
    >
      {actionErr && <div className="c2-note c2-note-danger" style={{ margin: '0 14px 10px' }}>{actionErr}</div>}
      {err && <div className="c2-note c2-note-danger" style={{ margin: '0 14px 10px' }}>{err}</div>}
      {rows === null && !err ? (
        <div className="c2-loading">Loading pre-registered devices…</div>
      ) : (
        <DataGrid
          rows={rows ?? []}
          columns={columns}
          rowKey={(d) => d.id}
          defaultSort={{ key: 'created_at', dir: 'desc' }}
          empty="No devices pre-registered yet."
          actions={(d) => (
            <Button variant="danger" size="sm" onClick={() => remove(d.id)}>Delete</Button>
          )}
        />
      )}
    </Panel>
  )
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s
}

function messageOf(e: unknown): string {
  if (e instanceof AdminError) return `${e.status === 403 ? 'forbidden' : `HTTP ${e.status}`}: ${e.message}`
  if (e instanceof Error) return e.message
  return String(e)
}

// Corporate device pre-registration API client — backs the SPA /devices
// route. All endpoints proxy to the controller admin port via jess-web's
// /api/admin/devices/* handlers, which enforce a server-side
// platform_admin gate (the SPA also gates the route client-side but the
// proxy is authoritative).
//
// Pre-registering a device's TPM EK-pubkey hash (or serial) marks it a
// corporate asset so the device can attest as TIER_CORP; genuine-TPM
// devices that are NOT pre-registered stay BYOD / posture-only.

import { AdminError } from './admin'

export interface DevicePreReg {
  id: string
  ek_pubkey_hash: string
  serial_number: string
  asset_tag: string
  model: string
  note: string
  tenant_id: string
  created_by: string
  created_at: string // RFC3339
}

// One row of an import payload. At least one of ek_pubkey_hash /
// serial_number must be present per row (enforced both client-side
// before submit and server-side).
export interface DevicePreRegImportRow {
  ek_pubkey_hash?: string
  serial_number?: string
  asset_tag?: string
  model?: string
  note?: string
}

export interface DevicePreRegImportResult {
  imported: number
  errors: Array<{ row: number; error: string }>
}

async function devicesJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, {
    credentials: 'same-origin',
    cache: 'no-store',
    ...init,
  })
  if (r.status === 204) return undefined as unknown as T
  const raw = await r.text()
  let parsed: unknown = null
  try {
    parsed = raw.length > 0 ? JSON.parse(raw) : null
  } catch {
    // fall through
  }
  if (!r.ok) {
    const msg =
      typeof parsed === 'object' && parsed !== null && 'error' in parsed && typeof (parsed as { error: unknown }).error === 'string'
        ? ((parsed as { error: string }).error)
        : `HTTP ${r.status}`
    throw new AdminError(r.status, msg)
  }
  return parsed as T
}

export function listDevicePreRegs(signal?: AbortSignal): Promise<DevicePreReg[]> {
  return devicesJSON<DevicePreReg[]>('/api/admin/devices/pre-registrations', { signal })
}

export function importDevicePreRegs(
  devices: DevicePreRegImportRow[],
  signal?: AbortSignal,
): Promise<DevicePreRegImportResult> {
  return devicesJSON<DevicePreRegImportResult>('/api/admin/devices/pre-registrations/import', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ devices }),
    signal,
  })
}

export function deleteDevicePreReg(id: string, signal?: AbortSignal): Promise<void> {
  return devicesJSON<void>(`/api/admin/devices/pre-registrations/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    signal,
  })
}

// --- TOFU auto-enroll review queue -----------------------------------------
// Genuine-TPM devices observed attesting that would earn TIER_CORP but aren't
// pre-registered. Approve promotes one to the corporate-asset allowlist (the
// device earns TIER_CORP on its next attestation); reject drops it.
export interface PendingDevice {
  ek_hash: string
  device_uuid: string
  platform: string
  subject: string
  would_be_tier: string
  first_seen: string
  last_seen: string
  count: number
}

export function listPendingDevices(signal?: AbortSignal): Promise<PendingDevice[]> {
  return devicesJSON<PendingDevice[]>('/api/admin/devices/pending', { signal })
}

export function approvePendingDevice(ekHash: string, signal?: AbortSignal): Promise<DevicePreRegImportResult> {
  return devicesJSON<DevicePreRegImportResult>(`/api/admin/devices/pending/${encodeURIComponent(ekHash)}/approve`, {
    method: 'POST',
    signal,
  })
}

export function rejectPendingDevice(ekHash: string, signal?: AbortSignal): Promise<void> {
  return devicesJSON<void>(`/api/admin/devices/pending/${encodeURIComponent(ekHash)}/reject`, {
    method: 'POST',
    signal,
  })
}

// --- Enroll-first, approve-later onboarding queue ---------------------------
// Registry-backed: enrolled devices that are currently BYOD/posture-only
// (their EK hash is NOT in the corp-asset allowlist). Approve adds the device
// to the allowlist (it earns TIER_CORP on its next attestation) — no
// pre-harvested CSV needed. serial_number/model/manufacturer are the
// hardware-identity columns falcon-id carries on the iam_devices row (populated
// from the agent's inventory report); they may be empty until the device has
// reported inventory (rendered as "—"). Hostname is not yet a registry column.
export interface OnboardingDevice {
  device_uuid: string
  user_sub: string
  platform: string
  tier: string
  ek_pubkey_hash: string
  hostname: string
  serial_number: string
  model: string
  manufacturer: string
  enrolled_at?: string
  last_seen_at?: string
}

export async function listOnboardingDevices(signal?: AbortSignal): Promise<OnboardingDevice[]> {
  const r = await devicesJSON<{ devices: OnboardingDevice[] }>('/api/admin/devices/onboarding', { signal })
  return r?.devices ?? []
}

// approveCorpAsset promotes an already-enrolled device into a corporate asset.
// The EK-pubkey hash (and any serial/model) is read from the onboarding row
// being approved; the controller validates the hash, writes the allowlist
// entry attributed to the operator, and WORM-audits the approval.
export function approveCorpAsset(
  deviceUuid: string,
  body: { ek_pubkey_hash: string; serial_number?: string; model?: string },
  signal?: AbortSignal,
): Promise<DevicePreRegImportResult> {
  return devicesJSON<DevicePreRegImportResult>(
    `/api/admin/devices/onboarding/${encodeURIComponent(deviceUuid)}/approve`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal,
    },
  )
}

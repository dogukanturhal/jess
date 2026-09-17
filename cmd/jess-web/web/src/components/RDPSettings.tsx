// RDPSettings — VMware-style per-session console settings for the live RDP
// viewport (resolution / scale-DPI / colour).
//
// The backend already supports `?w=&h=` on /ws/rdp-live → RDP_DESKTOP_W/H →
// the connector's desktop_size (the resolution-match quality work). This module
// is the OPERATOR-FACING control for that knob plus a DPI multiplier:
//
//   Resolution  Match window (default — the canvas auto-measures its stage) |
//               presets (1920×1080 …) | Custom W×H
//   Scale/DPI   1× / 1.25× / 1.5× / 2× — multiplies the requested device-pixel
//               size (a 1920×1080 desktop at 1.5× requests 2880×1620 so HiDPI
//               renders crisp; the canvas CSS-fits it to the stage)
//   Colour      INFORMATIONAL — the broker pins lossless 32-bit colour
//               (RemoteFX dropped); no depth knob is exposed by the connector,
//               so this is shown for parity with vSphere, not a control.
//
// Settings persist in localStorage (per browser). "Apply" hands the chosen size
// back to the page, which reconnects the live session (remount RDPCanvas with a
// new ?w=&h=). "Match window" yields `undefined` → the canvas keeps today's
// auto-measure behaviour.

import { useState } from 'react'
import { Dialog } from './c2/Dialog'
import { Button } from './c2/Button'

export type RDPResolutionMode = 'match' | 'preset' | 'custom'
export type RDPScale = 1 | 1.25 | 1.5 | 2

export interface RDPSettings {
  resolutionMode: RDPResolutionMode
  // The chosen preset / custom dimensions in CSS pixels (the DPI scale is
  // applied on top when computing the device-pixel request). Ignored when
  // resolutionMode === 'match'.
  presetW: number
  presetH: number
  customW: number
  customH: number
  scale: RDPScale
}

// Presets are CSS-pixel desktop sizes; the DPI scale multiplies them.
export const RDP_RESOLUTION_PRESETS: ReadonlyArray<{ w: number; h: number; label: string }> = [
  { w: 1920, h: 1080, label: '1920 × 1080' },
  { w: 1600, h: 1200, label: '1600 × 1200' },
  { w: 1366, h: 768, label: '1366 × 768' },
  { w: 1280, h: 1024, label: '1280 × 1024' },
]

export const RDP_SCALES: ReadonlyArray<RDPScale> = [1, 1.25, 1.5, 2]

export const DEFAULT_RDP_SETTINGS: RDPSettings = {
  resolutionMode: 'match',
  presetW: 1920,
  presetH: 1080,
  customW: 1440,
  customH: 900,
  scale: 1,
}

const STORAGE_KEY = 'jess.rdp.session-settings.v1'

// Permissive even/clamp matching RDPCanvas (u16 wire range). Custom/preset dims
// pass through this so we never persist or request a silly value.
function sane(n: number, fallback: number): number {
  if (!Number.isFinite(n) || n <= 0) return fallback
  return Math.min(Math.max(2, Math.round(n / 2) * 2), 8192)
}

export function loadRDPSettings(): RDPSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return DEFAULT_RDP_SETTINGS
    const p = JSON.parse(raw) as Partial<RDPSettings>
    const mode: RDPResolutionMode =
      p.resolutionMode === 'preset' || p.resolutionMode === 'custom' ? p.resolutionMode : 'match'
    const scale: RDPScale = (RDP_SCALES as readonly number[]).includes(p.scale as number)
      ? (p.scale as RDPScale)
      : 1
    return {
      resolutionMode: mode,
      presetW: sane(p.presetW ?? DEFAULT_RDP_SETTINGS.presetW, DEFAULT_RDP_SETTINGS.presetW),
      presetH: sane(p.presetH ?? DEFAULT_RDP_SETTINGS.presetH, DEFAULT_RDP_SETTINGS.presetH),
      customW: sane(p.customW ?? DEFAULT_RDP_SETTINGS.customW, DEFAULT_RDP_SETTINGS.customW),
      customH: sane(p.customH ?? DEFAULT_RDP_SETTINGS.customH, DEFAULT_RDP_SETTINGS.customH),
      scale,
    }
  } catch {
    return DEFAULT_RDP_SETTINGS
  }
}

export function saveRDPSettings(s: RDPSettings): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(s))
  } catch {
    // localStorage may be unavailable (private mode / blocked) — non-fatal; the
    // settings just won't persist across reloads this session.
  }
}

// computeDesiredSize turns the settings into the explicit DEVICE-pixel size to
// request via ?w=&h=, or `undefined` for "Match window" (the canvas then
// auto-measures its stage — today's behaviour). For preset/custom we multiply
// the CSS dims by the chosen scale; RDPCanvas re-clamps to even/u16 anyway.
export function computeDesiredSize(s: RDPSettings): { w: number; h: number } | undefined {
  if (s.resolutionMode === 'match') return undefined
  const baseW = s.resolutionMode === 'custom' ? s.customW : s.presetW
  const baseH = s.resolutionMode === 'custom' ? s.customH : s.presetH
  return { w: Math.round(baseW * s.scale), h: Math.round(baseH * s.scale) }
}

// Short human label for the toolbar telemetry cell.
export function rdpSettingsLabel(s: RDPSettings): string {
  const scale = s.scale === 1 ? '' : ` · ${s.scale}×`
  if (s.resolutionMode === 'match') return `Match window${scale}`
  if (s.resolutionMode === 'custom') return `${s.customW}×${s.customH}${scale}`
  return `${s.presetW}×${s.presetH}${scale}`
}

export function RDPSettingsDialog({
  initial,
  onApply,
  onClose,
}: {
  initial: RDPSettings
  // Apply hands back the (already-sanitised) settings; the page persists +
  // reconnects.
  onApply: (s: RDPSettings) => void
  onClose: () => void
}) {
  const [s, setS] = useState<RDPSettings>(initial)

  const set = <K extends keyof RDPSettings>(k: K, v: RDPSettings[K]) =>
    setS((prev) => ({ ...prev, [k]: v }))

  const apply = () => {
    onApply({
      ...s,
      presetW: sane(s.presetW, DEFAULT_RDP_SETTINGS.presetW),
      presetH: sane(s.presetH, DEFAULT_RDP_SETTINGS.presetH),
      customW: sane(s.customW, DEFAULT_RDP_SETTINGS.customW),
      customH: sane(s.customH, DEFAULT_RDP_SETTINGS.customH),
    })
  }

  const reset = () => setS(DEFAULT_RDP_SETTINGS)

  const desired = computeDesiredSize(s)
  const requestNote =
    desired == null
      ? 'The session will be sized to fit the console window (× your display DPI).'
      : `The session will request a ${desired.w} × ${desired.h} desktop (device pixels).`

  return (
    <Dialog
      title="Session settings"
      onClose={onClose}
      width={560}
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={reset}>Reset</Button>
          <span className="c2-toolbar-spacer" />
          <Button variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
          <Button variant="primary" size="sm" onClick={apply}>Apply &amp; reconnect</Button>
        </>
      }
    >
      <p className="c2-field-hint" style={{ marginTop: 0, marginBottom: 14 }}>
        Resolution &amp; scale apply on reconnect. Changing them re-opens the live session with the
        new desktop size; the in-progress session ends.
      </p>

      {/* --- Resolution --- */}
      <fieldset style={{ border: 0, margin: 0, padding: 0, marginBottom: 16 }}>
        <legend className="c2-eyebrow" style={{ marginBottom: 8 }}>Resolution</legend>

        <label className="c2-settings-row">
          <input
            type="radio"
            name="rdp-res"
            checked={s.resolutionMode === 'match'}
            onChange={() => set('resolutionMode', 'match')}
          />
          <span>Match window <span className="c2-field-hint">(default — fit the console, HiDPI-aware)</span></span>
        </label>

        <label className="c2-settings-row">
          <input
            type="radio"
            name="rdp-res"
            checked={s.resolutionMode === 'preset'}
            onChange={() => set('resolutionMode', 'preset')}
          />
          <span>Preset</span>
          <select
            className="c2-select"
            style={{ marginLeft: 'auto' }}
            disabled={s.resolutionMode !== 'preset'}
            value={`${s.presetW}x${s.presetH}`}
            onChange={(e) => {
              const [w, h] = e.target.value.split('x').map(Number)
              setS((prev) => ({ ...prev, resolutionMode: 'preset', presetW: w, presetH: h }))
            }}
          >
            {RDP_RESOLUTION_PRESETS.map((p) => (
              <option key={`${p.w}x${p.h}`} value={`${p.w}x${p.h}`}>{p.label}</option>
            ))}
          </select>
        </label>

        <label className="c2-settings-row">
          <input
            type="radio"
            name="rdp-res"
            checked={s.resolutionMode === 'custom'}
            onChange={() => set('resolutionMode', 'custom')}
          />
          <span>Custom</span>
          <span style={{ marginLeft: 'auto', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <input
              type="number"
              className="c2-input"
              style={{ width: 84 }}
              min={640}
              max={8192}
              step={2}
              disabled={s.resolutionMode !== 'custom'}
              value={s.customW}
              aria-label="Custom width"
              onChange={(e) => set('customW', Number(e.target.value))}
            />
            <span className="c2-field-hint">×</span>
            <input
              type="number"
              className="c2-input"
              style={{ width: 84 }}
              min={480}
              max={8192}
              step={2}
              disabled={s.resolutionMode !== 'custom'}
              value={s.customH}
              aria-label="Custom height"
              onChange={(e) => set('customH', Number(e.target.value))}
            />
          </span>
        </label>
      </fieldset>

      {/* --- Scale / DPI --- */}
      <div className="c2-field" style={{ marginBottom: 16 }}>
        <label>Scale / DPI</label>
        <div className="c2-segment" role="group" aria-label="Scale / DPI">
          {RDP_SCALES.map((sc) => (
            <button
              key={sc}
              type="button"
              className={`c2-segment-btn${s.scale === sc ? ' is-on' : ''}`}
              aria-pressed={s.scale === sc}
              onClick={() => set('scale', sc)}
            >
              {sc}×
            </button>
          ))}
        </div>
        <span className="c2-field-hint">
          Multiplies the requested device-pixel size — higher = sharper on HiDPI, more bandwidth.
        </span>
      </div>

      {/* --- Colour (informational) --- */}
      <div className="c2-field" style={{ marginBottom: 14 }}>
        <label>Colour depth</label>
        <div className="c2-note c2-note-mute" style={{ margin: 0 }}>
          <p className="c2-note-title" style={{ margin: 0 }}>Lossless 32-bit (true colour)</p>
          <p className="c2-field-hint" style={{ margin: '4px 0 0' }}>
            The broker pins lossless 32-bit colour and drops the lossy RemoteFX codec, so colour
            depth isn't adjustable. Shown for parity with desktop RDP clients.
          </p>
        </div>
      </div>

      <div className="c2-note c2-note-info" style={{ margin: 0 }} role="note">
        <p className="c2-field-hint" style={{ margin: 0 }}>{requestNote}</p>
      </div>
    </Dialog>
  )
}

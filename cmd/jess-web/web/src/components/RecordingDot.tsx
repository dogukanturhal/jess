// Recording indicator — Phase 5e-3.
//
// Recording is PER-TARGET (admin catalog toggle, override-or-default) — it is
// NOT an unconditional substrate invariant, so this dot reflects the resolved
// decision rather than affirming "always on":
//   - 'live'    pulsing green — this session IS being tee'd to the audit-archive
//               MinIO WORM bucket (jess-rdp-recording-v2 + Vault Transit manifest)
//   - 'stopped' static grey — the session ended (bundle sealed)
//   - 'off'     static grey — recording is DISABLED for this target, so nothing
//               is recorded for this session (honest: shows "Recording off")
import type { ReactNode } from 'react'

type Status = 'live' | 'stopped' | 'off'

export function RecordingDot({ status, children }: { status: Status; children?: ReactNode }) {
  return (
    <span className="jw-recording" aria-live="polite" aria-label={`Recording ${status}`}>
      <span className={status === 'live' ? 'jw-dot jw-dot-live' : 'jw-dot jw-dot-stopped'} aria-hidden="true" />
      <span className="jw-mono-eyebrow">{status === 'off' ? 'Recording off' : 'Recording'}</span>
      <span className="jw-ink-2">{children}</span>
    </span>
  )
}

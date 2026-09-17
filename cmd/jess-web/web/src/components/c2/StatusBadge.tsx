// StatusBadge + StatusDot — Carbon Tag, kept behind the C2 status API.
//
// `tone` maps to Carbon Tag `type`:
//   online → green   warn → yellow   danger → red
//   offline/mute → gray   info → cyan
// `dot` keeps a leading status dot (Carbon Tag has no built-in dot, so we
// render one inside the tag via the legacy .c2-badge-dot for the live cue).
// StatusDot is the bare indicator used in dense grids; `pulse` animates it for
// live sessions (CSS keyframe in c2.css).
//
// Legacy c2-badge* class names are still applied so the per-tone dot colour
// rules + any external hooks keep matching.
import type { ReactNode } from 'react'
import { Tag } from '@carbon/react'

export type Tone = 'online' | 'warn' | 'danger' | 'offline' | 'mute' | 'info'

// Carbon Tag has no "yellow"; warn keeps the warm colour via the .c2-badge-warn
// class (token-bridged to --c2-warn). The other tones map directly to Carbon
// Tag colours.
const TAG_TYPE: Record<Tone, 'green' | 'red' | 'gray' | 'cyan' | 'outline'> = {
  online: 'green',
  warn: 'outline',
  danger: 'red',
  offline: 'gray',
  mute: 'gray',
  info: 'cyan',
}

export function StatusBadge({
  tone,
  children,
  dot = true,
  title,
}: {
  tone: Tone
  children: ReactNode
  dot?: boolean
  title?: string
}) {
  return (
    <Tag type={TAG_TYPE[tone]} size="sm" className={`c2-badge c2-badge-${tone}`} title={title}>
      {dot && <span className="c2-badge-dot" />}
      {children}
    </Tag>
  )
}

export function StatusDot({
  tone,
  pulse = false,
  title,
}: {
  tone: 'online' | 'warn' | 'danger' | 'offline'
  pulse?: boolean
  title?: string
}) {
  return (
    <span
      className={`c2-dot c2-dot-${tone}${pulse ? ' c2-dot-pulse' : ''}`}
      title={title}
      aria-hidden="true"
    />
  )
}

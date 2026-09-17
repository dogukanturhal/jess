// Button — Carbon Button, kept behind the C2 Button API so every call site
// (primary cyan/blue / ghost / danger / icon, <button> or <a href>) is
// unchanged. Maps the C2 variants → Carbon kinds:
//   primary → 'primary'   ghost → 'tertiary' (outline)   danger → 'danger--ghost'
//   icon    → hasIconOnly  size  sm → 'sm', md → 'md'
//
// Renders as Carbon <Button as="a" href=…> when href is set (so existing
// open-in-new-tab / download / auth-redirect anchors keep their behavior),
// otherwise a normal Carbon <button>. Legacy c2-btn* class names are still
// applied so any external CSS hooks / tests that key off them keep matching.
import type { AnchorHTMLAttributes, ButtonHTMLAttributes, ReactNode } from 'react'
import { Button as CarbonButton } from '@carbon/react'

type Variant = 'primary' | 'ghost' | 'danger'

interface Common {
  variant?: Variant
  size?: 'sm' | 'md'
  icon?: boolean
  children?: ReactNode
}

type ButtonProps = Common & ButtonHTMLAttributes<HTMLButtonElement> & { href?: undefined }
type AnchorProps = Common & AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }

const KIND: Record<Variant, 'primary' | 'tertiary' | 'danger--ghost'> = {
  primary: 'primary',
  ghost: 'tertiary',
  danger: 'danger--ghost',
}

function legacyClass(variant: Variant, size: 'sm' | 'md', icon: boolean, extra?: string): string {
  return [
    'c2-btn',
    `c2-btn-${variant}`,
    size === 'sm' ? 'c2-btn-sm' : '',
    icon ? 'c2-btn-icon' : '',
    extra ?? '',
  ].filter(Boolean).join(' ')
}

export function Button(props: ButtonProps | AnchorProps) {
  const {
    variant = 'ghost',
    size = 'md',
    icon = false,
    className,
    children,
    title,
    ...rest
  } = props as Common & { className?: string; href?: string; title?: string } & Record<string, unknown>

  const cls = legacyClass(variant, size, icon, className)
  const href = (rest as { href?: string }).href

  // Common Carbon props. `hasIconOnly` needs an iconDescription for a11y; reuse
  // the title (call sites always pass one for icon buttons).
  const carbonCommon = {
    kind: KIND[variant],
    size: size === 'sm' ? ('sm' as const) : ('md' as const),
    className: cls,
    ...(icon ? { hasIconOnly: true, iconDescription: typeof title === 'string' ? title : 'action' } : {}),
    ...(title ? { title } : {}),
  }

  if (typeof href === 'string') {
    // Carbon's <Button> is typed for <button> even when polymorphic via `as`,
    // so anchor-only attrs (type/onCopy/etc.) don't unify. Render through a
    // permissively-typed wrapper — at runtime Carbon emits a real <a href> and
    // forwards every prop, so all existing anchor behavior is preserved.
    const AnyButton = CarbonButton as unknown as (
      p: Record<string, unknown>,
    ) => JSX.Element
    return (
      <AnyButton as="a" href={href} {...carbonCommon} {...(rest as Record<string, unknown>)}>
        {children}
      </AnyButton>
    )
  }
  return (
    <CarbonButton {...carbonCommon} {...(rest as ButtonHTMLAttributes<HTMLButtonElement>)}>
      {children}
    </CarbonButton>
  )
}

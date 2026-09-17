// Dialog — modal overlay used to host ConnectForm / RequestForm / ConnectResolver
// and small confirmations.
//
// This is a SELF-CONTAINED custom modal — deliberately NOT Carbon's
// ComposedModal. Carbon's stock modal sizes itself as a viewport percentage,
// pads bare <p> 20% on the right, and stretches a single footer button to
// flex 0 1 50% / 64px tall. The c2-* pages render arbitrary structural markup
// (notes, lists, forms) as the body, so those stock styles clipped our content
// and detached the Cancel button into a floating box. Two prior attempts to
// override them lost the specificity war against Carbon's bundle.
//
// Instead we own the entire chrome: a fixed dim overlay that flex-centers a
// constrained card, a header row, a scrollable body, and a normal action bar
// footer. Everything is styled from the app's existing design tokens (the
// --hxm-* / --c2-* bridge in carbon.scss, which resolve to Carbon g100), so it
// stays consistent with the rest of the C2 console. See `.c2-dlg*` in c2.css.
//
// Callers may pass Carbon <Button>s in `footer`; the layout/container is ours.
import { useEffect, useRef, type MouseEvent, type ReactNode } from 'react'
import { createPortal } from 'react-dom'

const DEFAULT_WIDTH = 520

export function Dialog({
  title,
  onClose,
  children,
  footer,
  width = DEFAULT_WIDTH,
}: {
  title: ReactNode
  onClose: () => void
  children: ReactNode
  footer?: ReactNode
  width?: number
}) {
  const titleIsString = typeof title === 'string'
  const cardRef = useRef<HTMLDivElement>(null)

  // Esc closes; focus the dialog on open and restore the previously-focused
  // element on close (focus management Carbon used to handle for us).
  useEffect(() => {
    const prevFocus = document.activeElement as HTMLElement | null
    cardRef.current?.focus()

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation()
        onClose()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      // Restore focus to whatever was focused before the dialog opened.
      prevFocus?.focus?.()
    }
  }, [onClose])

  // Backdrop-click closes — but only a genuine click on the overlay itself,
  // not a drag/selection that started inside the card and released on the
  // backdrop. We track where the mousedown landed.
  const downOnOverlay = useRef(false)
  const onOverlayMouseDown = (e: MouseEvent<HTMLDivElement>) => {
    downOnOverlay.current = e.target === e.currentTarget
  }
  const onOverlayMouseUp = (e: MouseEvent<HTMLDivElement>) => {
    if (downOnOverlay.current && e.target === e.currentTarget) onClose()
    downOnOverlay.current = false
  }

  // Render into document.body via a portal. The overlay is position:fixed, but
  // if ANY ancestor has transform/filter/contain (Carbon shell, animated
  // collapsible sidebar, etc.) fixed positioning anchors to that ancestor and
  // the modal gets clipped by its overflow — which is why the body text was cut
  // off on the right. Portaling to <body> guarantees viewport-relative
  // positioning and top-level stacking, independent of where it's rendered.
  return createPortal(
    <div
      className="c2-dlg-overlay"
      onMouseDown={onOverlayMouseDown}
      onMouseUp={onOverlayMouseUp}
    >
      <div
        ref={cardRef}
        className="c2-dlg"
        role="dialog"
        aria-modal="true"
        aria-label={titleIsString ? (title as string) : undefined}
        tabIndex={-1}
        style={{ width: `min(${width}px, calc(100vw - 2rem))` }}
      >
        <div className="c2-dlg-header">
          <div className="c2-dlg-title">{title}</div>
          <button
            type="button"
            className="c2-dlg-close"
            aria-label="Close"
            onClick={onClose}
          >
            ✕
          </button>
        </div>

        <div className="c2-dlg-body">{children}</div>

        {footer != null && <div className="c2-dlg-footer">{footer}</div>}
      </div>
    </div>,
    document.body,
  )
}

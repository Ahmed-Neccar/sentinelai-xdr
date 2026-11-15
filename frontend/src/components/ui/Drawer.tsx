import { useEffect, useRef, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import gsap from 'gsap'
import { X } from 'lucide-react'
import { prefersReducedMotion } from '../../design/motion'

const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])'

/**
 * A panel that slides in from the right over the page. It scrolls on its own, traps the keyboard
 * focus while open, closes on Escape or a click outside, and hands focus back when it closes.
 */
export default function Drawer({
  title,
  eyebrow,
  closeLabel,
  onClose,
  children,
  width = 640,
}: {
  title: ReactNode
  eyebrow?: string
  closeLabel: string
  onClose: () => void
  children: ReactNode
  width?: number
}) {
  const panel = useRef<HTMLDivElement>(null)
  const returnTo = useRef<Element | null>(null)

  useEffect(() => {
    returnTo.current = document.activeElement
    const element = panel.current
    if (!element) return
    if (!prefersReducedMotion()) gsap.fromTo(element, { x: 56, opacity: 0 }, { x: 0, opacity: 1, duration: 0.38, ease: 'power3.out' })
    element.querySelector<HTMLElement>(FOCUSABLE)?.focus()
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { onClose(); return }
      if (event.key !== 'Tab') return
      const items = [...element.querySelectorAll<HTMLElement>(FOCUSABLE)]
      if (!items.length) return
      const first = items[0]
      const last = items[items.length - 1]
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      if (returnTo.current instanceof HTMLElement) returnTo.current.focus()
    }
    // onClose is read through the latest closure on each key press by design.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Rendered on the body: a parent with a blur filter would otherwise become the containing block of this fixed layer.
  return createPortal(
    <div className="drawer-backdrop" onMouseDown={event => { if (event.target === event.currentTarget) onClose() }}>
      <div className="drawer" role="dialog" aria-modal="true" aria-label={typeof title === 'string' ? title : undefined} ref={panel} style={{ width: `min(${width}px, 100vw)` }}>
        <header className="drawer-head">
          <div>
            {eyebrow && <div className="eyebrow">{eyebrow}</div>}
            <h2>{title}</h2>
          </div>
          <button type="button" className="icon-button" aria-label={closeLabel} onClick={onClose}><X size={18} /></button>
        </header>
        <div className="drawer-body">{children}</div>
      </div>
    </div>
    , document.body)
}

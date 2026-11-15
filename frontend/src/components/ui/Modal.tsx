import { useEffect, useRef, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { X } from 'lucide-react'

const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])'

/** A centred dialog with a focus trap, Escape to close and focus returned to what opened it. */
export default function Modal({ title, closeLabel, onClose, children, busy = false }: { title: string; closeLabel: string; onClose: () => void; children: ReactNode; busy?: boolean }) {
  const box = useRef<HTMLDivElement>(null)
  const returnTo = useRef<Element | null>(null)
  useEffect(() => {
    returnTo.current = document.activeElement
    const element = box.current
    if (!element) return
    const first = element.querySelector<HTMLElement>('input,select,textarea') ?? element.querySelector<HTMLElement>(FOCUSABLE)
    first?.focus()
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !busy) { onClose(); return }
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [busy])
  // Rendered on the body: a parent with a blur filter would otherwise become the containing block of this fixed layer.
  return createPortal(
    <div className="modal-backdrop" onMouseDown={event => { if (event.target === event.currentTarget && !busy) onClose() }}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title} ref={box}>
        <header className="modal-head">
          <h2>{title}</h2>
          <button type="button" className="icon-button" aria-label={closeLabel} onClick={onClose} disabled={busy}><X size={18} /></button>
        </header>
        <div className="modal-body">{children}</div>
      </div>
    </div>
    , document.body)
}

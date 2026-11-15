import { useRef, type HTMLAttributes, type ReactNode } from 'react'
import { prefersReducedMotion } from '../../design/motion'

/** A card with a soft light that follows the pointer. Pure CSS variables, no re-render per move. */
export default function Spotlight({ children, className = '', ...rest }: { children: ReactNode } & HTMLAttributes<HTMLDivElement>) {
  const ref = useRef<HTMLDivElement>(null)
  const move = (event: React.PointerEvent<HTMLDivElement>) => {
    if (prefersReducedMotion()) return
    const box = ref.current?.getBoundingClientRect()
    if (!box || !ref.current) return
    ref.current.style.setProperty('--mx', `${event.clientX - box.left}px`)
    ref.current.style.setProperty('--my', `${event.clientY - box.top}px`)
  }
  return <div ref={ref} className={`spotlight ${className}`} onPointerMove={move} {...rest}>{children}</div>
}

import { useEffect, type RefObject } from 'react'
import Lenis from 'lenis'
import { prefersReducedMotion } from '../../design/motion'

/**
 * Smooth scrolling for one long reading container only (a threat summary or case report).
 *
 * It is deliberately never attached to `window`: the side menu, the event feed and the slide-over
 * drawers each scroll on their own, and a global smooth scroller would fight them. The instance
 * is destroyed with the container.
 */
export function useScopedLenis(wrapper: RefObject<HTMLElement | null>, content: RefObject<HTMLElement | null>) {
  useEffect(() => {
    const outer = wrapper.current
    const inner = content.current
    if (!outer || !inner || prefersReducedMotion()) return
    const lenis = new Lenis({ wrapper: outer, content: inner, lerp: 0.12, smoothWheel: true })
    let frame = 0
    const raf = (time: number) => {
      lenis.raf(time)
      frame = requestAnimationFrame(raf)
    }
    frame = requestAnimationFrame(raf)
    return () => {
      cancelAnimationFrame(frame)
      lenis.destroy()
    }
  }, [wrapper, content])
}

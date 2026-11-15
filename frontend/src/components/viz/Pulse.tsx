import { useEffect, useRef } from 'react'
import gsap from 'gsap'
import { prefersReducedMotion } from '../../design/motion'

/** A heartbeat ring: expanding while a sensor reports, still and grey when it does not. */
export default function Pulse({ online, label }: { online: boolean; label: string }) {
  const ring = useRef<HTMLSpanElement>(null)
  useEffect(() => {
    const element = ring.current
    if (!element || !online || prefersReducedMotion()) return
    const tween = gsap.fromTo(element, { scale: 1, opacity: 0.55 }, { scale: 2.4, opacity: 0, duration: 1.8, repeat: -1, ease: 'power1.out' })
    return () => { tween.kill() }
  }, [online])
  return (
    <span className={`pulse ${online ? 'on' : 'off'}`} role="img" aria-label={label}>
      {online && <span className="pulse-ring" ref={ring} />}
      <span className="pulse-dot" />
    </span>
  )
}

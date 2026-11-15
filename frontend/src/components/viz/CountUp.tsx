import { useEffect, useRef, useState } from 'react'
import { prefersReducedMotion } from '../../design/motion'

/** A number that counts up to its value once, then follows changes. */
export default function CountUp({ value, locale = 'en-US', duration = 900 }: { value: number; locale?: string; duration?: number }) {
  const [shown, setShown] = useState(prefersReducedMotion() ? value : 0)
  const from = useRef(0)
  useEffect(() => {
    if (prefersReducedMotion() || duration <= 0) { setShown(value); return }
    const start = performance.now()
    const origin = from.current
    let frame = 0
    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / duration)
      const eased = 1 - Math.pow(1 - progress, 3)
      const current = Math.round(origin + (value - origin) * eased)
      setShown(current)
      from.current = current
      if (progress < 1) frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [value, duration])
  return <span className="count-up">{shown.toLocaleString(locale)}</span>
}

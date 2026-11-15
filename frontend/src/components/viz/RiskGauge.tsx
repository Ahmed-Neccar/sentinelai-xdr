import { useEffect, useRef } from 'react'
import gsap from 'gsap'
import { prefersReducedMotion } from '../../design/motion'
import { riskColor } from '../../design/severity'

/** A circular 0 to 100 gauge. The arc fills with GSAP unless the system asks for less motion. */
export default function RiskGauge({ value, size = 132, label }: { value: number; size?: number; label?: string }) {
  const arc = useRef<SVGCircleElement>(null)
  const clamped = Math.max(0, Math.min(100, Number.isFinite(value) ? value : 0))
  const radius = 52
  const circumference = 2 * Math.PI * radius
  const full = circumference * 0.75 // three quarters of a circle, open at the bottom
  const color = riskColor(clamped)
  useEffect(() => {
    const element = arc.current
    if (!element) return
    const target = full * (1 - clamped / 100)
    if (prefersReducedMotion()) { element.style.strokeDashoffset = String(target); return }
    const tween = gsap.fromTo(element, { strokeDashoffset: full }, { strokeDashoffset: target, duration: 1.1, ease: 'power3.out' })
    return () => { tween.kill() }
  }, [clamped, full])
  return (
    <figure className="risk-gauge" style={{ width: size, height: size }} aria-label={`${label ?? 'Risk'} ${Math.round(clamped)} / 100`}>
      <svg viewBox="0 0 132 132" aria-hidden="true">
        <g transform="rotate(135 66 66)">
          <circle cx="66" cy="66" r={radius} fill="none" stroke="rgba(255,255,255,.08)" strokeWidth="10" strokeLinecap="round" strokeDasharray={`${full} ${circumference}`} />
          <circle ref={arc} cx="66" cy="66" r={radius} fill="none" stroke={color} strokeWidth="10" strokeLinecap="round" strokeDasharray={`${full} ${circumference}`} strokeDashoffset={full} style={{ filter: `drop-shadow(0 0 6px ${color}88)` }} />
        </g>
      </svg>
      <figcaption><b style={{ color }}>{Math.round(clamped)}</b>{label && <small>{label}</small>}</figcaption>
    </figure>
  )
}

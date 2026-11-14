import { useEffect, useRef } from 'react'

export const IDLE_MINUTES = 30
const EVENTS = ['pointerdown', 'keydown', 'wheel', 'touchstart'] as const

/**
 * Calls `onIdle` once the person has not touched the page for `minutes`.
 *
 * Background polling keeps the access token fresh, so without this an unattended tab could stay
 * signed in as long as the server allows. The last activity is compared with the clock on a
 * short interval, so a laptop that slept past the limit is signed out as soon as it wakes.
 */
export function useIdleLogout(active: boolean, onIdle: () => void, minutes = IDLE_MINUTES) {
  const callback = useRef(onIdle)
  callback.current = onIdle
  useEffect(() => {
    if (!active) return
    let last = Date.now()
    const touch = () => { last = Date.now() }
    const check = () => {
      if (Date.now() - last >= minutes * 60_000) callback.current()
    }
    EVENTS.forEach(name => window.addEventListener(name, touch, { passive: true }))
    const timer = window.setInterval(check, 15_000)
    document.addEventListener('visibilitychange', check)
    return () => {
      EVENTS.forEach(name => window.removeEventListener(name, touch))
      window.clearInterval(timer)
      document.removeEventListener('visibilitychange', check)
    }
  }, [active, minutes])
}

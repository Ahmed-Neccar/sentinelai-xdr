/** Motion is decoration. When the system asks for less of it, every animation jumps to its end state. */
export const prefersReducedMotion = (): boolean =>
  typeof window !== 'undefined' && !!window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches

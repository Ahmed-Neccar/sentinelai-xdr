import { describe, expect, it } from 'vitest'
import { riskPercent } from './ForensicDrawer'

describe('riskPercent', () => {
  it('reads a 0 to 1 probability and a 0 to 100 score', () => {
    expect(riskPercent(0.42, 'low')).toBeCloseTo(42)
    expect(riskPercent(73, 'low')).toBe(73)
    expect(riskPercent(250, 'low')).toBe(100)
  })
  it('falls back to the severity when the detector gave no score', () => {
    expect(riskPercent(null, 'high')).toBe(70)
    expect(riskPercent(undefined, 'critical')).toBe(90)
    expect(riskPercent('not a number', 'weird')).toBe(5)
  })
})

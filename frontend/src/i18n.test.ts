import { describe, expect, it } from 'vitest'
import { translate } from './i18n'

describe('translate', () => {
  it('returns the English text unchanged', () => {
    expect(translate('Refresh', 'en')).toBe('Refresh')
  })

  it('translates known strings and falls back to the original for unknown ones', () => {
    expect(translate('Refresh', 'tr')).toBe('Yenile')
    expect(translate('A sentence nobody has translated yet', 'tr')).toBe(
      'A sentence nobody has translated yet',
    )
  })

  it('has Turkish text for the newest screens', () => {
    for (const key of [
      'System health',
      'Failed sign-ins, last 24 hours',
      'Test message delivered.',
      'Registered sensors',
    ]) {
      expect(translate(key, 'tr')).not.toBe(key)
    }
  })
})

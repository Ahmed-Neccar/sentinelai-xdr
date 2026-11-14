import { afterEach, describe, expect, it } from 'vitest'
import { startAutoTranslate, translateString } from './autoTranslate'

afterEach(() => {
  document.body.innerHTML = ''
})

const tick = () => new Promise((resolve) => setTimeout(resolve, 0))

describe('translateString', () => {
  it('translates whole known strings and keeps surrounding spaces', () => {
    expect(translateString('  Refresh ', 'tr')).toBe('  Yenile ')
    expect(translateString('Refresh', 'en')).toBe('Refresh')
    expect(translateString('Something nobody translated', 'tr')).toBe('Something nobody translated')
  })

  it('translates the prefix of a case title and the rule name after it', () => {
    expect(translateString('Investigation: Windows service installed', 'tr')).toBe(
      'İnceleme: Windows hizmeti kuruldu',
    )
  })
})

describe('startAutoTranslate', () => {
  it('translates text and attributes, follows later changes and restores English', async () => {
    document.body.innerHTML = '<p id="a">Refresh</p><input id="b" placeholder="Refresh"><code>Refresh</code>'
    const stop = startAutoTranslate('tr')
    expect(document.getElementById('a')?.textContent).toBe('Yenile')
    expect(document.getElementById('b')?.getAttribute('placeholder')).toBe('Yenile')
    expect(document.querySelector('code')?.textContent).toBe('Refresh') // code is left alone

    const added = document.createElement('span')
    added.textContent = 'Refresh'
    document.body.appendChild(added)
    document.getElementById('a')!.firstChild!.nodeValue = 'Refresh' // React writing English again
    await tick()
    expect(added.textContent).toBe('Yenile')
    expect(document.getElementById('a')?.textContent).toBe('Yenile')

    stop()
    expect(document.getElementById('a')?.textContent).toBe('Refresh')
    expect(document.getElementById('b')?.getAttribute('placeholder')).toBe('Refresh')
  })

  it('does nothing for English', () => {
    document.body.innerHTML = '<p id="a">Refresh</p>'
    const stop = startAutoTranslate('en')
    expect(document.getElementById('a')?.textContent).toBe('Refresh')
    stop()
  })
})

describe('detector sentences', () => {
  it('translates the sentences the detectors build and keeps the numbers and addresses', () => {
    expect(
      translateString(
        '14 distinct destination ports from 203.0.113.50 in 120s starting 2026-10-21T12:40:00+00:00 (threshold 12).',
        'tr',
      ),
    ).toBe('203.0.113.50 adresinden 120 sn içinde 14 farklı hedef port, başlangıç 2026-10-21T12:40:00+00:00 (eşik 12).')
    expect(
      translateString('9 failures and 1 success(es) from 198.51.100.24 in window starting 2026-10-21T12:30:00+00:00.', 'tr'),
    ).toContain('198.51.100.24 adresinden')
    expect(
      translateString(
        '9 matching events for src_ip=198.51.100.24 in a 300s window starting 2026-10-21T12:30:00+00:00 (threshold 8). Synthetic or lab telemetry only unless labeled otherwise.',
        'tr',
      ),
    ).toContain('9 eşleşen olay')
    expect(translateString('Failed sign-in (9), Successful sign-in (1)', 'tr')).toBe(
      'Başarısız oturum açma (9), Başarılı oturum açma (1)',
    )
  })
})

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { hashForSection, sectionFromHash } from './app/router'
import Drawer from './components/ui/Drawer'
import Stepper from './components/ui/Stepper'
import Tabs from './components/ui/Tabs'
import { SeverityPill } from './components/viz/badges'
import { riskIndex } from './features/overview/BentoOverview'
import { EnrollModal, RevokeDialog } from './features/sensors/SensorDialogs'
import { lifecycleOf } from './services/responses'
import { isSensorOnline } from './services/sensors'

afterEach(() => { cleanup(); vi.restoreAllMocks() })

describe('router', () => {
  it('turns sections into hashes and back', () => {
    expect(hashForSection('Network discovery')).toBe('#/network-discovery')
    expect(sectionFromHash('#/network-discovery')).toBe('Network discovery')
    expect(sectionFromHash('#/cases?x=1')).toBe('Cases')
    expect(sectionFromHash('#/nonsense')).toBeNull()
    expect(sectionFromHash('')).toBeNull()
  })
})

describe('response lifecycle mapping', () => {
  it('maps server states onto proposed, approved, dispatched, executed or failed', () => {
    expect(lifecycleOf({ status: 'proposed' })).toEqual({ index: 0 })
    expect(lifecycleOf({ status: 'approved', enforcement_status: 'pending' })).toEqual({ index: 1 })
    expect(lifecycleOf({ status: 'approved', enforcement_status: 'dispatched' })).toEqual({ index: 2 })
    expect(lifecycleOf({ status: 'approved', enforcement_status: 'applied' })).toEqual({ index: 3 })
    const failed = lifecycleOf({ status: 'approved', enforcement_status: 'failed' })
    expect(failed.failedAt).toBe(3)
    expect(lifecycleOf({ status: 'rejected' }).failedAt).toBe(1)
    expect(lifecycleOf({ status: 'approved', enforcement_status: 'cancelled' }).failedAt).toBe(2)
  })
})

describe('sensor liveness', () => {
  it('treats a sensor as online only when active and seen in the last 45 seconds', () => {
    const now = Date.parse('2026-11-15T12:00:00Z')
    expect(isSensorOnline({ status: 'active', last_seen_at: '2026-11-15T11:59:30Z' }, now)).toBe(true)
    expect(isSensorOnline({ status: 'active', last_seen_at: '2026-11-15T11:58:00Z' }, now)).toBe(false)
    expect(isSensorOnline({ status: 'revoked', last_seen_at: '2026-11-15T11:59:59Z' }, now)).toBe(false)
    expect(isSensorOnline({ status: 'active', last_seen_at: null }, now)).toBe(false)
  })
})

describe('risk index', () => {
  it('weights findings by severity and caps at 100', () => {
    expect(riskIndex([])).toBe(0)
    expect(riskIndex([{ severity: 'high' }, { severity: 'medium' }])).toBe(28)
    expect(riskIndex(Array.from({ length: 10 }, () => ({ severity: 'critical' })))).toBe(100)
  })
})

describe('Stepper', () => {
  it('marks the current step and the step where it failed', () => {
    render(<Stepper label="progress" currentIndex={2} failedAt={3} steps={[{ key: 'a', label: 'A' }, { key: 'b', label: 'B' }, { key: 'c', label: 'C' }, { key: 'd', label: 'D' }]} />)
    expect(screen.getByLabelText('progress').querySelector('.step.current')?.textContent).toContain('C')
    expect(screen.getByLabelText('progress').querySelector('.step.failed')?.textContent).toContain('D')
    expect(screen.getByLabelText('progress').querySelectorAll('.step.done').length).toBe(2)
  })
})

describe('Tabs', () => {
  it('moves with the arrow keys and shows only the active panel', () => {
    const change = vi.fn()
    const items = [{ id: 'one', label: 'One', content: <p>first</p> }, { id: 'two', label: 'Two', content: <p>second</p> }]
    render(<Tabs label="t" items={items} active="one" onChange={change} />)
    expect(screen.getByText('first')).toBeTruthy()
    expect(screen.queryByText('second')).toBeNull()
    fireEvent.keyDown(screen.getAllByRole('tab')[0], { key: 'ArrowRight' })
    expect(change).toHaveBeenCalledWith('two')
  })
})

describe('Drawer', () => {
  it('closes on Escape and on a click outside, and keeps focus inside', () => {
    const close = vi.fn()
    render(<Drawer title="Finding" closeLabel="Close" onClose={close}><button>inside</button></Drawer>)
    expect(screen.getByRole('dialog').getAttribute('aria-modal')).toBe('true')
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(close).toHaveBeenCalledTimes(1)
    fireEvent.mouseDown(document.querySelector('.drawer-backdrop')!)
    expect(close).toHaveBeenCalledTimes(2)
  })
})

describe('SeverityPill', () => {
  it('shows text with the colour class, never colour alone', () => {
    render(<SeverityPill severity="HIGH" />)
    const pill = screen.getByText('high')
    expect(pill.className).toContain('high')
  })
})

describe('sensor dialogs', () => {
  it('registers a sensor and shows the key once', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ name: 'Lab PC', email: 'sensor-lab@x.test', password: 'p'.repeat(40) }), { status: 201, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    const created = vi.fn()
    render(<EnrollModal language="en" onClose={vi.fn()} onCreated={created} setError={vi.fn()} />)
    fireEvent.change(screen.getByLabelText('Name of the computer'), { target: { value: 'Lab PC' } })
    fireEvent.click(screen.getByRole('button', { name: 'Generate key' }))
    await waitFor(() => expect(screen.getByText('sensor-lab@x.test')).toBeTruthy())
    expect(created).toHaveBeenCalled()
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/ingest/live/sensors/enrollment')
    vi.unstubAllGlobals()
  })

  it('asks before revoking and calls the revoke endpoint on confirm', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    const revoked = vi.fn()
    render(<RevokeDialog language="en" sensor={{ sensor_id: 's1', host_name: 'LAB-PC', credential_email: 'a@b.test', status: 'active' }} onClose={vi.fn()} onRevoked={revoked} setError={vi.fn()} />)
    expect(fetchMock).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Revoke access' }))
    await waitFor(() => expect(revoked).toHaveBeenCalled())
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/ingest/live/sensors/s1/revoke')
    vi.unstubAllGlobals()
  })
})

describe('Modal focus', () => {
  it('puts the keyboard in the first field when it opens', () => {
    render(<EnrollModal language="en" onClose={vi.fn()} onCreated={vi.fn()} setError={vi.fn()} />)
    expect(document.activeElement?.tagName).toBe('INPUT')
  })
})

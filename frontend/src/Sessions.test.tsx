import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import Sessions, { deviceName } from './Sessions'

afterEach(cleanup)

describe('deviceName', () => {
  it('reads browser and system from the user-agent text', () => {
    expect(deviceName('Mozilla/5.0 (Windows NT 10.0) Chrome/120 Safari/537 Edg/120')).toBe('Edge · Windows')
    expect(deviceName(null)).toBe('Unknown device')
  })
})

describe('Sessions', () => {
  it('lists sessions and ends another one', async () => {
    const list = { items: [
      { id: 'a', ip_address: '10.0.0.1', user_agent: 'Chrome/1 Windows', last_active: '2026-11-15T10:00:00Z', expires_at: '2026-11-15T20:00:00Z', current: true },
      { id: 'b', ip_address: '10.0.0.2', user_agent: 'Firefox/1 Linux', last_active: '2026-11-15T09:00:00Z', expires_at: '2026-11-15T19:00:00Z', current: false },
    ] }
    const api = vi.fn().mockResolvedValue(list)
    render(<Sessions language="en" setError={vi.fn()} apiRequest={api} />)
    await waitFor(() => expect(screen.getByText('This device')).toBeTruthy())
    expect(screen.getAllByRole('button', { name: 'End session' }).length).toBe(1)
    fireEvent.click(screen.getByRole('button', { name: 'End session' }))
    await waitFor(() => expect(api).toHaveBeenCalledWith('/auth/sessions/b', { method: 'DELETE' }))
  })
})

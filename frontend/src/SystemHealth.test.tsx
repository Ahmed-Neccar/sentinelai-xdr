import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import SystemHealth from './SystemHealth'

afterEach(cleanup)

const healthy = {
  sensors: { online: 2, silent: [] },
  connectors: [
    { name: 'azure-prod', provider: 'azure_activity', status: 'idle', healthy: true, enabled: true, last_success_at: null, last_error: null },
  ],
  notifications: { enabled_channels: 1, pending: 0, failed_24h: 0 },
}

describe('SystemHealth', () => {
  it('says everything is normal when nothing is wrong', async () => {
    const api = vi.fn().mockResolvedValue(healthy)
    render(<SystemHealth language="en" apiRequest={api} />)
    await waitFor(() => expect(screen.getByText('Everything reports normally.')).toBeTruthy())
    expect(screen.getByText('azure-prod')).toBeTruthy()
    expect(api).toHaveBeenCalledWith('/system/health')
  })

  it('counts a silent sensor, a failing connector and failed messages as problems', async () => {
    const api = vi.fn().mockResolvedValue({
      sensors: { online: 0, silent: [{ name: 'office-pc', last_heartbeat_at: '2026-11-14T10:00:00Z' }] },
      connectors: [{ ...healthy.connectors[0], healthy: false, status: 'error', last_error: 'Authentication failed' }],
      notifications: { enabled_channels: 1, pending: 0, failed_24h: 3 },
    })
    render(<SystemHealth language="en" apiRequest={api} />)
    await waitFor(() => expect(screen.getByText('3 problems need attention')).toBeTruthy())
    expect(screen.getByText(/office-pc: no heartbeat/)).toBeTruthy()
    expect(screen.getByText(/Authentication failed/)).toBeTruthy()
  })

  it('shows Turkish labels and renders nothing when the request fails', async () => {
    const { container, rerender } = render(<SystemHealth language="tr" apiRequest={vi.fn().mockResolvedValue(healthy)} />)
    await waitFor(() => expect(screen.getByText('Her şey normal görünüyor.')).toBeTruthy())
    rerender(<SystemHealth language="tr" apiRequest={vi.fn().mockRejectedValue(new Error('x'))} />)
    await waitFor(() => expect(container.querySelector('section')).toBeNull())
  })
})

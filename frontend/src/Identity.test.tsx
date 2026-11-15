import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import Identity from './Identity'

afterEach(cleanup)

const settings = {
  sso_enabled: true,
  auto_provision: false,
  sync_roles: false,
  default_role: null,
  mappings: [{ id: 'm1', claim_value: 'soc-analysts', role_name: 'analyst' }],
  scim_base_path: '/api/v1/scim/v2',
  scim_tokens: [],
}

describe('Identity', () => {
  it('shows the mappings and saves a switched setting', async () => {
    const api = vi.fn().mockResolvedValue(settings)
    render(<Identity language="en" setError={vi.fn()} apiRequest={api} />)
    await waitFor(() => expect(screen.getByText('soc-analysts')).toBeTruthy())
    fireEvent.click(screen.getByLabelText(/Create accounts on first sign-in/))
    await waitFor(() => expect(api).toHaveBeenCalledWith('/identity/settings', expect.objectContaining({ method: 'PUT' })))
    const put = api.mock.calls.find(call => call[1]?.method === 'PUT')!
    expect(JSON.parse(put[1].body)).toEqual({ auto_provision: true, sync_roles: false, default_role: null })
  })

  it('shows a new SCIM token once', async () => {
    const api = vi.fn().mockImplementation(async (path: string, init?: RequestInit) =>
      path === '/identity/scim-tokens' && init?.method === 'POST' ? { id: 't1', name: 'Entra', token: 'scim_secret_value' } : settings)
    render(<Identity language="en" setError={vi.fn()} apiRequest={api} />)
    await waitFor(() => expect(screen.getByLabelText('Token name')).toBeTruthy())
    fireEvent.change(screen.getByLabelText('Token name'), { target: { value: 'Entra' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create token' }))
    await waitFor(() => expect(screen.getByText('scim_secret_value')).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: 'I saved it' }))
    expect(screen.queryByText('scim_secret_value')).toBeNull()
  })
})

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import PasswordDialog from './PasswordDialog'

afterEach(cleanup)

const target = { id: 'u1', email: 'someone@example.test' }

function setup(self: boolean, api = vi.fn().mockResolvedValue({})) {
  const done = vi.fn()
  render(<PasswordDialog language="en" target={target} self={self} apiRequest={api} onClose={vi.fn()} onDone={done} />)
  return { api, done }
}

describe('PasswordDialog', () => {
  it('asks for the administrator password first, then sets the new one', async () => {
    const { api, done } = setup(false)
    expect(screen.queryByLabelText('New password')).toBeNull()
    fireEvent.change(screen.getByLabelText('Your own administrator password'), { target: { value: 'Admin-pass-12345' } })
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'Brand-new-pass-456' } })
    fireEvent.change(screen.getByLabelText('Repeat the new password'), { target: { value: 'Brand-new-pass-456' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save password' }))
    await waitFor(() => expect(done).toHaveBeenCalled())
    expect(api).toHaveBeenCalledWith('/users/u1', {
      method: 'PATCH',
      body: JSON.stringify({ password: 'Brand-new-pass-456', confirm_password: 'Admin-pass-12345' }),
    })
  })

  it('uses the self-service endpoint for one’s own account and returns to step 1 on a wrong password', async () => {
    const api = vi.fn().mockRejectedValue(new Error('Current password is incorrect'))
    setup(true, api)
    fireEvent.change(screen.getByLabelText('Your current password'), { target: { value: 'wrong-password-1' } })
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'Brand-new-pass-456' } })
    fireEvent.change(screen.getByLabelText('Repeat the new password'), { target: { value: 'Brand-new-pass-456' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save password' }))
    await waitFor(() => expect(screen.getByLabelText('Your current password')).toBeTruthy())
    expect(api.mock.calls[0][0]).toBe('/auth/password')
    expect(screen.getByRole('alert').textContent).toMatch(/incorrect/)
  })
})

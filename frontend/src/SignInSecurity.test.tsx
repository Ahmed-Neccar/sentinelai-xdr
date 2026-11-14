import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import SignInSecurity from './SignInSecurity'

afterEach(cleanup)

describe('SignInSecurity', () => {
  it('lists the accounts and addresses with the most failed attempts', async () => {
    const api = vi.fn().mockResolvedValue({
      hours: 24,
      total: 5,
      by_action: { 'auth.login_failed': 4, 'auth.sso_failed': 1 },
      top_sources: [{ ip_address: '10.0.0.9', account: 'a@example.test', attempts: 4, last_attempt: '2026-11-14T10:00:00Z' }],
    })
    render(<SignInSecurity language="en" setError={vi.fn()} apiRequest={api} />)
    await waitFor(() => expect(screen.getByText('5 failed attempts')).toBeTruthy())
    expect(screen.getByText('a@example.test')).toBeTruthy()
    expect(screen.getByText('10.0.0.9')).toBeTruthy()
    expect(screen.getByText('Wrong password or unknown account')).toBeTruthy()
    expect(api).toHaveBeenCalledWith('/audit-logs/sign-in-security?hours=24')
  })

  it('reports an empty period and passes load errors on', async () => {
    const empty = vi.fn().mockResolvedValue({ hours: 24, total: 0, by_action: {}, top_sources: [] })
    render(<SignInSecurity language="en" setError={vi.fn()} apiRequest={empty} />)
    await waitFor(() => expect(screen.getByText('No failed sign-ins in the last 24 hours.')).toBeTruthy())
    cleanup()
    const setError = vi.fn()
    render(<SignInSecurity language="en" setError={setError} apiRequest={vi.fn().mockRejectedValue(new Error('denied'))} />)
    await waitFor(() => expect(setError).toHaveBeenCalledWith('denied'))
  })
})

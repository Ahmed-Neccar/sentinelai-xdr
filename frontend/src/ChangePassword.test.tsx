import { act, cleanup, fireEvent, render, renderHook, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import ChangePassword, { passwordProblem } from './ChangePassword'
import { useIdleLogout } from './useIdleLogout'

afterEach(() => {
  cleanup()
  vi.useRealTimers()
})

describe('passwordProblem', () => {
  it('flags short, unchanged and mismatched passwords', () => {
    expect(passwordProblem('old-password-1', 'short', '')).toMatch(/12 characters/)
    expect(passwordProblem('same-password-12', 'same-password-12', '')).toMatch(/different/)
    expect(passwordProblem('old-password-1', 'a-long-new-password', 'another-one')).toMatch(/match/)
    expect(passwordProblem('old-password-1', 'a-long-new-password', 'a-long-new-password')).toBe('')
  })
})

describe('ChangePassword', () => {
  it('sends the current and the new password and reports success', async () => {
    const api = vi.fn().mockResolvedValue({ access_token: 'x', user: { id: '1' } })
    const changed = vi.fn()
    render(<ChangePassword language="en" apiRequest={api} onChanged={changed} setError={vi.fn()} />)
    const button = screen.getByRole('button', { name: 'Change password' }) as HTMLButtonElement
    expect(button.disabled).toBe(true)
    fireEvent.change(screen.getByLabelText('Current password'), { target: { value: 'Old-password-123' } })
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'Brand-new-pass-456' } })
    fireEvent.change(screen.getByLabelText('Repeat the new password'), { target: { value: 'Brand-new-pass-456' } })
    expect(button.disabled).toBe(false)
    fireEvent.click(button)
    await waitFor(() => expect(changed).toHaveBeenCalled())
    expect(api).toHaveBeenCalledWith('/auth/password', {
      method: 'POST',
      body: JSON.stringify({ current_password: 'Old-password-123', new_password: 'Brand-new-pass-456' }),
    })
    expect(screen.getByRole('status').textContent).toMatch(/Password changed/)
  })

  it('shows a mismatch as an alert and does not send anything', () => {
    const api = vi.fn()
    render(<ChangePassword language="en" apiRequest={api} onChanged={vi.fn()} setError={vi.fn()} />)
    fireEvent.change(screen.getByLabelText('Current password'), { target: { value: 'Old-password-123' } })
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'Brand-new-pass-456' } })
    fireEvent.change(screen.getByLabelText('Repeat the new password'), { target: { value: 'Different-pass-789' } })
    expect(screen.getByRole('alert').textContent).toMatch(/do not match/)
    expect(api).not.toHaveBeenCalled()
  })
})

describe('useIdleLogout', () => {
  it('signs out after the idle period and not while the person is active', () => {
    vi.useFakeTimers()
    const onIdle = vi.fn()
    renderHook(() => useIdleLogout(true, onIdle, 1))
    act(() => { vi.advanceTimersByTime(45_000) })
    window.dispatchEvent(new Event('keydown'))
    act(() => { vi.advanceTimersByTime(45_000) })
    expect(onIdle).not.toHaveBeenCalled()
    act(() => { vi.advanceTimersByTime(30_000) })
    expect(onIdle).toHaveBeenCalled()
  })

  it('does nothing while nobody is signed in', () => {
    vi.useFakeTimers()
    const onIdle = vi.fn()
    renderHook(() => useIdleLogout(false, onIdle, 1))
    act(() => { vi.advanceTimersByTime(10 * 60_000) })
    expect(onIdle).not.toHaveBeenCalled()
  })
})

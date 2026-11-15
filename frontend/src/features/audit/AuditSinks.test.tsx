import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import AuditSinks from './AuditSinks'

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

describe('AuditSinks', () => {
  it('lists destinations with their state and never shows the address', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json([
      { id: 'a', name: 'Splunk', enabled: true, last_seq: 10, behind: 3, last_success_at: '2026-11-15T10:00:00Z', last_error: null, failures: 0 },
      { id: 'b', name: 'Archive', enabled: true, last_seq: 5, behind: 40, last_success_at: null, last_error: 'Destination timed out', failures: 2 },
    ])))
    render(<AuditSinks language="en" setError={vi.fn()} />)
    await waitFor(() => expect(screen.getByText('Splunk')).toBeTruthy())
    expect(screen.getByText('3 records waiting')).toBeTruthy()
    expect(screen.getByText('Failing')).toBeTruthy()
    expect(screen.getByText('Destination timed out')).toBeTruthy()
  })

  it('adds a destination with the typed address and the replay choice', async () => {
    const fetchMock = vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => (init?.method === 'POST' ? json({ id: 'c' }, 201) : json([])))
    vi.stubGlobal('fetch', fetchMock)
    render(<AuditSinks language="en" setError={vi.fn()} />)
    await waitFor(() => expect(screen.getByLabelText('Name')).toBeTruthy())
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Splunk' } })
    fireEvent.change(screen.getByLabelText('HTTPS address of the collector'), { target: { value: 'https://siem.example.com/x' } })
    fireEvent.click(screen.getByLabelText(/Also send the existing log/))
    fireEvent.click(screen.getByRole('button', { name: 'Add destination' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(call => call[1]?.method === 'POST')).toBe(true))
    const post = fetchMock.mock.calls.find(call => call[1]?.method === 'POST')!
    expect(JSON.parse(post[1].body)).toEqual({ name: 'Splunk', url: 'https://siem.example.com/x', from_beginning: true })
  })

  it('will not submit a signing secret that is too short', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json([])))
    render(<AuditSinks language="en" setError={vi.fn()} />)
    await waitFor(() => expect(screen.getByLabelText('Name')).toBeTruthy())
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'X' } })
    fireEvent.change(screen.getByLabelText('HTTPS address of the collector'), { target: { value: 'https://siem.example.com/x' } })
    fireEvent.change(screen.getByLabelText(/Signing secret/), { target: { value: 'short' } })
    expect((screen.getByRole('button', { name: 'Add destination' }) as HTMLButtonElement).disabled).toBe(true)
  })
})

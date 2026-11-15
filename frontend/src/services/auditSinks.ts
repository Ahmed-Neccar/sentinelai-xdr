import { api } from './http'

export type AuditSink = {
  id: string
  name: string
  enabled: boolean
  last_seq: number
  behind: number
  last_success_at?: string | null
  last_error?: string | null
  failures: number
}

export const auditSinks = {
  list: () => api<AuditSink[]>('/audit-sinks'),
  create: (body: { name: string; url: string; signing_secret?: string; from_beginning: boolean }) =>
    api<AuditSink>('/audit-sinks', { method: 'POST', body: JSON.stringify(body) }),
  setEnabled: (id: string, enabled: boolean) => api<AuditSink>(`/audit-sinks/${id}`, { method: 'PATCH', body: JSON.stringify({ enabled }) }),
  remove: (id: string) => api<unknown>(`/audit-sinks/${id}`, { method: 'DELETE' }),
  test: (id: string) => api<{ ok: boolean; error?: string }>(`/audit-sinks/${id}/test`, { method: 'POST' }),
}

import { api } from './http'

/** One executed response action as the server describes it. */
export type ResponseAction = {
  id: string
  case_id?: string
  action_type: string
  target: string
  status: string
  enforcement_status?: string | null
  enforcement_detail?: string
  failure_code?: string | null
  sensor_id?: string | null
  created_at?: string
  expires_at?: string
  block_until?: string | null
  duration_minutes?: number | null
}

export const responses = {
  /** The latest executed actions across all cases (newest first). */
  recent: () => api<{ items: ResponseAction[] }>('/cases/responses/recent'),
  approve: (caseId: string, id: string) => api<ResponseAction>(`/cases/${caseId}/responses/${id}/approve`, { method: 'POST' }),
}

export const LIFECYCLE_STEPS = ['proposed', 'approved', 'dispatched', 'executed'] as const

/**
 * Maps the server's two status fields (the proposal status and the enforcement status) onto the
 * four steps shown to people: proposed, approved, dispatched, executed or failed.
 */
export function lifecycleOf(action: Pick<ResponseAction, 'status' | 'enforcement_status'>): { index: number; failedAt?: number; ended?: string } {
  const proposal = action.status
  const enforcement = action.enforcement_status ?? null
  if (proposal === 'rejected' || proposal === 'expired') return { index: 0, failedAt: 1, ended: proposal }
  if (proposal === 'proposed') return { index: 0 }
  switch (enforcement) {
    case 'pending': return { index: 1 }
    case 'dispatched': return { index: 2 }
    case 'applied': return { index: 3 }
    case 'removal_pending': return { index: 3 }
    case 'removed': return { index: 4, ended: 'lifted' }
    case 'refused': return { index: 2, failedAt: 3, ended: 'refused' }
    case 'failed': return { index: 2, failedAt: 3, ended: 'failed' }
    case 'cancelled': return { index: 1, failedAt: 2, ended: 'cancelled' }
    default: return { index: 1 }
  }
}

import { api } from './http'
import type { Mitre } from '../components/viz/badges'

export type EvidenceEvent = {
  id: string
  event_time: string
  event_type: string
  host_id?: string | null
  src_ip?: string | null
  dst_ip?: string | null
  src_port?: number | null
  dst_port?: number | null
  attributes: Record<string, any>
}

export type DetectionDetail = {
  id: string
  title: string
  severity: string
  status: string
  summary?: string
  evidence?: Record<string, any>
  mitre?: Mitre[]
  score?: number | null
  score_kind?: string | null
  rule_id?: string | null
  rule_version?: number | null
  model_version?: string | null
  detector_kind?: string
  created_at: string
  attribution_note?: string | null
  evidence_events: EvidenceEvent[]
}

export const detections = {
  get: (id: string) => api<DetectionDetail>(`/detections/${id}`),
}

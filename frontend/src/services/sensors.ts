import { api } from './http'

export type SensorRow = {
  sensor_id: string
  source_name?: string
  host_name?: string
  credential_email: string
  status: string
  last_seen_at?: string | null
  sensor_version?: string
  capabilities?: string[]
}

export type Enrollment = { sensor_id?: string; name: string; email: string; password: string }

/** A sensor that has not reported for longer than this cannot be sent actions (the server enforces the same). */
export const SENSOR_ONLINE_MS = 45_000

export const isSensorOnline = (sensor: Pick<SensorRow, 'last_seen_at' | 'status'>, now = Date.now()): boolean =>
  sensor.status === 'active' && !!sensor.last_seen_at && now - new Date(sensor.last_seen_at).getTime() <= SENSOR_ONLINE_MS

export const sensors = {
  list: () => api<SensorRow[]>('/ingest/live/sensors'),
  enroll: (name: string) => api<Enrollment>('/ingest/live/sensors/enrollment', { method: 'POST', body: JSON.stringify({ name }) }),
  revoke: (sensorId: string) => api<unknown>(`/ingest/live/sensors/${sensorId}/revoke`, { method: 'POST' }),
  rotateCredential: (sensorId: string, password: string) =>
    api<unknown>(`/ingest/live/sensors/${sensorId}/rotate-credential`, { method: 'POST', body: JSON.stringify({ password }) }),
}

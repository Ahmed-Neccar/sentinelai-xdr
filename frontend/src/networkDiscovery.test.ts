import { describe, expect, it } from 'vitest'
import { networkScanEvents } from './networkDiscovery'

describe('networkScanEvents', () => {
  it('turns real per-port results into idempotent generic-ingest events', () => {
    const events = networkScanEvents({
      scan_id: 'scan-123',
      target: '192.168.1.0/30',
      state: 'completed',
      finished_at: '2026-11-21T10:00:00Z',
      results: [{
        address: '192.168.1.2',
        state: 'up',
        discovered_by: ['ARP', 'TCP'],
        ports: [
          { port: 22, state: 'open', service: 'SSH', identified: true },
          { port: 443, state: 'filtered', service: 'Unknown', identified: false },
        ],
      }],
    })

    expect(events).toHaveLength(2)
    expect(events[0]).toMatchObject({
      event_time: '2026-11-21T10:00:00Z',
      event_type: 'network.discovery.port',
      dst_ip: '192.168.1.2',
      dst_port: 22,
      source_name: 'network.discovery',
      outcome: 'open',
      service: 'SSH',
      dedup_key: 'network-discovery:scan-123:192.168.1.2:22',
      raw_payload: { discovered_by: ['ARP', 'TCP'] },
    })
    expect(events[1]).toMatchObject({ outcome: 'filtered', service: null })
  })

  it('records a completed scan with no responding hosts', () => {
    const [event] = networkScanEvents({
      scan_id: 'scan-empty',
      target: '192.168.1.0/30',
      state: 'completed',
      results: [],
    })

    expect(event).toMatchObject({
      event_type: 'network.discovery.scan',
      outcome: 'completed',
      dedup_key: 'network-discovery:scan-empty:summary',
      raw_payload: { responsive_hosts: 0, results: [] },
    })
  })
})

type PortResult = {
  port: number
  state: string
  service?: string
  port_hint?: string
  identified?: boolean
  product?: string | null
}

type HostResult = {
  address: string
  state: string
  discovered_by?: string[]
  ports: PortResult[]
}

export type NetworkScanResult = {
  scan_id: string
  target: string
  state: string
  started_at?: string
  finished_at?: string
  results: HostResult[]
}

export function networkScanEvents(scan: NetworkScanResult) {
  const eventTime = scan.finished_at || scan.started_at || new Date().toISOString()
  const common = { event_time: eventTime, severity: 'informational', source_name: 'network.discovery' }
  const events = scan.results.flatMap(host => host.ports.map(port => ({
    ...common,
    event_type: 'network.discovery.port',
    dst_ip: host.address,
    dst_port: port.port,
    host_id: host.address,
    activity: 'authorized_network_scan',
    outcome: port.state,
    service: port.identified ? port.service : null,
    message: `TCP port ${port.port} reported ${port.state} during authorized network discovery`,
    dedup_key: `network-discovery:${scan.scan_id}:${host.address}:${port.port}`,
    scan_id: scan.scan_id,
    raw_payload: { target: scan.target, scan_state: scan.state, discovered_by: host.discovered_by || [], port },
  })))

  if (events.length) return events
  return [{
    ...common,
    event_type: 'network.discovery.scan',
    activity: 'authorized_network_scan',
    outcome: scan.state,
    message: 'Authorized network discovery completed without a responsive device',
    dedup_key: `network-discovery:${scan.scan_id}:summary`,
    scan_id: scan.scan_id,
    target: scan.target,
    raw_payload: { target: scan.target, scan_state: scan.state, responsive_hosts: 0, results: [] },
  }]
}

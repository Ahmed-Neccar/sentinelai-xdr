import { AlertTriangle, Flame, Info, ShieldAlert, ShieldCheck } from 'lucide-react'
import { normalizeSeverity, type Severity } from '../../design/severity'

const ICON: Record<Severity, typeof Flame> = { critical: Flame, high: ShieldAlert, medium: AlertTriangle, low: Info, informational: ShieldCheck }

/** Severity as colour, icon and text together, so it never depends on colour alone. */
export function SeverityPill({ severity, label }: { severity: unknown; label?: string }) {
  const level = normalizeSeverity(severity)
  const Icon = ICON[level]
  return <span className={`severity-pill ${level}`}><Icon size={12} aria-hidden="true" />{label ?? level}</span>
}

export type Mitre = { tactic?: string; technique?: string; technique_id?: string; id?: string; name?: string; justification?: string } | string

/** MITRE ATT&CK tactic and technique, as the rule declares them. */
export function MitreBadge({ item }: { item: Mitre }) {
  const text = typeof item === 'string' ? item : [item.technique_id ?? item.id ?? item.technique, item.name ?? item.tactic].filter(Boolean).join(' · ')
  const why = typeof item === 'string' ? undefined : item.justification
  return <span className="mitre-badge" title={why ? `MITRE ATT&CK: ${why}` : 'MITRE ATT&CK'}>{text || 'ATT&CK'}</span>
}

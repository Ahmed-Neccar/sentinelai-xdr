export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational'

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'informational']

export function normalizeSeverity(value: unknown): Severity {
  const text = String(value ?? '').toLowerCase()
  return (SEVERITY_ORDER as string[]).includes(text) ? (text as Severity) : 'informational'
}

/** The one place a severity gets its colour; screens never pick their own. */
export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#F43F5E',
  high: '#F97316',
  medium: '#F59E0B',
  low: '#60A5FA',
  informational: '#A3ABCB',
}

/** Risk gauge colour from a 0 to 100 score. */
export function riskColor(score: number): string {
  if (score >= 80) return '#F43F5E'
  if (score >= 60) return '#F97316'
  if (score >= 40) return '#F59E0B'
  return '#10B981'
}

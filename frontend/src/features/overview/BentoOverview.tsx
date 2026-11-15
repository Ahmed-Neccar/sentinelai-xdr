import { useCallback, useEffect, useMemo, useState } from 'react'
import { Activity, BriefcaseBusiness, ChevronDown, Radar, Server, ShieldAlert } from 'lucide-react'
import CountUp from '../../components/viz/CountUp'
import Pulse from '../../components/viz/Pulse'
import RiskGauge from '../../components/viz/RiskGauge'
import Spotlight from '../../components/viz/Spotlight'
import { MitreBadge, SeverityPill } from '../../components/viz/badges'
import { SEVERITY_ORDER, normalizeSeverity } from '../../design/severity'
import { translate, type Language } from '../../i18n'
import { api } from '../../services/http'
import { LIFECYCLE_STEPS, lifecycleOf, responses, type ResponseAction } from '../../services/responses'
import { hashForDetection } from '../../app/router'
import SystemHealth from '../../SystemHealth'

type Row = Record<string, any>

const SEVERITY_WEIGHT = { critical: 40, high: 20, medium: 8, low: 2, informational: 0 }

/** A single 0 to 100 figure for the gauge: the latest findings weighted by severity. Not a probability. */
export function riskIndex(findings: Row[]): number {
  const total = findings.reduce((sum, finding) => sum + SEVERITY_WEIGHT[normalizeSeverity(finding.severity)], 0)
  return Math.min(100, total)
}

export default function BentoOverview({ language, setSection, setError }: { language: Language; setSection: (section: any) => void; setError: (message: string) => void }) {
  const t = (text: string) => translate(text, language)
  const locale = language === 'tr' ? 'tr-TR' : 'en-US'
  const [summary, setSummary] = useState<Row | null>(null)
  const [findings, setFindings] = useState<Row[]>([])
  const [sessions, setSessions] = useState<Row[]>([])
  const [actions, setActions] = useState<ResponseAction[]>([])
  const [loading, setLoading] = useState(true)
  const [open, setOpen] = useState<string | null>(null)

  const load = useCallback(async () => {
    const [s, d, ss, r] = await Promise.allSettled([
      api<Row>('/dashboard/summary'),
      api<{ items: Row[] }>('/detections?page_size=30'),
      api<Row[]>('/ingest/live/sessions?page_size=25'),
      responses.recent(),
    ])
    if (s.status === 'fulfilled') setSummary(s.value)
    else setError(s.reason instanceof Error ? s.reason.message : 'Unable to load overview')
    if (d.status === 'fulfilled') setFindings(d.value.items)
    // The sensor list and response list are role-limited: a missing one simply stays empty.
    if (ss.status === 'fulfilled') setSessions(ss.value)
    if (r.status === 'fulfilled') setActions(r.value.items)
    setLoading(false)
  }, [setError])
  useEffect(() => {
    void load()
    const timer = window.setInterval(() => void load(), 15000)
    return () => window.clearInterval(timer)
  }, [load])

  const grouped = useMemo(() => SEVERITY_ORDER.map(level => ({ level, items: findings.filter(f => normalizeSeverity(f.severity) === level) })).filter(group => group.items.length), [findings])
  const online = sessions.filter(row => row.state === 'online')
  const risk = riskIndex(findings)
  const when = (value?: string) => (value ? new Date(value).toLocaleString(locale) : '—')

  return (
    <div className="content bento-content">
      <div className="heading">
        <div>
          <div className="eyebrow">{t('DAILY SECURITY SUMMARY')}</div>
          <h1>{t('Your security, at a glance.')}</h1>
          <p>{online.length ? t('Your sensors are reporting. Here is what may need your attention.') : t('Review your workspace status and the latest security findings.')}</p>
        </div>
      </div>
      {loading && !summary ? <p className="muted-note">{t('Loading workspace data…')}</p> : (
        <div className="bento">
          <section className="bento-card bento-risk" aria-label={t('Threat pulse and risk')}>
            <div className="bento-title"><Radar size={16} /> {t('Threat pulse')}</div>
            <RiskGauge value={risk} size={170} label={t('Risk index')} />
            <p className="muted-note">{t('Weighted by the severity of the latest findings. It is a guide for attention, not a probability of attack.')}</p>
          </section>

          <div className="bento-metrics">
            {[
              { icon: Activity, label: 'Events ingested', value: summary?.event_count ?? 0, tone: 'info', note: 'All stored events' },
              { icon: ShieldAlert, label: 'Findings to review', value: summary?.detection_count ?? 0, tone: 'warn', note: 'Review the latest findings', go: 'Detections' },
              { icon: BriefcaseBusiness, label: 'Open cases', value: summary?.open_cases ?? 0, tone: 'accent', note: 'New or being investigated', go: 'Cases' },
              { icon: Server, label: 'Sensors reporting', value: online.length, tone: 'ok', note: `${sessions.length} ${t('registered sensor sessions')}`, go: 'Sensors' },
            ].map(metric => (
              <Spotlight key={metric.label} className={`bento-metric ${metric.tone}`}>
                <metric.icon size={18} aria-hidden="true" />
                <small>{t(metric.label)}</small>
                <strong><CountUp value={metric.value} locale={locale} /></strong>
                <span>{t(metric.note)}</span>
                {metric.go && <button type="button" className="bento-link" onClick={() => setSection(metric.go)} aria-label={`${t(metric.label)}: ${t('open')}`} />}
              </Spotlight>
            ))}
          </div>

          <section className="bento-card bento-findings" aria-label={t('Categorised findings')}>
            <div className="bento-title"><ShieldAlert size={16} /> {t('Categorised findings')} <button type="button" className="secondary" onClick={() => setSection('Detections')}>{t('View all')} →</button></div>
            {grouped.length === 0 && <p className="muted-note">{t('No detections yet. Import sample telemetry to get started.')}</p>}
            {grouped.map(group => (
              <div className="finding-group" key={group.level}>
                <h3><SeverityPill severity={group.level} label={t(group.level)} /> <span>{group.items.length}</span></h3>
                {group.items.slice(0, 4).map(finding => {
                  const expanded = open === finding.id
                  return (
                    <article className={`finding-row ${expanded ? 'open' : ''}`} key={finding.id}>
                      <button type="button" className="finding-head" aria-expanded={expanded} onClick={() => setOpen(expanded ? null : finding.id)}>
                        <ChevronDown size={16} aria-hidden="true" />
                        <b>{finding.title}</b>
                        <time>{when(finding.created_at)}</time>
                      </button>
                      {expanded && (
                        <div className="finding-body">
                          <p>{finding.summary || t('A security rule noticed an unusual activity.')}</p>
                          {finding.mitre?.length > 0 && <div className="mitre-row">{finding.mitre.map((item: any, position: number) => <MitreBadge key={position} item={item} />)}</div>}
                          <button type="button" className="primary" onClick={() => { window.location.hash = hashForDetection(finding.id) }}>{t('Investigate in detail')}</button>
                        </div>
                      )}
                    </article>
                  )
                })}
              </div>
            ))}
          </section>

          <section className="bento-card bento-sensors" aria-label={t('Live sensor health')}>
            <div className="bento-title"><Server size={16} /> {t('Live sensor health')}</div>
            {sessions.length === 0 && <p className="muted-note">{t('No sensor is currently reporting')}</p>}
            <ul className="sensor-health">
              {sessions.slice(0, 6).map(row => {
                const isOnline = row.state === 'online'
                return (
                  <li key={row.id}>
                    <Pulse online={isOnline} label={isOnline ? t('online') : t('offline')} />
                    <div><b>{row.host_name || row.source_name}</b><small>{isOnline ? t('online') : t('offline')} · {when(row.last_heartbeat_at)}</small></div>
                  </li>
                )
              })}
            </ul>
          </section>

          <section className="bento-card bento-actions" aria-label={t('Recent response actions')}>
            <div className="bento-title"><ShieldAlert size={16} /> {t('Recent response actions')} <button type="button" className="secondary" onClick={() => setSection('Cases')}>{t('Cases')} →</button></div>
            {actions.length === 0 && <p className="muted-note">{t('No response actions yet.')}</p>}
            <ul className="action-list">
              {actions.slice(0, 5).map(item => {
                const state = lifecycleOf(item)
                const step = state.failedAt !== undefined ? t('Failed') : t(({ proposed: 'Proposed', approved: 'Approved', dispatched: 'Dispatched', executed: 'Executed' })[LIFECYCLE_STEPS[Math.min(state.index, 3)]])
                return (
                  <li key={item.id}>
                    <span className={`action-state ${state.failedAt !== undefined ? 'bad' : state.index >= 3 ? 'good' : ''}`}>{step}</span>
                    <div><b>{t(item.action_type === 'block_source_ip' ? 'IP block' : item.action_type === 'isolate_host' ? 'Host isolation' : 'Account disable')}</b><small><code>{item.target}</code> · {when(item.created_at)}</small></div>
                  </li>
                )
              })}
            </ul>
          </section>
          <div className="bento-health"><SystemHealth language={language} apiRequest={api} /></div>
        </div>
      )}
    </div>
  )
}

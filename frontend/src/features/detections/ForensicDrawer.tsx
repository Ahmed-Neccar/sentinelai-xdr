import { useEffect, useRef, useState } from 'react'
import { Activity, Copy, Fingerprint, Globe, KeyRound, Terminal } from 'lucide-react'
import Drawer from '../../components/ui/Drawer'
import Tabs from '../../components/ui/Tabs'
import { useScopedLenis } from '../../components/ui/useScopedLenis'
import RiskGauge from '../../components/viz/RiskGauge'
import { MitreBadge, SeverityPill } from '../../components/viz/badges'
import { normalizeSeverity } from '../../design/severity'
import { translate, type Language } from '../../i18n'
import { detections, type DetectionDetail, type EvidenceEvent } from '../../services/detections'

const baseName = (path: unknown) => (typeof path === 'string' ? path.split(/[\\/]/).pop() || path : '')

/** The risk gauge wants 0 to 100; detectors report either a 0 to 1 probability or a 0 to 100 score. */
export const riskPercent = (score: unknown, severity?: unknown): number => {
  const value = score === null || score === undefined ? NaN : Number(score)
  if (Number.isFinite(value) && value >= 0) return value <= 1 ? value * 100 : Math.min(100, value)
  // Rule detections carry no numeric score: the gauge then shows where the severity sits on the scale.
  return ({ critical: 90, high: 70, medium: 45, low: 20, informational: 5 } as Record<string, number>)[normalizeSeverity(severity)]
}

const EVENT_ICON = (type: string) => (type.startsWith('auth.') ? KeyRound : type === 'process.start' ? Terminal : type.startsWith('net.') ? Globe : Activity)

/** Slide-over investigation of one finding: summary and risk, timeline, process and network, raw record. */
export default function ForensicDrawer({ finding, language, close }: { finding: { id: string; title?: string }; language: Language; close: () => void }) {
  const t = (text: string) => translate(text, language)
  const locale = language === 'tr' ? 'tr-TR' : 'en-US'
  const [detail, setDetail] = useState<DetectionDetail | null>(null)
  const [error, setError] = useState('')
  const [tab, setTab] = useState('summary')
  const [copied, setCopied] = useState(false)
  const reading = useRef<HTMLDivElement>(null)
  const readingInner = useRef<HTMLDivElement>(null)
  useScopedLenis(reading, readingInner)

  useEffect(() => {
    let alive = true
    detections.get(finding.id).then(value => { if (alive) setDetail(value) }).catch(e => { if (alive) setError(e instanceof Error ? e.message : t('Unable to load this finding')) })
    return () => { alive = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [finding.id])

  const when = (value?: string) => (value ? new Date(value).toLocaleString(locale) : '—')
  const events: EvidenceEvent[] = [...(detail?.evidence_events ?? [])].sort((a, b) => a.event_time.localeCompare(b.event_time))
  const network = events.filter(event => event.src_ip || event.dst_ip)
  const processes = events.filter(event => event.event_type === 'process.start' || event.attributes?.process_name)
  const accounts = events.filter(event => event.event_type.startsWith('auth.'))
  const label = (type: string) => t(({ 'net.conn': 'Network connection', 'auth.success': 'Successful sign-in', 'auth.failure': 'Failed sign-in', 'process.start': 'Program started' } as Record<string, string>)[type] ?? type)

  const summary = (
    <div className="reading" ref={reading}>
      <div ref={readingInner}>
        <div className="forensic-top">
          <RiskGauge value={riskPercent(detail?.score, detail?.severity)} label={t('Risk')} />
          <div className="forensic-facts">
            <SeverityPill severity={detail?.severity} label={t(String(detail?.severity ?? ''))} />
            <p className="forensic-summary">{detail?.summary || t('A security rule noticed an unusual activity.')}</p>
            <dl>
              <dt>{t('Detected')}</dt><dd>{when(detail?.created_at)}</dd>
              <dt>{t('Detector')}</dt><dd>{detail?.rule_id ? `${detail.rule_id}${detail.rule_version ? ` v${detail.rule_version}` : ''}` : detail?.model_version || detail?.detector_kind || '—'}</dd>
              <dt>{t('Status')}</dt><dd>{detail?.status ?? '—'}</dd>
            </dl>
          </div>
        </div>
        <h3 className="forensic-h">{t('ATT&CK mapping')}</h3>
        {detail?.mitre?.length
          ? <div className="mitre-row">{detail.mitre.map((item, position) => <MitreBadge key={position} item={item} />)}</div>
          : <p className="muted-note">{t('This rule does not declare an ATT&CK technique.')}</p>}
        {detail?.attribution_note && <p className="muted-note">{detail.attribution_note}</p>}
        <h3 className="forensic-h">{t('Evidence the rule used')}</h3>
        {detail?.evidence && Object.keys(detail.evidence).length
          ? <dl className="evidence-list">{Object.entries(detail.evidence).filter(([key]) => !/(^|_)ids?$/.test(key)).map(([key, value]) => <div key={key}><dt>{key.replace(/_/g, ' ')}</dt><dd><code>{typeof value === 'object' ? JSON.stringify(value) : String(value)}</code></dd></div>)}</dl>
          : <p className="muted-note">{t('No extra evidence was recorded.')}</p>}
      </div>
    </div>
  )

  const timeline = events.length
    ? <ol className="timeline">{events.map(event => {
      const Icon = EVENT_ICON(event.event_type)
      return (
        <li key={event.id}>
          <span className="timeline-dot"><Icon size={13} /></span>
          <div>
            <time>{when(event.event_time)}</time>
            <b>{label(event.event_type)}</b>
            <small><code>{[event.src_ip && `${event.src_ip}${event.src_port ? ':' + event.src_port : ''}`, event.dst_ip && `${event.dst_ip}${event.dst_port ? ':' + event.dst_port : ''}`].filter(Boolean).join(' → ') || event.host_id || '—'}</code></small>
          </div>
        </li>
      )
    })}</ol>
    : <p className="muted-note">{t('No events are linked to this finding.')}</p>

  const flows = (
    <div className="flows">
      <h3 className="forensic-h"><Globe size={14} /> {t('Network')}</h3>
      {network.length
        ? <div className="table-wrap"><table><thead><tr><th>{t('TIME')}</th><th>{t('SOURCE')}</th><th>{t('DESTINATION')}</th></tr></thead><tbody>{network.map(event => <tr key={event.id}><td>{when(event.event_time)}</td><td><code>{event.src_ip ?? '—'}{event.src_port ? `:${event.src_port}` : ''}</code></td><td><code>{event.dst_ip ?? '—'}{event.dst_port ? `:${event.dst_port}` : ''}</code></td></tr>)}</tbody></table></div>
        : <p className="muted-note">{t('No network details in the linked events.')}</p>}
      <h3 className="forensic-h"><Terminal size={14} /> {t('Programs')}</h3>
      {processes.length
        ? <div className="table-wrap"><table><thead><tr><th>{t('TIME')}</th><th>{t('PROGRAM')}</th><th>{t('STARTED BY')}</th></tr></thead><tbody>{processes.map(event => <tr key={event.id}><td>{when(event.event_time)}</td><td><code>{baseName(event.attributes?.process_name) || '—'}</code></td><td><code>{baseName(event.attributes?.parent_process_name) || '—'}</code></td></tr>)}</tbody></table></div>
        : <p className="muted-note">{t('No program details in the linked events.')}</p>}
      {accounts.length > 0 && <>
        <h3 className="forensic-h"><Fingerprint size={14} /> {t('Accounts')}</h3>
        <div className="table-wrap"><table><thead><tr><th>{t('TIME')}</th><th>{t('Account')}</th><th>{t('Result')}</th></tr></thead><tbody>{accounts.map(event => <tr key={event.id}><td>{when(event.event_time)}</td><td><code>{event.attributes?.username ?? '—'}</code></td><td>{t(String(event.attributes?.outcome ?? label(event.event_type)))}</td></tr>)}</tbody></table></div>
      </>}
    </div>
  )

  const raw = (
    <div className="raw">
      <button type="button" className="secondary" onClick={() => { void navigator.clipboard?.writeText(JSON.stringify(detail, null, 2)); setCopied(true) }}><Copy size={14} /> {copied ? t('Copied') : t('Copy JSON')}</button>
      <pre>{JSON.stringify(detail, null, 2)}</pre>
    </div>
  )

  return (
    <Drawer title={detail?.title ?? finding.title ?? t('Finding')} eyebrow={t('FORENSIC REVIEW')} closeLabel={t('Close')} onClose={close} width={720}>
      {error ? <p className="field-error" role="alert">{error}</p> : !detail ? <p className="muted-note">{t('Loading…')}</p> : (
        <Tabs
          label={t('Finding sections')}
          active={tab}
          onChange={setTab}
          items={[
            { id: 'summary', label: t('Summary & risk'), content: summary },
            { id: 'timeline', label: t('Forensic timeline'), content: timeline },
            { id: 'flows', label: t('Process & network'), content: flows },
            { id: 'raw', label: t('Raw JSON'), content: raw },
          ]}
        />
      )}
    </Drawer>
  )
}

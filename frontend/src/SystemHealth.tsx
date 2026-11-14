import { useCallback, useEffect, useState } from 'react'
import { translate, type Language } from './i18n'

type Health = {
  sensors: { online: number; silent: { name: string; last_heartbeat_at: string }[] }
  connectors: {
    name: string
    provider: string
    status: string
    healthy: boolean
    enabled: boolean
    last_success_at: string | null
    last_error: string | null
  }[]
  notifications: { enabled_channels: number; pending: number; failed_24h: number }
}

export default function SystemHealth({
  language,
  apiRequest,
}: {
  language: Language
  apiRequest: (path: string, init?: RequestInit) => Promise<any>
}) {
  const t = (value: string) => translate(value, language)
  const [data, setData] = useState<Health | null>(null)

  const load = useCallback(async () => {
    try {
      setData(await apiRequest('/system/health'))
    } catch {
      setData(null)
    }
  }, [apiRequest])

  useEffect(() => {
    void load()
    const timer = window.setInterval(() => void load(), 30000)
    return () => window.clearInterval(timer)
  }, [load])

  if (!data) return null
  const problems =
    data.sensors.silent.length +
    data.connectors.filter((c) => c.enabled && !c.healthy).length +
    (data.notifications.failed_24h > 0 ? 1 : 0)
  return (
    <section className="panel overview-health">
      <div className="panel-head">
        <div>
          <h2>{t('System health')}</h2>
          <p>{problems ? `${problems} ${t('problems need attention')}` : t('Everything reports normally.')}</p>
        </div>
      </div>
      <div className="overview-list">
        <article className="overview-row">
          <span className={`overview-mark ${data.sensors.silent.length ? 'high' : 'low'}`} />
          <div className="overview-row-copy">
            <b>{t('Sensors')}</b>
            <small>
              {data.sensors.online} {t('sensors reporting')}
              {data.sensors.silent.map((s) => ` · ${s.name}: ${t('no heartbeat')}`).join('')}
            </small>
          </div>
        </article>
        {data.connectors.map((c) => (
          <article className="overview-row" key={c.name}>
            <span className={`overview-mark ${c.enabled && !c.healthy ? 'high' : 'low'}`} />
            <div className="overview-row-copy">
              <b>{c.name}</b>
              <small>
                {c.enabled ? (c.healthy ? t('Polling normally') : t('Failing')) : t('Paused')}
                {c.last_error ? ` · ${c.last_error}` : ''}
              </small>
            </div>
          </article>
        ))}
        <article className="overview-row">
          <span className={`overview-mark ${data.notifications.failed_24h ? 'high' : 'low'}`} />
          <div className="overview-row-copy">
            <b>{t('Notifications')}</b>
            <small>
              {data.notifications.enabled_channels} {t('channels enabled')} · {data.notifications.pending}{' '}
              {t('waiting')} · {data.notifications.failed_24h} {t('failed in 24 hours')}
            </small>
          </div>
        </article>
      </div>
    </section>
  )
}

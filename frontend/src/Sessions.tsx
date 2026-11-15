import { useCallback, useEffect, useState } from 'react'
import { MonitorSmartphone } from 'lucide-react'
import { translate, type Language } from './i18n'

type Session = { id: string; ip_address: string | null; user_agent: string | null; last_active: string; expires_at: string; current: boolean }

/** A readable name for a browser, from its user-agent text. */
export function deviceName(agent: string | null): string {
  if (!agent) return 'Unknown device'
  const browser = /Edg\//.test(agent) ? 'Edge' : /OPR\//.test(agent) ? 'Opera' : /Firefox\//.test(agent) ? 'Firefox' : /Chrome\//.test(agent) ? 'Chrome' : /Safari\//.test(agent) ? 'Safari' : ''
  const system = /Windows/.test(agent) ? 'Windows' : /Android/.test(agent) ? 'Android' : /iPhone|iPad/.test(agent) ? 'iOS' : /Mac OS X/.test(agent) ? 'macOS' : /Linux/.test(agent) ? 'Linux' : ''
  return [browser, system].filter(Boolean).join(' · ') || 'Unknown device'
}

/** The signed-in person's own sessions, with a way to end the ones they do not recognise. */
export default function Sessions({
  language,
  setError,
  apiRequest,
}: {
  language: Language
  setError: (message: string) => void
  apiRequest: (path: string, init?: RequestInit) => Promise<any>
}) {
  const t = (value: string) => translate(value, language)
  const [items, setItems] = useState<Session[] | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    try {
      setItems((await apiRequest('/auth/sessions')).items)
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to load sessions')
    }
  }, [apiRequest, setError])
  useEffect(() => { void load() }, [load])

  async function run(action: () => Promise<unknown>) {
    setBusy(true)
    try {
      await action()
      await load()
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to end the session')
    } finally {
      setBusy(false)
    }
  }

  const when = (value: string) => new Date(value).toLocaleString(language === 'tr' ? 'tr-TR' : 'en-US')
  if (!items) return null
  const others = items.filter(item => !item.current)

  return (
    <section className="panel preferences" aria-labelledby="sessions-title">
      <div className="panel-head">
        <div>
          <h2 id="sessions-title"><MonitorSmartphone size={16} /> {t('Where you are signed in')}</h2>
          <p>{t('End any session you do not recognise. It stops working immediately.')}</p>
        </div>
      </div>
      <div className="table-wrap">
        <table>
          <thead><tr><th>{t('DEVICE')}</th><th>{t('ADDRESS')}</th><th>{t('LAST ACTIVE')}</th><th>{t('ACTIONS')}</th></tr></thead>
          <tbody>
            {items.map(item => (
              <tr key={item.id}>
                <td><b>{t(deviceName(item.user_agent))}</b>{item.current && <small>{t('This device')}</small>}</td>
                <td>{item.ip_address ?? '—'}</td>
                <td>{when(item.last_active)}</td>
                <td>{item.current ? <small>—</small> : <button className="secondary" disabled={busy} onClick={() => void run(() => apiRequest(`/auth/sessions/${item.id}`, { method: 'DELETE' }))}>{t('End session')}</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {others.length > 0 && (
        <div className="session-actions">
          <button className="secondary" disabled={busy} onClick={() => void run(() => apiRequest('/auth/sessions/end-others', { method: 'POST' }))}>{t('Sign out all other devices')}</button>
        </div>
      )}
    </section>
  )
}

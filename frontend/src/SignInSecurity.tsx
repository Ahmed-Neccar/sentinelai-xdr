import { useCallback, useEffect, useState } from 'react'
import { RefreshCw, ShieldAlert } from 'lucide-react'
import { translate, type Language } from './i18n'

type Summary = {
  hours: number
  total: number
  by_action: Record<string, number>
  top_sources: { ip_address: string | null; account: string | null; attempts: number; last_attempt: string }[]
}

const LABEL: Record<string, string> = {
  'auth.login_failed': 'Wrong password or unknown account',
  'auth.sso_failed': 'Single sign-on failed',
  'auth.sso_identity_mismatch': 'Single sign-on identity mismatch',
}

export default function SignInSecurity({
  language,
  setError,
  apiRequest,
}: {
  language: Language
  setError: (message: string) => void
  apiRequest: (path: string, init?: RequestInit) => Promise<any>
}) {
  const t = (value: string) => translate(value, language)
  const [data, setData] = useState<Summary | null>(null)

  const load = useCallback(async () => {
    try {
      setData(await apiRequest('/audit-logs/sign-in-security?hours=24'))
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to load sign-in security')
    }
  }, [apiRequest, setError])

  useEffect(() => {
    void load()
  }, [load])

  if (!data) return null
  return (
    <section className="panel data-panel">
      <div className="panel-head">
        <div>
          <h2><ShieldAlert size={16} /> {t('Failed sign-ins, last 24 hours')}</h2>
          <p>{data.total ? `${data.total} ${t('failed attempts')}` : t('No failed sign-ins in the last 24 hours.')}</p>
        </div>
        <button className="icon-button" aria-label={t('Refresh')} onClick={() => void load()}><RefreshCw size={15} /></button>
      </div>
      {data.total > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>{t('TYPE')}</th><th>{t('ATTEMPTS')}</th></tr>
            </thead>
            <tbody>
              {Object.entries(data.by_action).map(([action, count]) => (
                <tr key={action}><td>{t(LABEL[action] ?? action)}</td><td>{count}</td></tr>
              ))}
            </tbody>
          </table>
          <table>
            <thead>
              <tr><th>{t('ACCOUNT')}</th><th>{t('ADDRESS')}</th><th>{t('ATTEMPTS')}</th><th>{t('LAST ATTEMPT')}</th></tr>
            </thead>
            <tbody>
              {data.top_sources.map((row, index) => (
                <tr key={index}>
                  <td>{row.account ?? '-'}</td>
                  <td>{row.ip_address ?? '-'}</td>
                  <td>{row.attempts}</td>
                  <td>{new Date(row.last_attempt).toLocaleString(language === 'tr' ? 'tr-TR' : 'en-US')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

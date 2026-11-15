import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { Send } from 'lucide-react'
import { translate, type Language } from '../../i18n'
import { auditSinks, type AuditSink } from '../../services/auditSinks'

/** Copies of the audit log sent to an outside collector, so removing the newest rows cannot go unseen. */
export default function AuditSinks({ language, setError }: { language: Language; setError: (message: string) => void }) {
  const t = (text: string) => translate(text, language)
  const locale = language === 'tr' ? 'tr-TR' : 'en-US'
  const [items, setItems] = useState<AuditSink[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [secret, setSecret] = useState('')
  const [replay, setReplay] = useState(false)
  const [testResult, setTestResult] = useState<Record<string, string>>({})

  const load = useCallback(async () => {
    try {
      setItems(await auditSinks.list())
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to load destinations')
    }
  }, [setError])
  useEffect(() => {
    void load()
    const timer = window.setInterval(() => void load(), 30000)
    return () => window.clearInterval(timer)
  }, [load])

  async function run(action: () => Promise<unknown>) {
    setBusy(true)
    try {
      await action()
      await load()
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to complete this request')
    } finally {
      setBusy(false)
    }
  }

  function add(event: FormEvent) {
    event.preventDefault()
    void run(async () => {
      await auditSinks.create({ name: name.trim(), url: url.trim(), signing_secret: secret || undefined, from_beginning: replay })
      setName(''); setUrl(''); setSecret(''); setReplay(false)
    })
  }

  async function test(item: AuditSink) {
    setBusy(true)
    try {
      const result = await auditSinks.test(item.id)
      setTestResult(current => ({ ...current, [item.id]: result.ok ? t('The destination accepted the test message.') : `${t('The destination refused it')}: ${result.error ?? ''}` }))
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to test the destination')
    } finally {
      setBusy(false)
    }
  }

  if (!items) return null
  return (
    <section className="panel data-panel" aria-labelledby="sinks-title">
      <div className="panel-head">
        <div>
          <h2 id="sinks-title"><Send size={16} /> {t('Send the audit log elsewhere')}</h2>
          <p>{t('Each new audit record is also sent to your own collector (a SIEM or log archive) over HTTPS, signed if you give a secret. Keeping a copy outside this server is what lets you notice if the newest records are ever removed.')}</p>
        </div>
      </div>
      {items.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>{t('NAME')}</th><th>{t('STATUS')}</th><th>{t('LAST SENT')}</th><th>{t('ACTIONS')}</th></tr></thead>
            <tbody>
              {items.map(item => (
                <tr key={item.id}>
                  <td><b>{item.name}</b></td>
                  <td>
                    <span className={`status ${!item.enabled ? 'disabled' : item.last_error ? 'failed' : 'completed'}`}>{!item.enabled ? t('Off') : item.last_error ? t('Failing') : t('Sending')}</span>
                    {item.behind > 0 && <small>{item.behind} {t('records waiting')}</small>}
                    {item.last_error && <small>{item.last_error}</small>}
                    {testResult[item.id] && <small>{testResult[item.id]}</small>}
                  </td>
                  <td>{item.last_success_at ? new Date(item.last_success_at).toLocaleString(locale) : '—'}</td>
                  <td>
                    <div className="sensor-registry-actions">
                      <button className="secondary" disabled={busy} onClick={() => void test(item)}>{t('Send a test')}</button>
                      <button className="secondary" disabled={busy} onClick={() => void run(() => auditSinks.setEnabled(item.id, !item.enabled))}>{item.enabled ? t('Turn off') : t('Turn on')}</button>
                      <button className="sensor-stop" disabled={busy} onClick={() => { if (window.confirm(t('Remove this destination? Records already sent stay there.'))) void run(() => auditSinks.remove(item.id)) }}>{t('Remove')}</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <form className="identity-add" onSubmit={add}>
        <label>{t('Name')}<input value={name} maxLength={200} onChange={event => setName(event.target.value)} placeholder="Splunk" /></label>
        <label>{t('HTTPS address of the collector')}<input value={url} maxLength={2048} onChange={event => setUrl(event.target.value)} placeholder="https://siem.example.com/hooks/sentinel" /></label>
        <label>{t('Signing secret (optional, 16+ characters)')}<input type="password" autoComplete="new-password" value={secret} maxLength={256} onChange={event => setSecret(event.target.value)} /></label>
        <label className="check-inline"><input type="checkbox" checked={replay} onChange={event => setReplay(event.target.checked)} /> {t('Also send the existing log from the beginning')}</label>
        <button className="primary" disabled={busy || !name.trim() || !url.trim() || (!!secret && secret.length < 16)}>{t('Add destination')}</button>
      </form>
    </section>
  )
}

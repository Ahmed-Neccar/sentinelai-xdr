import { useCallback, useEffect, useState } from 'react'
import { Bell, RefreshCw } from 'lucide-react'
import { translate, type Language } from './i18n'

type Row = Record<string, any>
type User = { roles: string[] }

const KIND_LABEL: Record<string, string> = {
  webhook: 'Generic webhook',
  slack: 'Slack-compatible webhook',
  telegram: 'Telegram bot',
}

export default function Notifications({
  user,
  language,
  setError,
  apiRequest,
}: {
  user: User
  language: Language
  setError: (message: string) => void
  apiRequest: (path: string, init?: RequestInit) => Promise<any>
}) {
  const t = (value: string) => translate(value, language)
  const [items, setItems] = useState<Row[]>([])
  const [kind, setKind] = useState('slack')
  const [name, setName] = useState('')
  const [target, setTarget] = useState<Record<string, string>>({})
  const [minSeverity, setMinSeverity] = useState('high')
  const [includeSummary, setIncludeSummary] = useState(false)
  const [busy, setBusy] = useState(false)
  // Result of the last "Send test" per channel, read from the channel's own delivery status.
  const [pendingTests, setPendingTests] = useState<Record<string, { since: number; success: string | null; error: string | null }>>({})
  const [testResults, setTestResults] = useState<Record<string, string>>({})
  const canManage = user.roles.includes('administrator')

  const load = useCallback(async () => {
    try {
      setItems(await apiRequest('/notification-channels'))
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to load notification channels')
    }
  }, [apiRequest, setError])

  useEffect(() => {
    void load()
    const timer = window.setInterval(() => void load(), 15000)
    return () => window.clearInterval(timer)
  }, [load])

  const targetFields = kind === 'telegram'
    ? [['bot_token', 'Bot token', true], ['chat_id', 'Chat ID', true]]
    : kind === 'webhook'
      ? [['url', 'Webhook URL (https)', true], ['signing_secret', 'Signing secret (optional)', false]]
      : [['url', 'Webhook URL (https)', true]]

  async function run(action: () => Promise<unknown>, fallback: string) {
    setBusy(true)
    try {
      await action()
      await load()
    } catch (error) {
      setError(error instanceof Error ? error.message : fallback)
    } finally {
      setBusy(false)
    }
  }

  function create(event: React.FormEvent) {
    event.preventDefault()
    void run(async () => {
      await apiRequest('/notification-channels', {
        method: 'POST',
        body: JSON.stringify({
          name,
          kind,
          target: Object.fromEntries(Object.entries(target).filter(([, value]) => value)),
          min_severity: minSeverity,
          include_summary: includeSummary,
        }),
      })
      setName('')
      setTarget({})
    }, 'Unable to save notification channel')
  }

  const patch = (item: Row, body: Row) => run(
    () => apiRequest(`/notification-channels/${item.id}`, { method: 'PATCH', body: JSON.stringify(body) }),
    'Unable to update notification channel',
  )
  const test = (item: Row) => run(
    async () => {
      await apiRequest(`/notification-channels/${item.id}/test`, { method: 'POST' })
      setTestResults(current => { const next = { ...current }; delete next[item.id]; return next })
      setPendingTests(current => ({ ...current, [item.id]: { since: Date.now(), success: item.last_success_at ?? null, error: item.last_error ?? null } }))
    },
    'Unable to queue test notification',
  )

  // While a test is waiting, look again every 4 seconds; give up after 2 minutes.
  useEffect(() => {
    const ids = Object.keys(pendingTests)
    if (!ids.length) return
    const timer = window.setInterval(() => void load(), 4000)
    return () => window.clearInterval(timer)
  }, [pendingTests, load])
  useEffect(() => {
    for (const [id, waiting] of Object.entries(pendingTests)) {
      const item = items.find(row => row.id === id)
      if (!item) continue
      let result = ''
      if ((item.last_success_at ?? null) !== waiting.success) result = 'Test message delivered.'
      else if (item.last_error && item.last_error !== waiting.error) result = 'Test message failed: ' + item.last_error
      else if (Date.now() - waiting.since > 120000) result = 'No result after 2 minutes. Check that the worker is running.'
      if (result) {
        setTestResults(current => ({ ...current, [id]: result }))
        setPendingTests(current => { const next = { ...current }; delete next[id]; return next })
      }
    }
  }, [items, pendingTests])
  function remove(item: Row) {
    if (!window.confirm(t('Delete this channel? Its stored destination and delivery history will be erased.'))) return
    void run(
      () => apiRequest(`/notification-channels/${item.id}`, { method: 'DELETE' }),
      'Unable to delete notification channel',
    )
  }

  const date = (value?: string) => value
    ? new Date(value).toLocaleString(language === 'tr' ? 'tr-TR' : 'en-US')
    : '—'
  const state = (item: Row) => !item.enabled
    ? ['disabled', 'Paused']
    : item.last_error
      ? ['processing', 'Delivery problem']
      : item.last_success_at
        ? ['completed', 'Delivering']
        : ['disabled', 'Not tested yet']

  return (
    <div className="content">
      <div className="heading">
        <div className="eyebrow">{t('ALERT DELIVERY')}</div>
        <h1>{t('Notifications')}</h1>
        <p>{t('Send a short message to your team when a new finding reaches the severity you choose.')}</p>
      </div>

      <section className="panel guide">
        <div className="panel-head">
          <div>
            <h2>{t('What is sent')}</h2>
            <p>{t('Each message contains the finding title, severity, rule, and the finding and case IDs. Findings are review signals, not confirmation of compromise.')}</p>
          </div>
          <Bell size={18} />
        </div>
        <p>{t('The finding summary can contain addresses, host names, and account names. It is left out unless you turn it on for a channel, because the message leaves this installation.')}</p>
        <small>{t('Destinations must be public https addresses. They are encrypted here and never shown again. New findings are sent within about 30 seconds; a failed send is retried up to five times.')}</small>
      </section>

      {canManage && <form className="panel preferences" onSubmit={create}>
        <div className="panel-head"><div><h2>{t('Add notification channel')}</h2><p>{t('Create the incoming webhook or bot in your chat tool first, then paste its address here.')}</p></div></div>
        <div className="preference-grid">
          <label>{t('Channel name')}<input required maxLength={200} value={name} onChange={event => setName(event.target.value)} /></label>
          <label>{t('Channel type')}<select value={kind} onChange={event => { setKind(event.target.value); setTarget({}) }}>
            {Object.entries(KIND_LABEL).map(([value, label]) => <option key={value} value={value}>{t(label)}</option>)}
          </select></label>
          {targetFields.map(([key, label, required]) => <label key={key as string}>{t(label as string)}<input type="password" autoComplete="new-password" required={required as boolean} value={target[key as string] || ''} onChange={event => setTarget(current => ({ ...current, [key as string]: event.target.value }))} /></label>)}
          <label>{t('Notify from severity')}<select value={minSeverity} onChange={event => setMinSeverity(event.target.value)}>
            {['low', 'medium', 'high', 'critical'].map(value => <option key={value} value={value}>{t(value)}</option>)}
          </select></label>
          <label><span><input type="checkbox" checked={includeSummary} onChange={event => setIncludeSummary(event.target.checked)} /> {t('Include the finding summary in messages')}</span></label>
        </div>
        <button className="primary" disabled={busy || !name.trim()}>{busy ? t('Saving…') : t('Save channel')}</button>
      </form>}

      <section className="panel data-panel">
        <div className="panel-head"><div><h2>{t('Configured channels')}</h2><p>{t('Status reflects the most recent delivery attempt.')}</p></div><button className="icon-button" aria-label={t('Refresh')} onClick={() => void load()}><RefreshCw size={16} /></button></div>
        {items.length ? <div className="table-wrap"><table><thead><tr><th>{t('CHANNEL')}</th><th>{t('STATUS')}</th><th>{t('NOTIFIES FROM')}</th><th>{t('LAST SUCCESS')}</th><th>{t('DELIVERIES')}</th>{canManage && <th>{t('ACTIONS')}</th>}</tr></thead><tbody>
          {items.map(item => { const [cls, label] = state(item); return <tr key={item.id}>
            <td><b>{item.name}</b><small>{t(KIND_LABEL[item.kind] || item.kind)}</small><small>{t(item.include_summary ? 'Summary included' : 'Summary left out')}</small></td>
            <td><span className={`status ${cls}`}>{t(label)}</span>{item.last_error && <small>{t(item.last_error)}</small>}{pendingTests[item.id] && <small>{t('Test message queued; waiting for the result…')}</small>}{testResults[item.id] && <small><b>{testResults[item.id].startsWith('Test message failed: ') ? t('Test message failed: ') + testResults[item.id].slice(21) : t(testResults[item.id])}</b></small>}</td>
            <td>{canManage ? <select value={item.min_severity} disabled={busy} aria-label={t('Notify from severity')} onChange={event => void patch(item, { min_severity: event.target.value })}>
              {['low', 'medium', 'high', 'critical'].map(value => <option key={value} value={value}>{t(value)}</option>)}
            </select> : t(item.min_severity)}</td>
            <td>{date(item.last_success_at)}</td>
            <td>{item.sent} {t('sent')} · {item.pending} {t('waiting')} · {item.failed} {t('failed')}</td>
            {canManage && <td><div className="sensor-registry-actions"><button className="secondary" disabled={busy || !item.enabled} onClick={() => void test(item)}>{t('Send test')}</button><button className="secondary" disabled={busy} onClick={() => void patch(item, { enabled: !item.enabled })}>{item.enabled ? t('Pause') : t('Enable')}</button><button className="secondary" disabled={busy} onClick={() => remove(item)}>{t('Delete')}</button></div></td>}
          </tr> })}
        </tbody></table></div> : <p>{t('No notification channels configured yet.')}</p>}
      </section>
    </div>
  )
}

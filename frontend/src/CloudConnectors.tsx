import { useCallback, useEffect, useState } from 'react'
import { Cloud, RefreshCw } from 'lucide-react'
import { translate, type Language } from './i18n'

type Row = Record<string, any>
type User = { roles: string[] }

export default function CloudConnectors({
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
  const [provider, setProvider] = useState('aws_cloudtrail')
  const [editingId, setEditingId] = useState('')
  const [name, setName] = useState('')
  const [config, setConfig] = useState<Record<string, string>>({ region: 'us-east-1' })
  const [credentials, setCredentials] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState(false)
  const canManage = user.roles.includes('administrator')

  const load = useCallback(async () => {
    try {
      setItems(await apiRequest('/cloud-connectors'))
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to load cloud connectors')
    }
  }, [apiRequest, setError])

  useEffect(() => {
    void load()
    const timer = window.setInterval(() => void load(), 15000)
    return () => window.clearInterval(timer)
  }, [load])

  const configFields = provider === 'aws_cloudtrail'
    ? [['region', 'AWS region']]
    : provider === 'azure_activity'
      ? [['tenant_id', 'Microsoft tenant ID'], ['client_id', 'Application ID'], ['subscription_id', 'Azure subscription ID']]
      : [['tenant_id', 'Microsoft tenant ID'], ['client_id', 'Application ID']]
  const secretFields = provider === 'aws_cloudtrail'
    ? [['access_key_id', 'Access key ID'], ['secret_access_key', 'Secret access key'], ['session_token', 'Session token (optional)']]
    : [['client_secret', 'Application secret']]

  function changeProvider(value: string) {
    setProvider(value)
    setConfig(value === 'aws_cloudtrail' ? { region: 'us-east-1' } : {})
    setCredentials({})
  }

  function edit(item: Row) {
    setEditingId(item.id)
    setName(item.name)
    setProvider(item.provider)
    setConfig(item.config || {})
    setCredentials({})
  }

  async function create(event: React.FormEvent) {
    event.preventDefault()
    setBusy(true)
    try {
      await apiRequest(editingId ? `/cloud-connectors/${editingId}` : '/cloud-connectors', {
        method: editingId ? 'PUT' : 'POST',
        body: JSON.stringify({
          name,
          provider,
          config,
          credentials: Object.fromEntries(Object.entries(credentials).filter(([, value]) => value)),
        }),
      })
      setName('')
      setEditingId('')
      setCredentials({})
      await load()
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to save cloud connector')
    } finally {
      setBusy(false)
    }
  }

  async function poll(id: string) {
    setBusy(true)
    try {
      await apiRequest(`/cloud-connectors/${id}/poll`, { method: 'POST' })
      await load()
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to start cloud poll')
    } finally {
      setBusy(false)
    }
  }

  async function toggle(item: Row) {
    setBusy(true)
    try {
      await apiRequest(`/cloud-connectors/${item.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ enabled: !item.enabled }),
      })
      await load()
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to update cloud connector')
    } finally {
      setBusy(false)
    }
  }

  async function revoke(item: Row) {
    if (!window.confirm(t('Revoke this connector? Stored provider credentials will be erased and polling will stop.'))) return
    setBusy(true)
    try {
      await apiRequest(`/cloud-connectors/${item.id}`, { method: 'DELETE' })
      await load()
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to revoke cloud connector')
    } finally {
      setBusy(false)
    }
  }

  const statusClass = (status: string) =>
    status === 'healthy' ? 'completed' : ['partial', 'queued', 'polling'].includes(status) ? 'processing' : 'disabled'
  const date = (value?: string) => value
    ? new Date(value).toLocaleString(language === 'tr' ? 'tr-TR' : 'en-US')
    : '—'

  return (
    <div className="content">
      <div className="heading">
        <div className="eyebrow">{t('CLOUD TELEMETRY')}</div>
        <h1>{t('Cloud connectors')}</h1>
        <p>{t('Connect read-only cloud audit sources and review their last poll and ingestion health.')}</p>
      </div>

      <section className="panel guide">
        <div className="panel-head">
          <div>
            <h2>{t('Read-only collection')}</h2>
            <p>{t('SentinelAI requests audit events only. It does not modify cloud accounts or resources.')}</p>
          </div>
          <Cloud size={18} />
        </div>
        <p>{t('AWS needs CloudTrail LookupEvents. Azure Activity needs a subscription role that can read the Activity Log; built-in Monitoring Reader has broader permissions. Entra sign-ins need the AuditLog.Read.All application permission and a P1 or P2 license.')}</p>
        <small>{t('Cloud account credentials are encrypted in this installation. Use separate credentials for each provider and grant only the listed read permissions.')}</small>
      </section>

      {canManage && <form className="panel preferences" onSubmit={create}>
        <div className="panel-head"><div><h2>{t(editingId ? 'Update cloud source' : 'Add cloud source')}</h2><p>{t('Secrets are encrypted before storage and are never returned by the API.')}</p></div></div>
        <div className="preference-grid">
          <label>{t('Source name')}<input required maxLength={200} value={name} onChange={event => setName(event.target.value)} /></label>
          <label>{t('Provider')}<select value={provider} onChange={event => changeProvider(event.target.value)}>
            <option value="aws_cloudtrail">{t('AWS CloudTrail')}</option>
            <option value="azure_activity">{t('Azure Activity Log')}</option>
            <option value="entra_signin">{t('Microsoft Entra sign-ins')}</option>
          </select></label>
          {configFields.map(([key, label]) => <label key={key}>{t(label)}<input required value={config[key] || ''} onChange={event => setConfig(current => ({ ...current, [key]: event.target.value }))} /></label>)}
          {secretFields.map(([key, label]) => <label key={key}>{t(label)}<input type="password" autoComplete="new-password" required={key !== 'session_token'} value={credentials[key] || ''} onChange={event => setCredentials(current => ({ ...current, [key]: event.target.value }))} /></label>)}
        </div>
        <button className="primary" disabled={busy || !name.trim()}>{busy ? t('Saving…') : t(editingId ? 'Update connector' : 'Save connector')}</button>{editingId&&<button type="button" className="secondary" disabled={busy} onClick={()=>{setEditingId('');setName('');setCredentials({})}}>{t('Cancel')}</button>}
      </form>}

      <section className="panel data-panel">
        <div className="panel-head"><div><h2>{t('Configured cloud sources')}</h2><p>{t('Health updates after scheduled polling, every five minutes.')}</p></div><button className="icon-button" aria-label={t('Refresh')} onClick={() => void load()}><RefreshCw size={16} /></button></div>
        {items.length ? <div className="table-wrap"><table><thead><tr><th>{t('SOURCE')}</th><th>{t('STATUS')}</th><th>{t('LAST SUCCESS')}</th><th>{t('DETAILS')}</th>{canManage && <th>{t('ACTIONS')}</th>}</tr></thead><tbody>
          {items.map(item => <tr key={item.id}>
            <td><b>{item.name}</b><small>{item.provider === 'aws_cloudtrail' ? 'AWS CloudTrail' : item.provider === 'azure_activity' ? 'Azure Activity Log' : 'Microsoft Entra sign-ins'}</small><small>{Object.entries(item.config || {}).map(([key, value]) => `${key}: ${value}`).join(' · ')}</small></td>
            <td><span className={`status ${statusClass(item.status)}`}>{t(item.status)}</span></td>
            <td>{date(item.last_success_at)}</td>
            <td>{item.last_error ? t(item.last_error) : item.last_success_at ? t('Events are being collected from this source.') : t('No successful poll yet.')}</td>
            {canManage && <td>{item.status === 'revoked' ? t('Revoked') : <div className="sensor-registry-actions"><button className="secondary" disabled={busy || !item.enabled || ['queued', 'polling'].includes(item.status)} onClick={() => void poll(item.id)}>{t('Poll now')}</button><button className="secondary" disabled={busy} onClick={() => void toggle(item)}>{item.enabled ? t('Pause') : t('Enable')}</button><button className="secondary" disabled={busy || ['queued', 'polling'].includes(item.status)} onClick={() => edit(item)}>{t('Rotate credentials')}</button><button className="secondary" disabled={busy} onClick={() => void revoke(item)}>{t('Revoke')}</button></div>}</td>}
          </tr>)}
        </tbody></table></div> : <p>{t('No cloud connectors configured yet.')}</p>}
      </section>
    </div>
  )
}

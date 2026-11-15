import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { KeyRound, Trash2 } from 'lucide-react'
import { translate, type Language } from './i18n'

type Row = Record<string, any>

const ROLES: [string, string][] = [
  ['administrator', 'Administrator'],
  ['analyst', 'Analyst'],
  ['auditor', 'Auditor (read only)'],
  ['ingestion_service', 'Sensor account'],
]

/** Administrator settings for company sign-in: group-to-role mapping, automatic accounts, SCIM. */
export default function Identity({
  language,
  setError,
  apiRequest,
}: {
  language: Language
  setError: (message: string) => void
  apiRequest: (path: string, init?: RequestInit) => Promise<any>
}) {
  const t = (value: string) => translate(value, language)
  const [data, setData] = useState<Row | null>(null)
  const [busy, setBusy] = useState(false)
  const [group, setGroup] = useState('')
  const [role, setRole] = useState('analyst')
  const [tokenName, setTokenName] = useState('')
  const [shownToken, setShownToken] = useState('')
  const [saved, setSaved] = useState(false)

  const load = useCallback(async () => {
    try {
      setData(await apiRequest('/identity/settings'))
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to load identity settings')
    }
  }, [apiRequest, setError])
  useEffect(() => { void load() }, [load])

  async function run(action: () => Promise<unknown>, fallback: string) {
    setBusy(true)
    setSaved(false)
    try {
      await action()
      await load()
    } catch (error) {
      setError(error instanceof Error ? t(error.message) : fallback)
    } finally {
      setBusy(false)
    }
  }

  const saveSettings = (patch: Row) => run(async () => {
    await apiRequest('/identity/settings', {
      method: 'PUT',
      body: JSON.stringify({
        auto_provision: data?.auto_provision,
        sync_roles: data?.sync_roles,
        default_role: data?.default_role ?? null,
        ...patch,
      }),
    })
    setSaved(true)
  }, 'Unable to save')

  function addMapping(event: FormEvent) {
    event.preventDefault()
    if (!group.trim()) return
    void run(async () => {
      await apiRequest('/identity/mappings', { method: 'POST', body: JSON.stringify({ claim_value: group.trim(), role_name: role }) })
      setGroup('')
    }, 'Unable to add the mapping')
  }

  function createToken(event: FormEvent) {
    event.preventDefault()
    if (!tokenName.trim()) return
    void run(async () => {
      const created = await apiRequest('/identity/scim-tokens', { method: 'POST', body: JSON.stringify({ name: tokenName.trim() }) })
      setShownToken(created.token)
      setTokenName('')
    }, 'Unable to create the token')
  }

  function revoke(item: Row) {
    if (!window.confirm(t('Revoke this token? The identity provider will stop being able to create or change accounts.'))) return
    void run(() => apiRequest(`/identity/scim-tokens/${item.id}`, { method: 'DELETE' }), 'Unable to revoke the token')
  }

  const roleLabel = (value: string) => t(ROLES.find(([key]) => key === value)?.[1] ?? value)
  const when = (value?: string) => value ? new Date(value).toLocaleString(language === 'tr' ? 'tr-TR' : 'en-US') : '—'
  if (!data) return null
  const scimUrl = `${window.location.origin}${data.scim_base_path}`

  return (
    <>
      <section className="panel preferences" aria-labelledby="sso-title">
        <div className="panel-head">
          <div>
            <h2 id="sso-title">{t('Company sign-in (SSO) and roles')}</h2>
            <p>{data.sso_enabled ? t('Single sign-on is configured on this server. People sign in with their company account; their identity provider decides about passwords and two-step verification.') : t('Single sign-on is not configured on this server, so these settings have no effect yet.')}</p>
          </div>
        </div>
        <div className="identity-body">
          <label className="check"><input type="checkbox" checked={!!data.auto_provision} disabled={busy} onChange={event => void saveSettings({ auto_provision: event.target.checked })} />
            <span><b>{t('Create accounts on first sign-in')}</b><small>{t('A person who signs in through the company account and has no account yet gets one, but only with a role mapped below from their groups (or the default role).')}</small></span></label>
          <label className="check"><input type="checkbox" checked={!!data.sync_roles} disabled={busy} onChange={event => void saveSettings({ sync_roles: event.target.checked })} />
            <span><b>{t('Keep roles in step with groups')}</b><small>{t('At every sign-in the person’s roles are set to the roles mapped from their groups. A person with no mapped group keeps their roles, and the last administrator is never demoted.')}</small></span></label>
          <label>{t('Default role for new accounts')}
            <select value={data.default_role ?? ''} disabled={busy} onChange={event => void saveSettings({ default_role: event.target.value || null })}>
              <option value="">{t('None: refuse people without a mapped group')}</option>
              {ROLES.filter(([key]) => key !== 'administrator').map(([key, label]) => <option key={key} value={key}>{t(label)}</option>)}
            </select>
          </label>
          {saved && <p className="field-success" role="status">{t('Saved.')}</p>}
        </div>

        <div className="panel-head"><div><h3>{t('Group to role mapping')}</h3><p>{t('Enter the value your identity provider sends in the groups or roles claim (for Microsoft Entra, the group’s Object ID or the app role’s value).')}</p></div></div>
        {data.mappings.length ? <div className="table-wrap"><table>
          <thead><tr><th>{t('GROUP OR ROLE VALUE')}</th><th>{t('ROLE')}</th><th>{t('ACTIONS')}</th></tr></thead>
          <tbody>{data.mappings.map((item: Row) => <tr key={item.id}>
            <td><code>{item.claim_value}</code></td><td>{roleLabel(item.role_name)}</td>
            <td><button className="secondary" disabled={busy} aria-label={`${t('Remove')} ${item.claim_value}`} onClick={() => void run(() => apiRequest(`/identity/mappings/${item.id}`, { method: 'DELETE' }), 'Unable to remove')}><Trash2 size={14} /> {t('Remove')}</button></td>
          </tr>)}</tbody></table></div> : <p className="identity-empty">{t('No mappings yet.')}</p>}
        <form className="identity-add" onSubmit={addMapping}>
          <label>{t('Group or role value')}<input value={group} maxLength={255} onChange={event => setGroup(event.target.value)} /></label>
          <label>{t('Role')}<select value={role} onChange={event => setRole(event.target.value)}>{ROLES.map(([key, label]) => <option key={key} value={key}>{t(label)}</option>)}</select></label>
          <button className="primary" disabled={busy || !group.trim()}>{t('Add mapping')}</button>
        </form>
      </section>

      <section className="panel preferences" aria-labelledby="scim-title">
        <div className="panel-head"><div>
          <h2 id="scim-title"><KeyRound size={16} /> {t('Automatic account management (SCIM)')}</h2>
          <p>{t('Lets your identity provider create, change and switch off accounts here when people join, change role or leave. Switching off ends their sessions at once. Accounts are never deleted, so the audit log stays complete.')}</p>
        </div></div>
        <div className="identity-body">
          <label>{t('SCIM address for your identity provider')}<input readOnly value={scimUrl} onFocus={event => event.currentTarget.select()} /></label>
          {shownToken && <div className="token-once" role="status">
            <b>{t('Copy this token now. It is shown only once.')}</b>
            <code>{shownToken}</code>
            <button type="button" className="secondary" onClick={() => void navigator.clipboard?.writeText(shownToken)}>{t('Copy')}</button>
            <button type="button" className="secondary" onClick={() => setShownToken('')}>{t('I saved it')}</button>
          </div>}
        </div>
        {data.scim_tokens.length ? <div className="table-wrap"><table>
          <thead><tr><th>{t('NAME')}</th><th>{t('CREATED')}</th><th>{t('LAST USED')}</th><th>{t('STATUS')}</th><th>{t('ACTIONS')}</th></tr></thead>
          <tbody>{data.scim_tokens.map((item: Row) => <tr key={item.id}>
            <td>{item.name}</td><td>{when(item.created_at)}</td><td>{when(item.last_used_at)}</td>
            <td><span className={`status ${item.revoked ? 'disabled' : 'completed'}`}>{t(item.revoked ? 'Revoked' : 'Active')}</span></td>
            <td>{!item.revoked && <button className="secondary" disabled={busy} onClick={() => revoke(item)}>{t('Revoke')}</button>}</td>
          </tr>)}</tbody></table></div> : <p className="identity-empty">{t('No tokens yet.')}</p>}
        <form className="identity-add" onSubmit={createToken}>
          <label>{t('Token name')}<input value={tokenName} maxLength={200} placeholder={t('For example: Microsoft Entra')} onChange={event => setTokenName(event.target.value)} /></label>
          <button className="primary" disabled={busy || !tokenName.trim()}>{t('Create token')}</button>
        </form>
      </section>
    </>
  )
}

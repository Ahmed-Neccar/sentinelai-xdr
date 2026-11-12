import { useCallback, useEffect, useState } from 'react'
import { RefreshCw, UserPlus } from 'lucide-react'
import { translate, type Language } from './i18n'

type Row = Record<string, any>
type User = { id: string; roles: string[] }

const ROLE_LABEL: Record<string, string> = {
  administrator: 'Administrator',
  analyst: 'Analyst',
  auditor: 'Auditor (read only)',
  ingestion_service: 'Sensor account',
}
const ROLE_HELP: Record<string, string> = {
  administrator: 'Full control, including users, connectors and settings.',
  analyst: 'Investigates findings and cases; cannot manage users or settings.',
  auditor: 'Reads events and the audit log; cannot change anything.',
  ingestion_service: 'For one sensor program only; cannot open the panel pages.',
}

export default function Users({
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
  const [email, setEmail] = useState('')
  const [fullName, setFullName] = useState('')
  const [role, setRole] = useState('analyst')
  const [password, setPassword] = useState('')
  const [repeat, setRepeat] = useState('')
  const [resets, setResets] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    try {
      const page = await apiRequest('/users?page_size=100')
      setItems(page.items || [])
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to load users')
    }
  }, [apiRequest, setError])

  useEffect(() => { void load() }, [load])

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
    if (password !== repeat) {
      setError(t('The two passwords do not match.'))
      return
    }
    void run(async () => {
      await apiRequest('/users', {
        method: 'POST',
        body: JSON.stringify({ email: email.trim(), full_name: fullName.trim(), password, roles: [role] }),
      })
      setEmail('')
      setFullName('')
      setPassword('')
      setRepeat('')
    }, 'Unable to create user')
  }

  const patch = (item: Row, body: Row, fallback = 'Unable to update user') => run(
    () => apiRequest(`/users/${item.id}`, { method: 'PATCH', body: JSON.stringify(body) }),
    fallback,
  )

  function toggleActive(item: Row) {
    const question = item.is_active
      ? 'Disable this account? The person is signed out immediately and cannot sign in again until it is enabled.'
      : 'Enable this account again?'
    if (!window.confirm(t(question))) return
    void patch(item, { is_active: !item.is_active })
  }

  function resetPassword(item: Row) {
    const next = resets[item.id] || ''
    if (next.length < 12) {
      setError(t('Passwords must be at least 12 characters.'))
      return
    }
    void run(async () => {
      await apiRequest(`/users/${item.id}`, { method: 'PATCH', body: JSON.stringify({ password: next }) })
      setResets(current => ({ ...current, [item.id]: '' }))
    }, 'Unable to reset password')
  }

  function unlinkSso(item: Row) {
    if (!window.confirm(t('Forget this account’s single sign-on identity? The next single sign-on with this email will be linked again.'))) return
    void patch(item, { unlink_sso: true })
  }

  const date = (value?: string) => value
    ? new Date(value).toLocaleDateString(language === 'tr' ? 'tr-TR' : 'en-US')
    : '—'
  const primaryRole = (item: Row) => (item.roles || [])[0] || ''

  return (
    <div className="content">
      <div className="heading">
        <div className="eyebrow">{t('ACCESS CONTROL')}</div>
        <h1>{t('Users')}</h1>
        <p>{t('Decide who can sign in and what each person is allowed to do.')}</p>
      </div>

      <section className="panel guide">
        <div className="panel-head">
          <div>
            <h2>{t('Roles')}</h2>
            <p>{t('Give each person the lowest role that lets them do their work.')}</p>
          </div>
          <UserPlus size={18} />
        </div>
        {Object.keys(ROLE_LABEL).map(key => <p key={key}><b>{t(ROLE_LABEL[key])}:</b> {t(ROLE_HELP[key])}</p>)}
        <small>{t('People who use single sign-on still need an account here with the same email; sign-in never creates accounts or grants roles by itself. Every change on this page is written to the audit log.')}</small>
      </section>

      <form className="panel preferences" onSubmit={create}>
        <div className="panel-head"><div><h2>{t('Add user')}</h2><p>{t('The password is needed even for single sign-on users; choose a long random one and share it only if the person will sign in with it.')}</p></div></div>
        <div className="preference-grid">
          <label>{t('Email address')}<input required maxLength={320} value={email} autoComplete="off" onChange={event => setEmail(event.target.value)} /></label>
          <label>{t('Full name')}<input maxLength={200} value={fullName} autoComplete="off" onChange={event => setFullName(event.target.value)} /></label>
          <label>{t('Role')}<select value={role} onChange={event => setRole(event.target.value)}>
            {Object.entries(ROLE_LABEL).map(([value, label]) => <option key={value} value={value}>{t(label)}</option>)}
          </select></label>
          <label>{t('Password (12+ characters)')}<input type="password" required minLength={12} maxLength={128} autoComplete="new-password" value={password} onChange={event => setPassword(event.target.value)} /></label>
          <label>{t('Repeat password')}<input type="password" required minLength={12} maxLength={128} autoComplete="new-password" value={repeat} onChange={event => setRepeat(event.target.value)} /></label>
        </div>
        <button className="primary" disabled={busy || !email.trim() || password.length < 12}>{busy ? t('Saving…') : t('Create user')}</button>
      </form>

      <section className="panel data-panel">
        <div className="panel-head"><div><h2>{t('Accounts')}</h2><p>{t('Disabling an account signs the person out immediately.')}</p></div><button className="icon-button" aria-label={t('Refresh')} onClick={() => void load()}><RefreshCw size={16} /></button></div>
        {items.length ? <div className="table-wrap"><table><thead><tr><th>{t('USER')}</th><th>{t('ROLE')}</th><th>{t('STATUS')}</th><th>{t('SIGN-IN')}</th><th>{t('CREATED')}</th><th>{t('ACTIONS')}</th></tr></thead><tbody>
          {items.map(item => { const self = item.id === user.id; return <tr key={item.id}>
            <td><b>{item.email}</b>{item.full_name && <small>{item.full_name}</small>}{self && <small>{t('This is you')}</small>}</td>
            <td><select value={primaryRole(item)} disabled={busy || self} aria-label={t('Role')} onChange={event => void patch(item, { roles: [event.target.value] })}>
              {Object.entries(ROLE_LABEL).map(([value, label]) => <option key={value} value={value}>{t(label)}</option>)}
            </select>{(item.roles || []).length > 1 && <small>{(item.roles as string[]).map(value => t(ROLE_LABEL[value] || value)).join(' · ')}</small>}</td>
            <td><span className={`status ${item.is_active ? 'completed' : 'disabled'}`}>{t(item.is_active ? 'Active' : 'Disabled')}</span></td>
            <td><small>{t(item.mfa_enabled ? 'Two-step verification on' : 'Two-step verification off')}</small><small>{t(item.sso_linked ? 'Single sign-on linked' : 'Single sign-on not linked')}</small></td>
            <td>{date(item.created_at)}</td>
            <td><div className="sensor-registry-actions">
              <input aria-label={`${t('New password for')} ${item.email}`} type="password" autoComplete="new-password" minLength={12} placeholder={t('New password (12+)')} value={resets[item.id] || ''} onChange={event => setResets(current => ({ ...current, [item.id]: event.target.value }))} />
              <button className="secondary" disabled={busy || !(resets[item.id] || '').length} onClick={() => resetPassword(item)}>{t('Set password')}</button>
              {item.sso_linked && <button className="secondary" disabled={busy} onClick={() => unlinkSso(item)}>{t('Unlink SSO')}</button>}
              <button className={item.is_active ? 'sensor-stop' : 'secondary'} disabled={busy || self} onClick={() => toggleActive(item)}>{item.is_active ? t('Disable') : t('Enable')}</button>
            </div></td>
          </tr> })}
        </tbody></table></div> : <p>{t('No users found.')}</p>}
      </section>
    </div>
  )
}

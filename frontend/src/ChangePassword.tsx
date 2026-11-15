import { useState, type FormEvent } from 'react'
import { KeyRound } from 'lucide-react'
import { translate, type Language } from './i18n'

export const MIN_PASSWORD_LENGTH = 12

/** Returns the first reason the new password cannot be used, or an empty string. */
export function passwordProblem(current: string, next: string, again: string): string {
  if (next && next.length < MIN_PASSWORD_LENGTH) return 'Use at least 12 characters for the new password.'
  if (next && current && next === current) return 'Choose a password different from the current one.'
  if (again && next !== again) return 'The two new passwords do not match.'
  return ''
}

export default function ChangePassword({
  language,
  apiRequest,
  onChanged,
  setError,
}: {
  language: Language
  apiRequest: (path: string, init?: RequestInit) => Promise<any>
  onChanged: (result: any) => void
  setError: (message: string) => void
}) {
  const t = (value: string) => translate(value, language)
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [again, setAgain] = useState('')
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState(false)
  const problem = passwordProblem(current, next, again)
  const ready = !!current && !!next && !!again && !problem

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!ready || busy) return
    setBusy(true)
    setDone(false)
    setError('')
    try {
      const result = await apiRequest('/auth/password', {
        method: 'POST',
        body: JSON.stringify({ current_password: current, new_password: next }),
      })
      onChanged(result)
      setCurrent('')
      setNext('')
      setAgain('')
      setDone(true)
    } catch (error) {
      setError(t(error instanceof Error ? error.message : 'Unable to change the password'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel preferences" aria-labelledby="change-password-title">
      <div className="panel-head">
        <div>
          <h2 id="change-password-title"><KeyRound size={16} /> {t('Change password')}</h2>
          <p>{t('Enter your current password first. Every other device signed in with this account is signed out.')}</p>
        </div>
      </div>
      <form className="password-form" onSubmit={submit} noValidate>
        <label>{t('Current password')}
          <input type="password" autoComplete="current-password" value={current} onChange={event => setCurrent(event.target.value)} />
        </label>
        <label>{t('New password')}
          <input type="password" autoComplete="new-password" aria-describedby="password-hint" aria-invalid={!!problem && !!next} value={next} onChange={event => setNext(event.target.value)} />
        </label>
        <label>{t('Repeat the new password')}
          <input type="password" autoComplete="new-password" value={again} onChange={event => setAgain(event.target.value)} />
        </label>
        <small id="password-hint" className="field-hint">{t('At least 12 characters, with letters and digits or symbols. Not a common word and not your account name.')}</small>
        {problem && <p className="field-error" role="alert">{t(problem)}</p>}
        {done && <p className="field-success" role="status">{t('Password changed. Other sessions were signed out.')}</p>}
        <div><button type="submit" className="primary" disabled={!ready || busy}>{busy ? t('Saving…') : t('Change password')}</button></div>
      </form>
    </section>
  )
}

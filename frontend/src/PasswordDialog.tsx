import { useEffect, useRef, useState, type FormEvent } from 'react'
import { KeyRound, X } from 'lucide-react'
import { translate, type Language } from './i18n'
import { passwordProblem } from './ChangePassword'

/**
 * Two-step password change opened from the Users page.
 * Step 1 asks for the signed-in person's own password; step 2 sets the new one.
 * `self` changes the person's own password (POST /auth/password), otherwise an administrator
 * resets someone else's (PATCH /users/{id}). The server checks the password when step 2 is
 * sent, so a wrong password sends the person back to step 1.
 */
export default function PasswordDialog({
  language,
  target,
  self,
  apiRequest,
  onClose,
  onDone,
}: {
  language: Language
  target: { id: string; email: string }
  self: boolean
  apiRequest: (path: string, init?: RequestInit) => Promise<any>
  onClose: () => void
  onDone: () => void
}) {
  const t = (value: string) => translate(value, language)
  const [step, setStep] = useState<1 | 2>(1)
  const [own, setOwn] = useState('')
  const [next, setNext] = useState('')
  const [again, setAgain] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const box = useRef<HTMLDivElement>(null)
  const problem = passwordProblem(self ? own : '', next, again)
  const ready = !!next && !!again && !problem

  useEffect(() => {
    box.current?.querySelector<HTMLInputElement>('input')?.focus()
  }, [step])
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  function goNext(event: FormEvent) {
    event.preventDefault()
    if (!own) return
    setError('')
    setStep(2)
  }

  async function save(event: FormEvent) {
    event.preventDefault()
    if (!ready || busy) return
    setBusy(true)
    setError('')
    try {
      if (self) {
        await apiRequest('/auth/password', {
          method: 'POST',
          body: JSON.stringify({ current_password: own, new_password: next }),
        })
      } else {
        await apiRequest(`/users/${target.id}`, {
          method: 'PATCH',
          body: JSON.stringify({ password: next, confirm_password: own }),
        })
      }
      onDone()
    } catch (e) {
      const message = e instanceof Error ? e.message : 'Unable to change the password'
      setError(message)
      if (/password is incorrect|Confirm with your own password/i.test(message)) {
        setOwn('')
        setStep(1)
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="dialog-backdrop" onMouseDown={event => { if (event.target === event.currentTarget && !busy) onClose() }}>
      <div className="dialog" role="dialog" aria-modal="true" aria-labelledby="password-dialog-title" ref={box}>
        <div className="dialog-head">
          <h2 id="password-dialog-title"><KeyRound size={16} /> {t(self ? 'Change your password' : 'Set a new password')}</h2>
          <button type="button" className="icon-button" aria-label={t('Close')} onClick={onClose}><X size={16} /></button>
        </div>
        <p className="dialog-sub">{self ? t('Your own account') : target.email} · {t('Step')} {step} / 2</p>
        {step === 1 ? (
          <form onSubmit={goNext} className="dialog-body">
            <label>{t(self ? 'Your current password' : 'Your own administrator password')}
              <input type="password" autoComplete="current-password" value={own} onChange={event => setOwn(event.target.value)} />
            </label>
            <small className="field-hint">{t(self ? 'Confirm it is you before choosing a new password.' : 'Confirm it is you before changing someone else’s password.')}</small>
            {error && <p className="field-error" role="alert">{t(error)}</p>}
            <div className="dialog-actions">
              <button type="button" className="secondary" onClick={onClose}>{t('Cancel')}</button>
              <button type="submit" className="primary" disabled={!own}>{t('Continue')}</button>
            </div>
          </form>
        ) : (
          <form onSubmit={save} className="dialog-body" noValidate>
            <label>{t('New password')}
              <input type="password" autoComplete="new-password" aria-invalid={!!problem && !!next} value={next} onChange={event => setNext(event.target.value)} />
            </label>
            <label>{t('Repeat the new password')}
              <input type="password" autoComplete="new-password" value={again} onChange={event => setAgain(event.target.value)} />
            </label>
            <small className="field-hint">{t('At least 12 characters, with letters and digits or symbols. Not a common word and not your account name.')}</small>
            {problem && <p className="field-error" role="alert">{t(problem)}</p>}
            {error && <p className="field-error" role="alert">{t(error)}</p>}
            <div className="dialog-actions">
              <button type="button" className="secondary" onClick={() => setStep(1)} disabled={busy}>{t('Back')}</button>
              <button type="submit" className="primary" disabled={!ready || busy}>{busy ? t('Saving…') : t('Save password')}</button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}

import { useState, type FormEvent } from 'react'
import { Copy, Download, ShieldOff } from 'lucide-react'
import Modal from '../../components/ui/Modal'
import { translate, type Language } from '../../i18n'
import { sensors, type Enrollment, type SensorRow } from '../../services/sensors'

/** Register a sensor computer and hand over its credentials once, without a terminal. */
export function EnrollModal({ language, onClose, onCreated, setError }: { language: Language; onClose: () => void; onCreated: () => void; setError: (message: string) => void }) {
  const t = (text: string) => translate(text, language)
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [created, setCreated] = useState<Enrollment | null>(null)
  const [copied, setCopied] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!name.trim() || busy) return
    setBusy(true)
    try {
      setCreated(await sensors.enroll(name.trim()))
      onCreated()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to create sensor credentials')
    } finally {
      setBusy(false)
    }
  }

  function download() {
    if (!created) return
    const blob = new Blob([JSON.stringify({ email: created.email, password: created.password, name: created.name }, null, 2)], { type: 'application/json' })
    const link = document.createElement('a')
    link.href = URL.createObjectURL(blob)
    link.download = 'sensor-credentials.json'
    link.click()
    URL.revokeObjectURL(link.href)
  }

  return (
    <Modal title={t('Register a new sensor')} closeLabel={t('Close')} onClose={onClose} busy={busy}>
      {!created ? (
        <form onSubmit={submit} className="modal-form">
          <label>{t('Name of the computer')}
            <input value={name} maxLength={80} onChange={event => setName(event.target.value)} placeholder={t('For example Accounting PC')} disabled={busy} />
          </label>
          <p className="muted-note">{t('This creates an account for that computer and a key. The key is shown once on the next screen.')}</p>
          <div className="modal-actions">
            <button type="button" className="secondary" onClick={onClose} disabled={busy}>{t('Cancel')}</button>
            <button type="submit" className="primary" disabled={busy || !name.trim()}>{busy ? t('Creating…') : t('Generate key')}</button>
          </div>
        </form>
      ) : (
        <div className="modal-form">
          <p className="key-warning" role="status"><b>{t('Copy or download this now.')}</b> {t('The password is shown only this once and cannot be recovered.')}</p>
          <dl className="key-box">
            <dt>{t('Account')}</dt><dd><code>{created.email}</code></dd>
            <dt>{t('Password')}</dt><dd><code>{created.password}</code></dd>
          </dl>
          <div className="modal-actions">
            <button type="button" className="secondary" onClick={() => { void navigator.clipboard?.writeText(created.password); setCopied(true) }}><Copy size={14} /> {copied ? t('Copied') : t('Copy password')}</button>
            <button type="button" className="primary" onClick={download}><Download size={14} /> {t('Download sensor-credentials.json')}</button>
          </div>
          <p className="muted-note">{t('Put the file in the sensor folder on that computer, next to start.ps1. Treat it like a password.')}</p>
          <div className="modal-actions"><button type="button" className="secondary" onClick={onClose}>{t('I saved it, close')}</button></div>
        </div>
      )}
    </Modal>
  )
}

/** One-click revoke, with what it will do spelled out first. */
export function RevokeDialog({ language, sensor, onClose, onRevoked, setError }: { language: Language; sensor: SensorRow; onClose: () => void; onRevoked: () => void; setError: (message: string) => void }) {
  const t = (text: string) => translate(text, language)
  const [busy, setBusy] = useState(false)
  async function revoke() {
    setBusy(true)
    try {
      await sensors.revoke(sensor.sensor_id)
      onRevoked()
      onClose()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to revoke sensor')
      setBusy(false)
    }
  }
  return (
    <Modal title={t('Revoke this sensor?')} closeLabel={t('Close')} onClose={onClose} busy={busy}>
      <div className="modal-form">
        <p><ShieldOff size={16} /> <b>{sensor.host_name || sensor.source_name || sensor.credential_email}</b></p>
        <p className="muted-note">{t('API access stops immediately. A running sensor process exits after its next heartbeat (within 10 seconds). Actions in progress for it are not carried out. This cannot be undone; register the computer again to use it.')}</p>
        <div className="modal-actions">
          <button type="button" className="secondary" onClick={onClose} disabled={busy}>{t('Cancel')}</button>
          <button type="button" className="danger" onClick={() => void revoke()} disabled={busy}>{busy ? t('Revoking…') : t('Revoke access')}</button>
        </div>
      </div>
    </Modal>
  )
}

import { useCallback, useEffect, useState } from 'react'
import { ShieldCheck, ShieldAlert } from 'lucide-react'
import { translate, type Language } from './i18n'

type Report = { ok: boolean; checked: number; first_seq: number | null; last_seq: number | null; head_hash: string | null; broken_at: number[] }

/** Shows whether the audit log is still the chain it was written as, and exports it for a SIEM. */
export default function AuditIntegrity({
  language,
  setError,
  apiRequest,
}: {
  language: Language
  setError: (message: string) => void
  apiRequest: (path: string, init?: RequestInit) => Promise<any>
}) {
  const t = (value: string) => translate(value, language)
  const [report, setReport] = useState<Report | null>(null)
  const [busy, setBusy] = useState(false)

  const check = useCallback(async () => {
    setBusy(true)
    try {
      setReport(await apiRequest('/audit-logs/integrity'))
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to check the audit log')
    } finally {
      setBusy(false)
    }
  }, [apiRequest, setError])
  useEffect(() => { void check() }, [check])

  async function download() {
    setBusy(true)
    try {
      const lines: string[] = []
      let after = 0
      for (let page = 0; page < 200; page++) {
        const chunk = await apiRequest(`/audit-logs/export?after_seq=${after}&limit=5000`)
        chunk.items.forEach((row: unknown) => lines.push(JSON.stringify(row)))
        after = chunk.next_seq
        if (!chunk.has_more) break
      }
      const url = URL.createObjectURL(new Blob([lines.join('\n') + '\n'], { type: 'application/x-ndjson' }))
      const link = document.createElement('a')
      link.href = url
      link.download = 'audit-log.jsonl'
      link.click()
      URL.revokeObjectURL(url)
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to export the audit log')
    } finally {
      setBusy(false)
    }
  }

  if (!report) return null
  return (
    <section className={`panel integrity ${report.ok ? 'ok' : 'broken'}`} aria-labelledby="integrity-title">
      <div className="panel-head">
        <div>
          <h2 id="integrity-title">{report.ok ? <ShieldCheck size={16} /> : <ShieldAlert size={16} />} {t(report.ok ? 'Audit log intact' : 'Audit log has been tampered with')}</h2>
          <p>{report.ok
            ? `${report.checked} ${t('records checked; every record is linked to the one before it.')}`
            : `${t('Records no longer match their chain at positions')}: ${report.broken_at.join(', ')}`}</p>
          {report.head_hash && <small className="integrity-head">{t('Latest hash')}: <code>{report.head_hash.slice(0, 16)}…</code> {t('Keep a copy outside the server to also detect removed latest records.')}</small>}
        </div>
        <div className="integrity-actions">
          <button className="secondary" disabled={busy} onClick={() => void check()}>{t('Check again')}</button>
          <button className="secondary" disabled={busy} onClick={() => void download()}>{t('Download for a SIEM')}</button>
        </div>
      </div>
    </section>
  )
}

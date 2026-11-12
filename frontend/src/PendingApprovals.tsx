import { useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import { translate, type Language } from './i18n'

type Row = Record<string, any>

const ACTION_LABEL: Record<string, string> = {
  block_source_ip: 'Real IP block',
  simulate_host_isolation: 'Host isolation (simulation)',
  simulate_account_disable: 'Account disable (simulation)',
  simulate_source_ip_block: 'Source IP block (simulation)',
}

// Shown at the top of Overview and Cases so that a waiting approval is seen
// without opening each case. Renders nothing when there is nothing to decide.
export default function PendingApprovals({
  items,
  language,
  setError,
  apiRequest,
  reload,
}: {
  items: Row[]
  language: Language
  setError: (message: string) => void
  apiRequest: (path: string, init?: RequestInit) => Promise<any>
  reload: () => void
}) {
  const t = (value: string) => translate(value, language)
  const [busy, setBusy] = useState(false)
  if (!items.length) return null

  async function decide(item: Row, step: 'approve' | 'reject') {
    const question = step === 'reject'
      ? 'Reject this proposal?'
      : item.executed
        ? 'Approve this real block? The sensor computer will block the address within about ten seconds.'
        : 'Approve this simulation? Nothing is executed.'
    if (!window.confirm(t(question))) return
    setBusy(true)
    try {
      await apiRequest(`/cases/${item.case_id}/responses/${item.id}/${step}`, { method: 'POST' })
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to update the proposal')
    } finally {
      setBusy(false)
      reload()
    }
  }

  const date = (value?: string) => value
    ? new Date(value).toLocaleString(language === 'tr' ? 'tr-TR' : 'en-US')
    : '—'

  return (
    <section className="panel data-panel pending-approvals">
      <div className="panel-head">
        <div>
          <h2>{t('Waiting for approval')} ({items.length})</h2>
          <p>{t('Response proposals that still need a decision. The person who proposed one cannot approve it.')}</p>
        </div>
        <ShieldAlert size={18} />
      </div>
      <div className="table-wrap"><table><thead><tr>
        <th>{t('ACTION')}</th><th>{t('TARGET')}</th><th>{t('CASE')}</th><th>{t('REQUESTED BY')}</th><th>{t('DECIDE BEFORE')}</th><th>{t('DECISION')}</th>
      </tr></thead><tbody>
        {items.map(item => <tr key={item.id}>
          <td><b>{t(ACTION_LABEL[item.action_type] || item.action_type)}</b>{item.executed && <small>{item.duration_minutes} {t('minutes')}</small>}</td>
          <td>{item.target}</td>
          <td>{item.case_title}<small>{item.rationale}</small></td>
          <td>{item.requested_by_email || '—'}</td>
          <td>{date(item.expires_at)}</td>
          <td>{item.can_decide
            ? <div className="sensor-registry-actions">
                <button className="secondary" disabled={busy} onClick={() => void decide(item, 'approve')}>{t('Approve')}</button>
                <button className="secondary" disabled={busy} onClick={() => void decide(item, 'reject')}>{t('Reject')}</button>
              </div>
            : <small>{t('Another administrator must decide.')}</small>}</td>
        </tr>)}
      </tbody></table></div>
    </section>
  )
}

import { Lock } from 'lucide-react'
import Stepper from '../../components/ui/Stepper'
import { translate, type Language } from '../../i18n'
import { LIFECYCLE_STEPS, lifecycleOf, type ResponseAction } from '../../services/responses'

const END_TEXT: Record<string, string> = {
  rejected: 'Rejected before it was approved',
  expired: 'Expired before it was approved',
  refused: 'The sensor refused it',
  failed: 'It failed on the sensor',
  cancelled: 'Cancelled before it reached the sensor',
  lifted: 'Lifted: the action is no longer in effect',
}

/** proposed, approved, dispatched, executed or failed: where a real response action stands. */
export default function ResponseLifecycle({ action, language }: { action: Pick<ResponseAction, 'status' | 'enforcement_status' | 'enforcement_detail' | 'failure_code'>; language: Language }) {
  const t = (text: string) => translate(text, language)
  const { index, failedAt, ended } = lifecycleOf(action)
  const steps = LIFECYCLE_STEPS.map(key => ({ key, label: t(({ proposed: 'Proposed', approved: 'Approved', dispatched: 'Dispatched', executed: 'Executed' })[key]) }))
  return (
    <div className="lifecycle">
      <Stepper steps={steps} currentIndex={index} failedAt={failedAt} label={t('Response action progress')} />
      {ended && <p className={failedAt !== undefined ? 'lifecycle-end bad' : 'lifecycle-end'}>{t(END_TEXT[ended] ?? ended)}{action.enforcement_detail ? ` — ${action.enforcement_detail}` : ''}</p>}
    </div>
  )
}

/** Shown in place of the propose button when the chosen sensor cannot take an action right now. */
export function OfflineLock({ language }: { language: Language }) {
  const t = (text: string) => translate(text, language)
  return <p className="offline-lock" role="alert"><Lock size={14} /> {t('The target sensor is offline. Actions are locked until it reports again.')}</p>
}

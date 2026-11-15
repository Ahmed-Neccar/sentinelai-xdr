import { Check, X } from 'lucide-react'

export type Step = { key: string; label: string }
export type StepState = 'done' | 'current' | 'todo' | 'failed'

/** A horizontal progress bar of named steps. `failedAt` marks where the sequence stopped. */
export default function Stepper({ steps, currentIndex, failedAt, label }: { steps: Step[]; currentIndex: number; failedAt?: number; label: string }) {
  const stateOf = (position: number): StepState => {
    if (failedAt !== undefined && position === failedAt) return 'failed'
    if (failedAt !== undefined && position > failedAt) return 'todo'
    if (position < currentIndex) return 'done'
    if (position === currentIndex) return 'current'
    return 'todo'
  }
  return (
    <ol className="stepper" aria-label={label}>
      {steps.map((step, position) => {
        const state = stateOf(position)
        return (
          <li key={step.key} className={`step ${state}`} aria-current={state === 'current' ? 'step' : undefined}>
            <span className="step-dot">{state === 'done' ? <Check size={12} /> : state === 'failed' ? <X size={12} /> : position + 1}</span>
            <span className="step-label">{step.label}</span>
          </li>
        )
      })}
    </ol>
  )
}

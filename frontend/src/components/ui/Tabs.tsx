import { useId, type KeyboardEvent, type ReactNode } from 'react'

export type TabItem = { id: string; label: string; content: ReactNode }

/** Accessible tabs: arrow keys, Home and End move between them; only the active panel is mounted. */
export default function Tabs({ items, active, onChange, label }: { items: TabItem[]; active: string; onChange: (id: string) => void; label: string }) {
  const base = useId()
  const index = Math.max(0, items.findIndex(item => item.id === active))
  const move = (event: KeyboardEvent) => {
    let next = index
    if (event.key === 'ArrowRight') next = (index + 1) % items.length
    else if (event.key === 'ArrowLeft') next = (index - 1 + items.length) % items.length
    else if (event.key === 'Home') next = 0
    else if (event.key === 'End') next = items.length - 1
    else return
    event.preventDefault()
    onChange(items[next].id)
    requestAnimationFrame(() => document.getElementById(`${base}-tab-${items[next].id}`)?.focus())
  }
  return (
    <div className="tabs">
      <div className="tab-list" role="tablist" aria-label={label} onKeyDown={move}>
        {items.map((item, position) => (
          <button
            key={item.id}
            id={`${base}-tab-${item.id}`}
            role="tab"
            type="button"
            aria-selected={position === index}
            aria-controls={`${base}-panel-${item.id}`}
            tabIndex={position === index ? 0 : -1}
            className={position === index ? 'tab active' : 'tab'}
            onClick={() => onChange(item.id)}
          >
            <i>{String(position + 1).padStart(2, '0')}</i>{item.label}
          </button>
        ))}
      </div>
      <div className="tab-panel" role="tabpanel" id={`${base}-panel-${items[index].id}`} aria-labelledby={`${base}-tab-${items[index].id}`}>
        {items[index].content}
      </div>
    </div>
  )
}

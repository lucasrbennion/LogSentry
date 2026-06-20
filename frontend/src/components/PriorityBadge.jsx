const PRIORITY_HELP = {
  P1: 'P1 = Immediate response',
  P2: 'P2 = High priority',
  P3: 'P3 = Review required',
  P4: 'P4 = Baseline / low priority',
}

export default function PriorityBadge({ priority }) {
  const className = `priority-badge priority-${String(priority || '').toLowerCase()}`
  const helpText = PRIORITY_HELP[priority] || 'Priority not defined'

  return (
    <span
      className={className}
      title={helpText}
      aria-label={helpText}
    >
      {priority || 'N/A'}
    </span>
  )
}
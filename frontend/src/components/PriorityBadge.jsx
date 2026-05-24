export default function PriorityBadge({ priority }) {
  const className = `priority-badge priority-${String(priority || '').toLowerCase()}`
  return <span className={className}>{priority || 'N/A'}</span>
}
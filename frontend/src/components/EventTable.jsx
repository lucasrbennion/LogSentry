import PriorityBadge from './PriorityBadge'

function formatAttackMappings(attackMappings) {
  if (!attackMappings?.length) {
    return '-'
  }

  return attackMappings
    .map((mapping) => mapping.attack_technique_id || 'Unmapped')
    .join(', ')
}

function formatRuleHits(ruleHits) {
  if (!ruleHits?.length) {
    return '-'
  }

  return ruleHits
    .map((rule) => `${rule.rule_id} (${rule.name})`)
    .join(' | ')
}

function renderAccountCell(row) {
  // Show the most meaningful account first, then add supporting context when available.
  // This makes account-management and group-management events much easier to interpret.
  const primary = row.account || '-'
  const actor = row.actor_account
  const groupName = row.group_name

  const showActor = actor && actor !== primary

  return (
    <div className="table-cell-stack">
      <span>{primary}</span>
      {showActor ? (
        <span className="table-cell-subtext">Actor: {actor}</span>
      ) : null}
      {groupName ? (
        <span className="table-cell-subtext">Group: {groupName}</span>
      ) : null}
    </div>
  )
}

export default function EventTable({ rows, onOpenNormalizedEvent }) {
  if (!rows.length) {
    return <p className="muted-text">No events match the current filter.</p>
  }

  return (
    <div className="table-wrap">
      <table className="event-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Event ID</th>
            <th>Account</th>
            <th>Machine</th>
            <th>Message</th>
            <th>ATT&amp;CK</th>
            <th>Priority</th>
            <th>Owner</th>
            <th>Explanation</th>
            <th>Rule hits</th>
          </tr>
        </thead>

        <tbody>
          {rows.map((row, index) => (
            <tr
              key={`${row.event_id}-${row.timestamp}-${index}`}
              onDoubleClick={() => onOpenNormalizedEvent(row)}
              title="Double-click to inspect the normalized event"
            >
              <td>{row.timestamp || '-'}</td>
              <td>{row.event_id}</td>
              <td>{renderAccountCell(row)}</td>
              <td>{row.machine_name || '-'}</td>
              <td>{row.message || '-'}</td>
              <td>{formatAttackMappings(row.attack_mappings)}</td>
              <td>
                <PriorityBadge priority={row.priority} />
              </td>
              <td>{row.recommended_owner || '-'}</td>
              <td>{row.explanation || '-'}</td>
              <td>{formatRuleHits(row.rule_hits)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
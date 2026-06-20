import PriorityBadge from './PriorityBadge'

function formatAttackMappings(attackMappings) {
  // Show concise ATT&CK technique IDs in the table so the grid stays readable.
  if (!attackMappings?.length) {
    return '-'
  }

  return attackMappings
    .map((mapping) => mapping.attack_technique_id || 'Unmapped')
    .join(', ')
}

function formatRuleHits(ruleHits) {
  // Keep the rule-hit column compact by showing rule IDs and labels rather than
  // the full explanatory text, which already appears in the Explanation column.
  if (!ruleHits?.length) {
    return '-'
  }

  return ruleHits
    .map((rule) => `${rule.rule_id} (${rule.name})`)
    .join(' | ')
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
            <th>Logon Type</th>
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
              <td>{row.account || '-'}</td>
              <td>{row.machine_name || '-'}</td>
              <td>{row.message || '-'}</td>
              <td>{formatAttackMappings(row.attack_mappings)}</td>
              <td>{row.logon_type || '-'}</td>
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
import PriorityBadge from './PriorityBadge'

export default function EventTable({ rows, onSelect, selected }) {
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
            <th>Logon Type</th>
            <th>Priority</th>
            <th>Owner</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => {
            const isSelected =
              selected?.event_id === row.event_id &&
              selected?.timestamp === row.timestamp &&
              selected?.account === row.account

            return (
              <tr
                key={`${row.event_id}-${row.timestamp}-${index}`}
                className={isSelected ? 'selected-row' : ''}
                onClick={() => onSelect(row)}
              >
                <td>{row.timestamp || '-'}</td>
                <td>{row.event_id}</td>
                <td>{row.account || '-'}</td>
                <td>{row.logon_type || '-'}</td>
                <td>
                  <PriorityBadge priority={row.priority} />
                </td>
                <td>{row.recommended_owner || '-'}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
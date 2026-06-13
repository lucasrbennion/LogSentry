export default function SummaryCards({ summary }) {
  // Break summary dictionaries into arrays so they can be rendered cleanly in the UI.
  const priorityBreakdown = Object.entries(summary?.priority_breakdown || {})
  const eventBreakdown = Object.entries(summary?.event_id_breakdown || {})
  const attackBreakdown = Object.entries(summary?.attack_technique_breakdown || {})

  return (
    <section className="summary-grid">
      <div className="summary-card">
        <span className="summary-label">Total events</span>
        <strong className="summary-value">{summary?.total_events ?? 0}</strong>
      </div>

      <div className="summary-card">
        <span className="summary-label">Priority breakdown</span>
        <div className="stack-list">
          {priorityBreakdown.length ? (
            priorityBreakdown.map(([priority, count]) => (
              <div key={priority} className="stack-row">
                <span>{priority}</span>
                <strong>{count}</strong>
              </div>
            ))
          ) : (
            <span className="muted-text">No data</span>
          )}
        </div>
      </div>

      <div className="summary-card">
        <span className="summary-label">Event ID breakdown</span>
        <div className="stack-list">
          {eventBreakdown.length ? (
            eventBreakdown.map(([eventId, count]) => (
              <div key={eventId} className="stack-row">
                <span>{eventId}</span>
                <strong>{count}</strong>
              </div>
            ))
          ) : (
            <span className="muted-text">No data</span>
          )}
        </div>
      </div>

      <div className="summary-card">
        <span className="summary-label">ATT&CK techniques observed</span>
        <div className="stack-list">
          {attackBreakdown.length ? (
            attackBreakdown.map(([techniqueId, count]) => (
              <div key={techniqueId} className="stack-row">
                <span>{techniqueId}</span>
                <strong>{count}</strong>
              </div>
            ))
          ) : (
            <span className="muted-text">No ATT&CK mappings yet</span>
          )}
        </div>
      </div>
    </section>
  )
}
export default function SummaryCards({ summary }) {
  const priorityBreakdown = Object.entries(summary?.priority_breakdown || {})
  const eventBreakdown = Object.entries(summary?.event_id_breakdown || {})

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
    </section>
  )
}
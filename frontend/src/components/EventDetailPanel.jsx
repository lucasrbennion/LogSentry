export default function EventDetailPanel({ event }) {
  if (!event) {
    return <p className="muted-text">Select an event to inspect its details.</p>
  }

  const normalized = event.normalized_event || {}

  return (
    <div className="detail-panel">
      <h2>Event detail</h2>

      <div className="detail-section">
        <h3>Triage outcome</h3>
        <dl className="detail-list">
          <div>
            <dt>Event ID</dt>
            <dd>{event.event_id}</dd>
          </div>
          <div>
            <dt>Timestamp</dt>
            <dd>{event.timestamp || '-'}</dd>
          </div>
          <div>
            <dt>Account</dt>
            <dd>{event.account || '-'}</dd>
          </div>
          <div>
            <dt>Provider</dt>
            <dd>{event.provider_name || '-'}</dd>
          </div>
          <div>
            <dt>Message</dt>
            <dd>{event.message || '-'}</dd>
          </div>
          <div>
            <dt>Priority</dt>
            <dd>{event.priority || '-'}</dd>
          </div>
          <div>
            <dt>Owner</dt>
            <dd>{event.recommended_owner || '-'}</dd>
          </div>
          <div>
            <dt>Explanation</dt>
            <dd>{event.explanation || '-'}</dd>
          </div>
        </dl>
      </div>

      <div className="detail-section">
        <h3>Rule hits</h3>
        {event.rule_hits?.length ? (
          <ul className="rule-list">
            {event.rule_hits.map((rule) => (
              <li key={rule.rule_id}>
                <strong>{rule.rule_id}</strong> · {rule.name} · {rule.effect}
                <br />
                <span>{rule.reason}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted-text">No rule hits recorded.</p>
        )}
      </div>

      <div className="detail-section">
        <h3>Normalized event</h3>
        <pre className="json-block">{JSON.stringify(normalized, null, 2)}</pre>
      </div>
    </div>
  )
}
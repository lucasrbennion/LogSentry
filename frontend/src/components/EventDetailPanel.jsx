function AttackMappingList({ mappings }) {
  // Render the ATT&CK classification clearly so the analyst can see both the
  // tactic-level context and the specific technique that the rule mapped to.
  if (!mappings?.length) {
    return <p className="muted-text">No ATT&CK mapping assigned to this event.</p>
  }

  return (
    <ul className="attack-list">
      {mappings.map((mapping, index) => (
        <li key={`${mapping.attack_technique_id || 'unmapped'}-${index}`}>
          <div className="attack-title">
            <strong>{mapping.attack_technique_id || 'Unmapped'}</strong>
            {' · '}
            <span>{mapping.attack_technique || 'No technique name'}</span>
          </div>
          <div className="attack-meta">
            <span><strong>Tactic:</strong> {mapping.attack_tactic || '-'}</span>
            <span><strong>Confidence:</strong> {mapping.attack_confidence || '-'}</span>
          </div>
        </li>
      ))}
    </ul>
  )
}

export default function EventDetailPanel({ event }) {
  if (!event) {
    return <p className="muted-text">Select an event to inspect its details.</p>
  }

  const normalized = event.normalized_event || {}
  const attackMappings = event.attack_mappings || []

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
        <h3>MITRE ATT&amp;CK mapping</h3>
        <AttackMappingList mappings={attackMappings} />
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
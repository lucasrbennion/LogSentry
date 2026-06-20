function collectObservedTechniques(results) {
  // Build a unique ATT&CK technique list from the triage results so the user can see
  // what each ATT&CK ID means without trying to decode it from the table alone.
  const seen = new Map()

  for (const row of results || []) {
    for (const mapping of row.attack_mappings || []) {
      const id = mapping.attack_technique_id || 'Unmapped'

      if (!seen.has(id)) {
        seen.set(id, {
          id,
          technique: mapping.attack_technique || 'No technique name',
          tactic: mapping.attack_tactic || '-',
        })
      }
    }
  }

  return Array.from(seen.values())
}

export default function AttackTechniqueGuide({ results }) {
  const techniques = collectObservedTechniques(results)

  return (
    <section className="panel guide-panel">
      <h2 className="guide-title">ATT&amp;CK techniques in this result set</h2>

      {techniques.length ? (
        <div className="attack-guide-list">
          {techniques.map((item) => (
            <div key={item.id} className="attack-guide-row">
              <strong>{item.id}</strong>
              <span>{item.technique}</span>
              <span className="guide-muted-text">Tactic: {item.tactic}</span>
            </div>
          ))}
        </div>
      ) : (
        <p className="muted-text">
          No ATT&amp;CK techniques were observed in the current result set.
        </p>
      )}
    </section>
  )
}
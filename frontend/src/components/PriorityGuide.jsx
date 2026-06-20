const PRIORITY_INFO = [
  {
    code: 'P1',
    title: 'Immediate response',
    description: 'Critical activity requiring urgent incident response, for example audit-log clearing.',
  },
  {
    code: 'P2',
    title: 'High priority',
    description: 'Security-significant activity that should be investigated quickly, such as privilege escalation indicators.',
  },
  {
    code: 'P3',
    title: 'Review required',
    description: 'Activity that merits analyst review but is not immediately critical.',
  },
  {
    code: 'P4',
    title: 'Baseline / low priority',
    description: 'Expected or lower-risk activity, including baseline logons and deprioritised noise.',
  },
]

export default function PriorityGuide() {
  // This guide explains the P1–P4 shorthand so the table stays compact
  // without leaving the reader guessing what the priority labels mean.
  return (
    <section className="panel guide-panel">
      <h2 className="guide-title">Priority meaning</h2>

      <div className="priority-guide-list">
        {PRIORITY_INFO.map((item) => (
          <div key={item.code} className="priority-guide-row">
            <span className={`priority-badge priority-${item.code.toLowerCase()}`}>
              {item.code}
            </span>
            <div>
              <strong>{item.title}</strong>
              <div className="guide-muted-text">{item.description}</div>
            </div>
          </div>
        ))}
      </div>
    </section>
  )
}
export default function NormalizedEventModal({ event, onClose }) {
  // Double-clicking a table row opens this modal so the full normalized record
  // remains available without permanently occupying space on the main page.
  if (!event) {
    return null
  }

  const normalized = event.normalized_event || {}

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-window normalized-event-modal"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <div>
            <h2>Windows Log Detailed Description - Normalised Event</h2>
            <p className="modal-subtitle">
              Event ID {event.event_id} · {event.timestamp || '-'} · {event.account || '-'}
            </p>
          </div>

          <button type="button" className="secondary-button" onClick={onClose}>
            Close
          </button>
        </div>

        <pre className="json-block">{JSON.stringify(normalized, null, 2)}</pre>
      </div>
    </div>
  )
}
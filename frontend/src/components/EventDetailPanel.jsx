import React from "react";

export default function EventDetailPanel({ event }) {
  if (!event) {
    return <div style={panelStyle}>Select an event to inspect its triage details.</div>;
  }

  return (
    <div style={panelStyle}>
      <h3>Event detail</h3>
      <p><strong>Event ID:</strong> {event.event_id}</p>
      <p><strong>Timestamp:</strong> {event.timestamp}</p>
      <p><strong>Account:</strong> {event.account}</p>
      <p><strong>Priority:</strong> {event.priority}</p>
      <p><strong>Recommended owner:</strong> {event.recommended_owner}</p>
      <p><strong>Explanation:</strong> {event.explanation}</p>
    </div>
  );
}

const panelStyle = {
  border: "1px solid #ddd",
  borderRadius: 12,
  padding: 16,
  background: "#fafafa",
};

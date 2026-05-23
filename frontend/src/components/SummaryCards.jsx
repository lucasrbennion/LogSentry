import React from "react";

export default function SummaryCards({ summary }) {
  const priorities = Object.entries(summary.priority_breakdown || {});
  return (
    <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginTop: 16 }}>
      <div style={cardStyle}>
        <strong>Total events</strong>
        <div>{summary.total_events}</div>
      </div>
      {priorities.map(([priority, count]) => (
        <div key={priority} style={cardStyle}>
          <strong>{priority}</strong>
          <div>{count}</div>
        </div>
      ))}
    </div>
  );
}

const cardStyle = {
  border: "1px solid #ddd",
  borderRadius: 12,
  padding: 16,
  minWidth: 120,
  background: "#fafafa",
};

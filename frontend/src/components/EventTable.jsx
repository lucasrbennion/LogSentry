import React from "react";
import PriorityBadge from "./PriorityBadge";

export default function EventTable({ rows, onSelect }) {
  return (
    <table style={{ width: "100%", borderCollapse: "collapse", marginTop: 8 }}>
      <thead>
        <tr>
          <th style={th}>Time</th>
          <th style={th}>Event ID</th>
          <th style={th}>Account</th>
          <th style={th}>Priority</th>
          <th style={th}>Owner</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row, idx) => (
          <tr key={idx} style={{ cursor: "pointer" }} onClick={() => onSelect(row)}>
            <td style={td}>{row.timestamp}</td>
            <td style={td}>{row.event_id}</td>
            <td style={td}>{row.account}</td>
            <td style={td}><PriorityBadge priority={row.priority} /></td>
            <td style={td}>{row.recommended_owner}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const th = { textAlign: "left", borderBottom: "1px solid #ccc", padding: 8 };
const td = { borderBottom: "1px solid #eee", padding: 8 };

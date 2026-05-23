import React from "react";

export default function PriorityBadge({ priority }) {
  return (
    <span style={{
      padding: "4px 8px",
      borderRadius: 999,
      border: "1px solid #bbb",
      fontSize: 12,
      fontWeight: 700
    }}>
      {priority}
    </span>
  );
}

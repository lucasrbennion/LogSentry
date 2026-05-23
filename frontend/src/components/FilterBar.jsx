import React from "react";

export default function FilterBar({ priorityFilter, setPriorityFilter }) {
  return (
    <div style={{ marginTop: 16 }}>
      <label>
        Priority filter:{" "}
        <select value={priorityFilter} onChange={(e) => setPriorityFilter(e.target.value)}>
          <option value="ALL">All</option>
          <option value="P1">P1</option>
          <option value="P2">P2</option>
          <option value="P3">P3</option>
          <option value="P4">P4</option>
        </select>
      </label>
    </div>
  );
}

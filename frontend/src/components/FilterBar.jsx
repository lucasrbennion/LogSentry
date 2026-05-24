export default function FilterBar({ priorityFilter, setPriorityFilter, resultCount }) {
  return (
    <div className="filter-bar">
      <div className="field-inline">
        <label htmlFor="priorityFilter">Priority</label>
        <select
          id="priorityFilter"
          value={priorityFilter}
          onChange={(e) => setPriorityFilter(e.target.value)}
        >
          <option value="ALL">All</option>
          <option value="P1">P1</option>
          <option value="P2">P2</option>
          <option value="P3">P3</option>
          <option value="P4">P4</option>
        </select>
      </div>

      <div className="result-count">
        Showing <strong>{resultCount}</strong> event(s)
      </div>
    </div>
  )
}
export default function PaginationControls({
  currentPage,
  totalPages,
  pageSize,
  pageSizeOptions,
  totalRows,
  visibleRows,
  onPageSizeChange,
  onPreviousPage,
  onNextPage,
}) {
  // Show the visible row range so the analyst can tell where they are inside a large dataset.
  const startRow = totalRows === 0 ? 0 : (currentPage - 1) * pageSize + 1
  const endRow = totalRows === 0 ? 0 : startRow + visibleRows - 1

  return (
    <div className="pagination-bar">
      <div className="pagination-info">
        Showing <strong>{startRow}</strong>–<strong>{endRow}</strong> of{' '}
        <strong>{totalRows}</strong> filtered event(s)
      </div>

      <div className="pagination-actions">
        <label htmlFor="pageSize">Rows per page</label>
        <select
          id="pageSize"
          value={pageSize}
          onChange={(e) => onPageSizeChange(Number(e.target.value))}
        >
          {pageSizeOptions.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>

        <button type="button" className="secondary-button" onClick={onPreviousPage} disabled={currentPage <= 1}>
          Previous
        </button>

        <span className="page-indicator">
          Page <strong>{currentPage}</strong> of <strong>{totalPages}</strong>
        </span>

        <button type="button" className="secondary-button" onClick={onNextPage} disabled={currentPage >= totalPages}>
          Next
        </button>
      </div>
    </div>
  )
}
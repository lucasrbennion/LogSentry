import { useEffect, useRef, useState } from 'react'
import PriorityBadge from './PriorityBadge'

function formatAttackMappings(attackMappings) {
  if (!attackMappings?.length) {
    return '-'
  }

  return attackMappings
    .map((mapping) => mapping.attack_technique_id || 'Unmapped')
    .join(', ')
}

function formatRuleHits(ruleHits) {
  if (!ruleHits?.length) {
    return '-'
  }

  return ruleHits
    .map((rule) => `${rule.rule_id} (${rule.name})`)
    .join(' | ')
}

function renderAccountCell(row) {
  const primary = row.account || '-'
  const actor = row.actor_account
  const groupName = row.group_name

  const showActor = actor && actor !== primary

  return (
    <div className="table-cell-stack">
      <span>{primary}</span>
      {showActor ? (
        <span className="table-cell-subtext">Actor: {actor}</span>
      ) : null}
      {groupName ? (
        <span className="table-cell-subtext">Group: {groupName}</span>
      ) : null}
    </div>
  )
}

function SortableHeader({ field, label, sortConfig, onSortChange }) {
  const isActive = sortConfig.field === field
  const direction = isActive ? sortConfig.direction : null
  const arrow = direction === 'asc' ? '▲' : direction === 'desc' ? '▼' : '↕'

  return (
    <button
      type="button"
      className={`sortable-header-button ${isActive ? 'sortable-header-button-active' : ''}`}
      onClick={() => onSortChange(field)}
      title={`Sort by ${label}`}
      aria-label={`Sort by ${label}`}
    >
      <span>{label}</span>
      <span className="sort-indicator" aria-hidden="true">{arrow}</span>
    </button>
  )
}

export default function EventTable({ rows, sortConfig, onSortChange, onOpenNormalizedEvent }) {
  const topScrollbarRef = useRef(null)
  const bottomScrollRef = useRef(null)
  const tableRef = useRef(null)

  const [tableScrollWidth, setTableScrollWidth] = useState(0)
  const syncingRef = useRef(null)

  useEffect(() => {
    // Keep the top scrollbar width aligned to the real table width so users can
    // navigate horizontally from either the top or the bottom.
    function updateWidths() {
      setTableScrollWidth(tableRef.current?.scrollWidth || 0)
    }

    updateWidths()

    const observer =
      typeof ResizeObserver !== 'undefined'
        ? new ResizeObserver(updateWidths)
        : null

    if (observer && tableRef.current) {
      observer.observe(tableRef.current)
    }

    window.addEventListener('resize', updateWidths)

    return () => {
      window.removeEventListener('resize', updateWidths)
      if (observer) {
        observer.disconnect()
      }
    }
  }, [rows])

  function syncScroll(source, target, sourceName) {
    if (!source || !target) return

    if (syncingRef.current && syncingRef.current !== sourceName) {
      return
    }

    syncingRef.current = sourceName
    target.scrollLeft = source.scrollLeft

    window.requestAnimationFrame(() => {
      syncingRef.current = null
    })
  }

  if (!rows.length) {
    return <p className="muted-text">No events match the current filter.</p>
  }

  return (
    <div className="table-region">
      <div
        ref={topScrollbarRef}
        className="table-scrollbar-top"
        onScroll={() =>
          syncScroll(topScrollbarRef.current, bottomScrollRef.current, 'top')
        }
      >
        <div
          className="table-scrollbar-spacer"
          style={{ width: `${tableScrollWidth}px` }}
        />
      </div>

      <div
        ref={bottomScrollRef}
        className="table-wrap"
        onScroll={() =>
          syncScroll(bottomScrollRef.current, topScrollbarRef.current, 'bottom')
        }
      >
        <table ref={tableRef} className="event-table">
          <thead>
            <tr>
              <th>
                <SortableHeader
                  field="timestamp"
                  label="Time"
                  sortConfig={sortConfig}
                  onSortChange={onSortChange}
                />
              </th>
              <th>
                <SortableHeader
                  field="event_id"
                  label="Event ID"
                  sortConfig={sortConfig}
                  onSortChange={onSortChange}
                />
              </th>
              <th>Account</th>
              <th>Machine</th>
              <th>Message</th>
              <th>ATT&amp;CK</th>
              <th>
                <SortableHeader
                  field="priority"
                  label="Priority"
                  sortConfig={sortConfig}
                  onSortChange={onSortChange}
                />
              </th>
              <th>Owner</th>
              <th>Explanation</th>
              <th>Rule hits</th>
            </tr>
          </thead>

          <tbody>
            {rows.map((row, index) => (
              <tr
                key={`${row.event_id}-${row.timestamp}-${index}`}
                onDoubleClick={() => onOpenNormalizedEvent(row)}
                title="Double-click to inspect the normalized event"
              >
                <td>{row.timestamp || '-'}</td>
                <td>{row.event_id}</td>
                <td>{renderAccountCell(row)}</td>
                <td>{row.machine_name || '-'}</td>
                <td>{row.message || '-'}</td>
                <td>{formatAttackMappings(row.attack_mappings)}</td>
                <td>
                  <PriorityBadge priority={row.priority} />
                </td>
                <td>{row.recommended_owner || '-'}</td>
                <td>{row.explanation || '-'}</td>
                <td>{formatRuleHits(row.rule_hits)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
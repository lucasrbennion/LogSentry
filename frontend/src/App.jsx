import { useEffect, useMemo, useState } from 'react'
import SummaryCards from './components/SummaryCards'
import EventTable from './components/EventTable'
import EventDetailPanel from './components/EventDetailPanel'
import FilterBar from './components/FilterBar'
import PaginationControls from './components/PaginationControls'

// Known local dataset paths used during development and dissertation demos.
// These can be changed later if you move the project or replace the generated dataset.
const SAMPLE_RAW_TEXT_FILE_PATH =
  'C:\\PythonProjects\\LogSentry\\backend\\data\\sample_windows_logs.txt'

const GENERATED_RAW_TEXT_FILE_PATH =
  'C:\\PythonProjects\\LogSentry\\backend\\data\\generated\\generated_windows_logs_2000.txt'

const GENERATED_JSON_FILE_PATH =
  'C:\\PythonProjects\\LogSentry\\backend\\data\\generated\\generated_events_2000.json'

const PAGE_SIZE_OPTIONS = [25, 50, 100, 250]

function sortResults(results) {
  // Sort by priority first so the most urgent events surface to the top,
  // then by timestamp to keep same-priority events in chronological order.
  const priorityOrder = { P1: 1, P2: 2, P3: 3, P4: 4 }

  return [...results].sort((a, b) => {
    const pa = priorityOrder[a.priority] ?? 99
    const pb = priorityOrder[b.priority] ?? 99

    if (pa !== pb) return pa - pb
    return String(a.timestamp || '').localeCompare(String(b.timestamp || ''))
  })
}

function getEndpointForInputMode(inputMode) {
  // Raw Windows log text goes to the parser-heavy route.
  // Large generated JSON datasets go to the JSON-file route.
  return inputMode === 'json_events' ? '/api/triage-json-file' : '/api/triage-file'
}

export default function App() {
  const [inputMode, setInputMode] = useState('raw_text')
  const [filePath, setFilePath] = useState(SAMPLE_RAW_TEXT_FILE_PATH)
  const [data, setData] = useState(null)
  const [selected, setSelected] = useState(null)
  const [priorityFilter, setPriorityFilter] = useState('ALL')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)

  function applyPreset(preset) {
    // Presets make it easy to switch between the canonical small sample and the
    // generated scale-test datasets without retyping long Windows paths by hand.
    if (preset === 'sample_raw') {
      setInputMode('raw_text')
      setFilePath(SAMPLE_RAW_TEXT_FILE_PATH)
      return
    }

    if (preset === 'generated_raw') {
      setInputMode('raw_text')
      setFilePath(GENERATED_RAW_TEXT_FILE_PATH)
      return
    }

    if (preset === 'generated_json') {
      setInputMode('json_events')
      setFilePath(GENERATED_JSON_FILE_PATH)
    }
  }

  async function handleRunTriage(e) {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      const endpoint = getEndpointForInputMode(inputMode)

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file_path: filePath }),
      })

      const payload = await response.json()

      if (!response.ok) {
        throw new Error(payload.error || 'Backend request failed')
      }

      const sortedResults = sortResults(payload.results || [])
      const nextData = {
        summary: payload.summary || {},
        results: sortedResults,
      }

      setData(nextData)
      setSelected(sortedResults[0] || null)
    } catch (err) {
      setError(err.message || 'Something went wrong')
      setData(null)
      setSelected(null)
    } finally {
      setLoading(false)
    }
  }

  const filteredResults = useMemo(() => {
    if (!data?.results) return []

    return data.results.filter((row) =>
      priorityFilter === 'ALL' ? true : row.priority === priorityFilter
    )
  }, [data, priorityFilter])

  // Reset paging whenever a new dataset is loaded, the filter changes, or the page size changes.
  useEffect(() => {
    setCurrentPage(1)
  }, [data, priorityFilter, pageSize])

  const totalPages = useMemo(() => {
    return Math.max(1, Math.ceil(filteredResults.length / pageSize))
  }, [filteredResults.length, pageSize])

  const paginatedResults = useMemo(() => {
    const start = (currentPage - 1) * pageSize
    const end = start + pageSize
    return filteredResults.slice(start, end)
  }, [filteredResults, currentPage, pageSize])

  return (
    <div className="app-shell">
      <header className="page-header">
        <div>
          <h1>LogSentry</h1>
          <p className="subtitle">
            Rule-based triage and prioritisation of Windows Security Event Logs.
          </p>
        </div>
      </header>

      <section className="panel">
        <form className="triage-form" onSubmit={handleRunTriage}>
          <div className="field-group field-group-compact">
            <label htmlFor="inputMode">Dataset type</label>
            <select
              id="inputMode"
              value={inputMode}
              onChange={(e) => setInputMode(e.target.value)}
            >
              <option value="raw_text">Raw Windows text log</option>
              <option value="json_events">Generated JSON event dataset</option>
            </select>
          </div>

          <div className="field-group">
            <label htmlFor="filePath">Dataset file path</label>
            <input
              id="filePath"
              type="text"
              value={filePath}
              onChange={(e) => setFilePath(e.target.value)}
              placeholder="C:\PythonProjects\LogSentry\backend\data\generated\generated_events_2000.json"
            />
          </div>

          <button type="submit" disabled={loading}>
            {loading ? 'Running...' : 'Run triage'}
          </button>
        </form>

        <div className="preset-row">
          <button type="button" className="secondary-button" onClick={() => applyPreset('sample_raw')}>
            Use sample raw log
          </button>
          <button type="button" className="secondary-button" onClick={() => applyPreset('generated_raw')}>
            Use generated raw log
          </button>
          <button type="button" className="secondary-button" onClick={() => applyPreset('generated_json')}>
            Use generated JSON dataset
          </button>
        </div>

        {error ? <p className="error-text">{error}</p> : null}
      </section>

      {data ? (
        <>
          <SummaryCards summary={data.summary} />

          <section className="panel">
            <FilterBar
              priorityFilter={priorityFilter}
              setPriorityFilter={setPriorityFilter}
              resultCount={filteredResults.length}
            />
            <PaginationControls
              currentPage={currentPage}
              totalPages={totalPages}
              pageSize={pageSize}
              pageSizeOptions={PAGE_SIZE_OPTIONS}
              totalRows={filteredResults.length}
              visibleRows={paginatedResults.length}
              onPageSizeChange={setPageSize}
              onPreviousPage={() => setCurrentPage((prev) => Math.max(1, prev - 1))}
              onNextPage={() => setCurrentPage((prev) => Math.min(totalPages, prev + 1))}
            />
          </section>

          <section className="content-grid">
            <div className="panel">
              <EventTable rows={paginatedResults} onSelect={setSelected} selected={selected} />
            </div>

            <div className="panel">
              <EventDetailPanel event={selected} />
            </div>
          </section>
        </>
      ) : (
        <section className="panel empty-state">
          <p>
            Run triage against either the canonical sample log or the generated 2,000-event dataset.
          </p>
        </section>
      )}
    </div>
  )
}
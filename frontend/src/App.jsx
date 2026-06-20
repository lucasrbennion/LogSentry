import { useEffect, useMemo, useState } from 'react'
import SummaryCards from './components/SummaryCards'
import EventTable from './components/EventTable'
import FilterBar from './components/FilterBar'
import PaginationControls from './components/PaginationControls'
import GeneratedFilePickerModal from './components/GeneratedFilePickerModal'
import NormalizedEventModal from './components/NormalizedEventModal'
import PriorityGuide from './components/PriorityGuide'
import AttackTechniqueGuide from './components/AttackTechniqueGuide'

const PAGE_SIZE_OPTIONS = [25, 50, 100, 250]

function getEndpointForFile(file) {
  if (!file) return null
  return file.kind === 'json_events' ? '/api/triage-json-file' : '/api/triage-file'
}

function parseTimestamp(value) {
  // The app currently receives timestamps like "13/06/2026 21:05:13".
  // Convert them into a comparable numeric value so table sorting behaves like
  // a real date sort rather than a naive string sort.
  if (!value || typeof value !== 'string') {
    return Number.NEGATIVE_INFINITY
  }

  const [datePart, timePart = '00:00:00'] = value.split(' ')
  const [day = '01', month = '01', year = '1970'] = datePart.split('/')
  const isoLike = `${year}-${month}-${day}T${timePart}`
  const parsed = Date.parse(isoLike)

  return Number.isNaN(parsed) ? Number.NEGATIVE_INFINITY : parsed
}

function compareByPriority(a, b) {
  const priorityOrder = { P1: 1, P2: 2, P3: 3, P4: 4 }
  const pa = priorityOrder[a.priority] ?? 99
  const pb = priorityOrder[b.priority] ?? 99
  return pa - pb
}

function sortResults(results, sortConfig) {
  // Sorting is done in App rather than EventTable because pagination should operate
  // on the already-sorted result set, not on the original unsorted rows.
  const { field, direction } = sortConfig
  const multiplier = direction === 'desc' ? -1 : 1

  return [...results].sort((a, b) => {
    let comparison = 0

    if (field === 'timestamp') {
      comparison = parseTimestamp(a.timestamp) - parseTimestamp(b.timestamp)
    } else if (field === 'event_id') {
      comparison = (a.event_id ?? -1) - (b.event_id ?? -1)
    } else if (field === 'priority') {
      comparison = compareByPriority(a, b)
    }

    // Stable fallback ordering so rows do not jump around unpredictably when the
    // primary sort field is tied.
    if (comparison === 0) {
      comparison = parseTimestamp(a.timestamp) - parseTimestamp(b.timestamp)
    }
    if (comparison === 0) {
      comparison = (a.event_id ?? -1) - (b.event_id ?? -1)
    }

    return comparison * multiplier
  })
}

export default function App() {
  const [availableFiles, setAvailableFiles] = useState([])
  const [generatedFolder, setGeneratedFolder] = useState('')
  const [selectedFile, setSelectedFile] = useState(null)
  const [isFilePickerOpen, setIsFilePickerOpen] = useState(false)

  const [data, setData] = useState(null)
  const [priorityFilter, setPriorityFilter] = useState('ALL')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)

  // Default sort preserves the current "most urgent first" behaviour while now allowing
  // the user to change it interactively from the table header.
  const [sortConfig, setSortConfig] = useState({
    field: 'priority',
    direction: 'asc',
  })

  const [normalizedModalEvent, setNormalizedModalEvent] = useState(null)

  async function fetchGeneratedFiles() {
    const response = await fetch('/api/generated-files')
    const payload = await response.json()

    if (!response.ok) {
      throw new Error(payload.error || 'Failed to load generated files')
    }

    setGeneratedFolder(payload.folder || '')
    setAvailableFiles(payload.files || [])

    if (!selectedFile && payload.files?.length) {
      setSelectedFile(payload.files[0])
    }
  }

  useEffect(() => {
    fetchGeneratedFiles().catch((err) => {
      setError(err.message || 'Failed to load generated files')
    })
  }, [])

  async function handleOpenFilePicker() {
    setError('')
    try {
      await fetchGeneratedFiles()
      setIsFilePickerOpen(true)
    } catch (err) {
      setError(err.message || 'Failed to load generated files')
    }
  }

  function handleSelectFile(file) {
    setSelectedFile(file)
    setIsFilePickerOpen(false)
  }

  function handleSortChange(field) {
    // Clicking the same sortable header toggles direction.
    // Clicking a different sortable header starts with ascending order.
    setSortConfig((current) => {
      if (current.field === field) {
        return {
          field,
          direction: current.direction === 'asc' ? 'desc' : 'asc',
        }
      }

      return {
        field,
        direction: 'asc',
      }
    })
  }

  async function handleRunTriage() {
    if (!selectedFile?.path) {
      setError('Load a log file first.')
      return
    }

    setLoading(true)
    setError('')

    try {
      const endpoint = getEndpointForFile(selectedFile)

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file_path: selectedFile.path }),
      })

      const payload = await response.json()

      if (!response.ok) {
        throw new Error(payload.error || 'Backend request failed')
      }

      // Keep the raw result order from the backend and apply UI sorting separately.
      // That makes the header sorting predictable and easier to reason about.
      setData({
        summary: payload.summary || {},
        results: payload.results || [],
      })

      setNormalizedModalEvent(null)
    } catch (err) {
      setError(err.message || 'Something went wrong')
      setData(null)
      setNormalizedModalEvent(null)
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

  const sortedResults = useMemo(() => {
    return sortResults(filteredResults, sortConfig)
  }, [filteredResults, sortConfig])

  useEffect(() => {
    setCurrentPage(1)
  }, [data, priorityFilter, pageSize, sortConfig])

  const totalPages = useMemo(() => {
    return Math.max(1, Math.ceil(sortedResults.length / pageSize))
  }, [sortedResults.length, pageSize])

  const paginatedResults = useMemo(() => {
    const start = (currentPage - 1) * pageSize
    const end = start + pageSize
    return sortedResults.slice(start, end)
  }, [sortedResults, currentPage, pageSize])

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
        <div className="toolbar-row">
          <button type="button" onClick={handleOpenFilePicker}>
            Load logs
          </button>

          <button type="button" onClick={handleRunTriage} disabled={loading || !selectedFile}>
            {loading ? 'Running...' : 'Run triage'}
          </button>
        </div>

        <div className="selected-file-summary">
          <p>
            <strong>Default generated folder:</strong>{' '}
            {generatedFolder || 'Loading generated folder...'}
          </p>
          <p>
            <strong>Selected file:</strong>{' '}
            {selectedFile
              ? `${selectedFile.name} (${selectedFile.kind_label})`
              : 'No file selected'}
          </p>
        </div>

        {error ? <p className="error-text">{error}</p> : null}
      </section>

      {data ? (
        <>
          <SummaryCards summary={data.summary} />

          <section className="guidance-grid">
            <PriorityGuide />
            <AttackTechniqueGuide results={data.results} />
          </section>

          <section className="panel">
            <FilterBar
              priorityFilter={priorityFilter}
              setPriorityFilter={setPriorityFilter}
              resultCount={sortedResults.length}
            />

            <PaginationControls
              currentPage={currentPage}
              totalPages={totalPages}
              pageSize={pageSize}
              pageSizeOptions={PAGE_SIZE_OPTIONS}
              totalRows={sortedResults.length}
              visibleRows={paginatedResults.length}
              onPageSizeChange={setPageSize}
              onPreviousPage={() => setCurrentPage((prev) => Math.max(1, prev - 1))}
              onNextPage={() => setCurrentPage((prev) => Math.min(totalPages, prev + 1))}
            />
          </section>

          <section className="panel table-panel">
            <p className="table-helper-text">
              Click Time, Event ID, or Priority to sort. Double-click a row to inspect the
              full normalized event in a pop-up window.
            </p>

            <EventTable
              rows={paginatedResults}
              sortConfig={sortConfig}
              onSortChange={handleSortChange}
              onOpenNormalizedEvent={setNormalizedModalEvent}
            />
          </section>
        </>
      ) : (
        <section className="panel empty-state">
          <p>
            Load a generated .txt or .json log file, then run triage to populate the summary
            cards and event table.
          </p>
        </section>
      )}

      <GeneratedFilePickerModal
        isOpen={isFilePickerOpen}
        folder={generatedFolder}
        files={availableFiles}
        selectedFilePath={selectedFile?.path || ''}
        onClose={() => setIsFilePickerOpen(false)}
        onSelectFile={handleSelectFile}
      />

      <NormalizedEventModal
        event={normalizedModalEvent}
        onClose={() => setNormalizedModalEvent(null)}
      />
    </div>
  )
}
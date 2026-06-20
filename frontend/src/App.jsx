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

function sortResults(results) {
  const priorityOrder = { P1: 1, P2: 2, P3: 3, P4: 4 }

  return [...results].sort((a, b) => {
    const pa = priorityOrder[a.priority] ?? 99
    const pb = priorityOrder[b.priority] ?? 99

    if (pa !== pb) return pa - pb
    return String(a.timestamp || '').localeCompare(String(b.timestamp || ''))
  })
}

function getEndpointForFile(file) {
  if (!file) return null
  return file.kind === 'json_events' ? '/api/triage-json-file' : '/api/triage-file'
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

      const sortedResults = sortResults(payload.results || [])
      setData({
        summary: payload.summary || {},
        results: sortedResults,
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

          <section className="panel table-panel">
            <p className="table-helper-text">
              Double-click a row to inspect the full normalized event in a pop-up window.
            </p>

            <EventTable
              rows={paginatedResults}
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
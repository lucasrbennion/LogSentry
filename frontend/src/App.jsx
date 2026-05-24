import { useMemo, useState } from 'react'
import SummaryCards from './components/SummaryCards'
import EventTable from './components/EventTable'
import EventDetailPanel from './components/EventDetailPanel'
import FilterBar from './components/FilterBar'

const DEFAULT_FILE_PATH =
  'C:\\PythonProjects\\LogSentry\\backend\\data\\sample_windows_logs.txt'

function sortResults(results) {
  const priorityOrder = { P1: 1, P2: 2, P3: 3, P4: 4 }
  return [...results].sort((a, b) => {
    const pa = priorityOrder[a.priority] ?? 99
    const pb = priorityOrder[b.priority] ?? 99
    if (pa !== pb) return pa - pb
    return String(a.timestamp || '').localeCompare(String(b.timestamp || ''))
  })
}

export default function App() {
  const [filePath, setFilePath] = useState(DEFAULT_FILE_PATH)
  const [data, setData] = useState(null)
  const [selected, setSelected] = useState(null)
  const [priorityFilter, setPriorityFilter] = useState('ALL')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function handleRunTriage(e) {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      const response = await fetch('/api/triage-file', {
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
          <div className="field-group">
            <label htmlFor="filePath">Windows log file path</label>
            <input
              id="filePath"
              type="text"
              value={filePath}
              onChange={(e) => setFilePath(e.target.value)}
              placeholder="C:\PythonProjects\LogSentry\backend\data\sample_windows_logs.txt"
            />
          </div>

          <button type="submit" disabled={loading}>
            {loading ? 'Running...' : 'Run triage'}
          </button>
        </form>

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
          </section>

          <section className="content-grid">
            <div className="panel">
              <EventTable rows={filteredResults} onSelect={setSelected} selected={selected} />
            </div>

            <div className="panel">
              <EventDetailPanel event={selected} />
            </div>
          </section>
        </>
      ) : (
        <section className="panel empty-state">
          <p>
            Run triage against your sample Windows log file to load the first event set.
          </p>
        </section>
      )}
    </div>
  )
}
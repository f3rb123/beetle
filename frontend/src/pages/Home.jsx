import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ArrowRight,
  Clock3,
  FileScan,
  SearchCode,
  Trash2,
  UploadCloud,
} from 'lucide-react'
import SeverityBadge from '../components/SeverityBadge.jsx'
import beetleIcon from '../assets/beetle-icon.png'
import {
  DEFAULT_STAGE,
  getPlatformCode,
  getPlatformLabel,
  getStageMeta,
  loadLocalHistory,
  looksLikeResults,
  normalizeHistoryEntry,
  readJsonResponse,
  relativeTimestamp,
  saveScanSnapshot,
} from '../lib/scan-data.js'
import { apiFetch, clearAuth, getToken, getUser, isAdmin } from '../lib/auth.js'

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

/**
 * Read a fetch Response body as a Server-Sent Events stream.
 * Calls onEvent(parsedData) for each "data: ..." line.
 * Returns when the stream closes or status reaches completed/failed.
 * Throws on network/parse errors.
 */
async function readSSEStream(response, onEvent) {
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buf = ''

  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break

      buf += decoder.decode(value, { stream: true })
      const lines = buf.split('\n')
      buf = lines.pop() // keep any incomplete trailing line

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue
        try {
          const data = JSON.parse(line.slice(6))
          const stop = onEvent(data)
          if (stop) return
        } catch {
          // malformed frame — skip
        }
      }
    }
  } finally {
    reader.cancel().catch(() => {})
  }
}

function rowSeverity(entry) {
  if ((entry.ss?.critical || 0) > 0) return 'critical'
  if ((entry.ss?.high || 0) > 0) return 'high'
  if ((entry.ss?.medium || 0) > 0) return 'medium'
  if ((entry.ss?.low || 0) > 0) return 'low'
  return 'info'
}

export default function Home() {
  const navigate = useNavigate()
  const inputRef = useRef(null)
  const uploadCardRef = useRef(null)
  const [file, setFile] = useState(null)
  const [dragging, setDragging] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [progress, setProgress] = useState(0)
  const [statusMessage, setStatusMessage] = useState(DEFAULT_STAGE.label)
  const [activeStage, setActiveStage] = useState(DEFAULT_STAGE.id)
  const [activeScanId, setActiveScanId] = useState('')
  const [streaming, setStreaming] = useState(false)
  const [history, setHistory] = useState([])

  useEffect(() => {
    apiFetch('/api/scans?limit=8')
      .then(response => (response.ok ? response.json() : null))
      .then(payload => {
        if (payload?.scans?.length) {
          setHistory(payload.scans.map(normalizeHistoryEntry))
          return
        }
        setHistory(loadLocalHistory())
      })
      .catch(() => setHistory(loadLocalHistory()))
  }, [])

  const pickFile = nextFile => {
    if (!nextFile) return
    const lower = nextFile.name.toLowerCase()

    if (!lower.endsWith('.apk') && !lower.endsWith('.ipa')) {
      setError('Only APK and IPA files are supported.')
      return
    }

    setFile(nextFile)
    setError('')
  }

  const applyStatusFrame = (data, scanId) => {
    const nextStage = data?.stage || DEFAULT_STAGE.id
    setActiveScanId(scanId)
    setActiveStage(nextStage)
    let msg = data?.message || getStageMeta(nextStage).label
    if (data?.queue_position && nextStage === 'queued') {
      msg = `Queued — position ${data.queue_position} of ${data.queue_position}`
    }
    setStatusMessage(msg)
    setProgress(typeof data?.progress === 'number' ? data.progress : 0)
  }

  // Fallback: poll /status with exponential backoff (used when SSE stream fails).
  // Scans average 2–10 min; hammering /status every 1.2 s is wasteful and, on
  // transient 5xx, also risks a tight retry loop. Backoff: 1.2s → 2s → 3s →
  // 5s → 8s, capped at 8s. Consecutive server errors double the wait up to 30s.
  const pollScan = async scanId => {
    const baseSchedule = [1200, 2000, 3000, 5000, 8000]
    let tick = 0
    let consecutiveErrors = 0
    for (;;) {
      const response = await apiFetch(`/api/scans/${scanId}/status`, { cache: 'no-store' })
      const { data, text } = await readJsonResponse(response)
      if (response.cortexServerError || (!response.ok && response.status >= 500)) {
        // Transient 5xx / network: back off harder instead of giving up.
        consecutiveErrors += 1
        if (consecutiveErrors >= 10) {
          throw new Error('Status check failing repeatedly — is the backend reachable?')
        }
        await sleep(Math.min(30000, 2000 * Math.pow(2, consecutiveErrors - 1)))
        continue
      }
      if (!response.ok) throw new Error(data?.detail || text || `Status check failed (${response.status})`)
      consecutiveErrors = 0

      applyStatusFrame(data, scanId)

      if (data?.status === 'completed') return data?.result
      if (data?.status === 'failed') throw new Error(data?.detail || data?.message || 'Scan failed during analysis.')

      await sleep(baseSchedule[Math.min(tick, baseSchedule.length - 1)])
      tick += 1
    }
  }

  // Primary: stream /stream via SSE-over-fetch (supports auth header)
  const streamScan = async scanId => {
    let streamResponse
    try {
      streamResponse = await apiFetch(`/api/scans/${scanId}/stream`, { cache: 'no-store' })
      if (!streamResponse.ok || !streamResponse.body) throw new Error('stream unavailable')
    } catch {
      // Server doesn't support SSE or network hiccup — fall back to polling
      return pollScan(scanId)
    }

    setStreaming(true)

    return new Promise((resolve, reject) => {
      let settled = false
      const settle = (fn, value) => {
        if (settled) return
        settled = true
        setStreaming(false)
        fn(value)
      }

      readSSEStream(streamResponse, data => {
        applyStatusFrame(data, scanId)

        if (data?.status === 'completed') {
          // Full results come from a separate fetch to avoid streaming the whole blob
          apiFetch(`/api/scans/${scanId}`, { cache: 'no-store' })
            .then(r => r.ok ? r.json() : null)
            .then(fullResults => settle(resolve, fullResults || data?.result || null))
            .catch(() => settle(resolve, data?.result || null))
          return true // signal readSSEStream to stop
        }
        if (data?.status === 'failed') {
          settle(reject, new Error(data?.detail || data?.message || 'Scan failed during analysis.'))
          return true
        }
        if (data?.status === 'timeout' || data?.status === 'not_found') {
          // SSE hit server-side 6-minute cap but the scan is usually still
          // running — fall back to polling rather than giving up.
          if (!settled) {
            pollScan(scanId).then(v => settle(resolve, v)).catch(err => settle(reject, err))
          }
          return true
        }
        return false // continue reading
      }).then(() => {
        // Stream closed cleanly (server EOF / idle timeout) without a terminal
        // event. The scan may still be running — poll /status until it finishes.
        if (!settled) {
          pollScan(scanId).then(v => settle(resolve, v)).catch(err => settle(reject, err))
        }
      }).catch(() => {
        // Stream read error — try polling as final fallback
        if (!settled) {
          pollScan(scanId).then(v => settle(resolve, v)).catch(err => settle(reject, err))
        }
      })
    })
  }

  const startScan = async () => {
    if (!file || loading) return

    setLoading(true)
    setError('')
    setProgress(4)
    setStatusMessage('Uploading package')
    setActiveStage('queued')
    setActiveScanId('')

    try {
      const formData = new FormData()
      formData.append('file', file)

      const response = await apiFetch('/api/analyze', { method: 'POST', body: formData })
      const { data, text } = await readJsonResponse(response)
      if (!response.ok) throw new Error(data?.detail || text || `Server error (${response.status})`)

      let results
      if (looksLikeResults(data)) {
        results = data
      } else if (data?.scan_id) {
        setActiveScanId(data.scan_id)
        setActiveStage(data.stage || 'queued')
        setStatusMessage(data.message || getStageMeta(data.stage).label)
        setProgress(typeof data.progress === 'number' ? data.progress : 6)
        results = data.result || await streamScan(data.scan_id)
      } else {
        throw new Error('Scan queue did not return a scan identifier.')
      }

      saveScanSnapshot(results)
      setHistory(current => [results, ...current.filter(item => item.scan_id !== results.scan_id)].slice(0, 8))
      setProgress(100)
      setActiveStage('completed')
      setStatusMessage('Analysis complete')

      navigate(`/scans/${results.scan_id}/dashboard`, { state: { results } })
    } catch (scanError) {
      setError(scanError.message || 'Scan failed.')
      setProgress(0)
      setActiveStage(DEFAULT_STAGE.id)
      setStatusMessage(DEFAULT_STAGE.label)
      setActiveScanId('')
    } finally {
      setLoading(false)
      setStreaming(false)
    }
  }

  const handleHistoryClick = async scanId => {
    navigate(`/scans/${scanId}/dashboard`)
  }

  const handleDeleteScan = async (scanId, event) => {
    if (event) {
      event.stopPropagation()
      event.preventDefault()
    }
    if (!scanId) return
    if (!window.confirm('Delete this scan? This cannot be undone.')) return

    // Snapshot everything we're about to mutate so we can roll back cleanly if
    // the server rejects the delete. Previously we wiped localStorage before
    // knowing the outcome and had no way to restore it on 5xx / network error.
    let snapshotHistory = null
    let snapshotScanBlob = null
    let snapshotCh = null
    setHistory(prev => {
      snapshotHistory = prev
      return prev.filter(h => h.scan_id !== scanId)
    })
    try {
      snapshotScanBlob = window.localStorage.getItem(`cs_${scanId}`)
      snapshotCh       = window.localStorage.getItem('ch')
      if (snapshotScanBlob !== null) window.localStorage.removeItem(`cs_${scanId}`)
      if (snapshotCh) {
        const parsed = JSON.parse(snapshotCh)
        if (Array.isArray(parsed)) {
          window.localStorage.setItem('ch', JSON.stringify(parsed.filter(e => e.scan_id !== scanId)))
        }
      }
    } catch {
      // best-effort
    }

    const rollback = (reason) => {
      if (snapshotHistory) setHistory(snapshotHistory)
      try {
        if (snapshotScanBlob !== null) window.localStorage.setItem(`cs_${scanId}`, snapshotScanBlob)
        if (snapshotCh !== null) window.localStorage.setItem('ch', snapshotCh)
      } catch {
        // ignore
      }
      if (reason) {
        // eslint-disable-next-line no-alert
        alert(`Could not delete scan: ${reason}. The scan has been restored.`)
      }
    }

    let res
    try {
      res = await apiFetch(`/api/scans/${scanId}`, { method: 'DELETE' })
    } catch {
      rollback('network error')
      return
    }
    if (res.ok || res.status === 404) return   // success (or already gone)
    if (res.cortexServerError || res.status >= 500) {
      rollback(`server error (${res.status})`)
      return
    }
    // 4xx permission / validation — treat as authoritative rejection.
    let detail = `server rejected delete (${res.status})`
    try {
      const body = await res.json()
      if (body?.detail) detail = body.detail
    } catch { /* ignore */ }
    rollback(detail)
  }

  const selectedFileMeta = file
    ? `${getPlatformLabel(file.name)} · ${(file.size / 1024 / 1024).toFixed(1)} MB`
    : 'Drop a package here or browse from disk'

  return (
    <div className="login-page login-page--workspace">
      <div className="login-page__grid" aria-hidden="true" />

      <div className="ws-home">
        <main className="ws-home__main">
          {/* Centered brand header + controls, aligned to the card width */}
          <header className="ws-brand">
            <img src={beetleIcon} alt="Beetle" className="login-card__logo" />
            <h1 className="login-card__title">Beetle</h1>
            <p className="login-card__sub">Mobile Static Security Workspace</p>
            <nav className="ws-brand__actions">
              {isAdmin() && (
                <>
                  <button
                    type="button"
                    className="ws-util-btn"
                    onClick={() => navigate('/settings/webhooks')}
                    title="Manage webhook notifications"
                  >
                    Webhooks
                  </button>
                  <button
                    type="button"
                    className="ws-util-btn"
                    onClick={() => navigate('/settings/rules')}
                    title="Custom SAST rules"
                  >
                    SAST Rules
                  </button>
                </>
              )}
              {getToken() && (
                <button
                  type="button"
                  className="ws-util-btn ws-util-btn--user"
                  onClick={() => { clearAuth(); window.location.reload() }}
                  title={`Signed in as ${getUser()?.username ?? '?'} · Click to sign out`}
                >
                  {getUser()?.username ?? 'Sign out'}
                </button>
              )}
            </nav>
          </header>

          {/* Upload card — login card visual language; workflow unchanged */}
          <div
            ref={uploadCardRef}
            className={`upload-card upload-card--ws${dragging ? ' is-dragging' : ''}${loading ? ' is-loading' : ''}`}
            onDragOver={event => {
              event.preventDefault()
              setDragging(true)
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={event => {
              event.preventDefault()
              setDragging(false)
              pickFile(event.dataTransfer.files?.[0])
            }}
          >
            <div className="upload-card__header">
              <div className="upload-card__icon">
                <UploadCloud size={22} />
              </div>
              <div>
                <div className="upload-card__title">Upload package</div>
                <div className="upload-card__copy">Drag and drop an APK or IPA to start a new scan.</div>
              </div>
            </div>

            <button type="button" className="upload-zone" onClick={() => inputRef.current?.click()}>
              <div className={`scan-orbit${loading ? ' is-active' : ''}`}>
                <div className="scan-orbit__icon">
                  <SearchCode size={26} />
                </div>
              </div>
              <div className="upload-zone__title">{file ? file.name : 'Drop your package here'}</div>
              <div className="upload-zone__copy">{selectedFileMeta}</div>
              <span className="button button--secondary button--small">
                Browse files
                <ArrowRight size={14} />
              </span>
            </button>

            <input ref={inputRef} type="file" accept=".apk,.ipa" hidden onChange={event => pickFile(event.target.files?.[0])} />

            {loading ? (
              <div className="scan-progress">
                <div className="scan-progress__top">
                  <div>
                    <div className="scan-progress__title">
                      Scanning in progress
                      {streaming && <span className="scan-live-badge">LIVE</span>}
                    </div>
                    <div className="scan-progress__copy">{statusMessage}</div>
                  </div>
                  <div className="scan-progress__percent">{Math.round(progress)}%</div>
                </div>

                <div className="scan-progress__bar">
                  <div className="scan-progress__fill" style={{ width: `${progress}%` }} />
                </div>

                <div className="scan-progress__steps">
                  {[DEFAULT_STAGE, ...['preparing', 'decompiling', 'analyzing', 'finalizing'].map(getStageMeta)].map(stage => {
                    const activeIndex = ['queued', 'preparing', 'decompiling', 'analyzing', 'finalizing', 'completed'].indexOf(activeStage)
                    const currentIndex = ['queued', 'preparing', 'decompiling', 'analyzing', 'finalizing', 'completed'].indexOf(stage.id)
                    return (
                      <div key={stage.id} className={`scan-progress__step${currentIndex <= activeIndex ? ' is-active' : ''}`}>
                        {stage.label}
                      </div>
                    )
                  })}
                </div>

                {activeScanId ? <div className="upload-helper">Scan ID {activeScanId.slice(0, 8)}</div> : null}
              </div>
            ) : null}

            {error ? <div className="error-callout">{error}</div> : null}

            <div className="button-row">
              <button type="button" className="button" disabled={!file || loading} onClick={startScan}>
                {loading ? 'Scanning…' : 'Start scan'}
              </button>
            </div>
          </div>

          {/* Recent scans — compact analyst list */}
          <section className="ws-recent">
            <div className="ws-recent__head">
              <span className="ws-recent__title"><Clock3 size={14} /> Recent scans</span>
              {history.length ? <span className="ws-recent__count">{history.length}</span> : null}
              <button type="button" className="ws-recent__all" onClick={() => navigate('/history')}>View all history →</button>
            </div>

            <div className="ws-recent__list">
              {history.length ? history.slice(0, 8).map((rawEntry, index) => {
                const appName = rawEntry.app_name || rawEntry.filename || 'Untitled scan'
                const packageId = rawEntry.pkg || rawEntry.package || rawEntry.app_info?.package || rawEntry.app_info?.bundle_id || rawEntry.filename || ''
                const timestamp = rawEntry.scan_time || rawEntry.created_at || rawEntry.updated_at
                const grade = rawEntry.grade || rawEntry.score?.grade || ''
                const scoreVal = rawEntry.score?.score ?? (typeof rawEntry.score === 'number' ? rawEntry.score : null)
                const gradeText = scoreVal != null ? `${grade || '—'} · ${scoreVal}` : (grade || '—')

                return (
                  <div
                    key={rawEntry.scan_id || `${appName}-${index}`}
                    role="button"
                    tabIndex={0}
                    className="ws-scan-row"
                    onClick={() => handleHistoryClick(rawEntry.scan_id)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault()
                        handleHistoryClick(rawEntry.scan_id)
                      }
                    }}
                    title="View scan results"
                  >
                    <div className="ws-scan-row__avatar">
                      {rawEntry.icon_data
                        ? <img src={rawEntry.icon_data} alt={appName} />
                        : <span>{appName.charAt(0).toUpperCase()}</span>}
                    </div>
                    <div className="ws-scan-row__id">
                      <div className="ws-scan-row__name">{appName}</div>
                      <div className="ws-scan-row__pkg">{packageId}</div>
                    </div>
                    <span className="ws-scan-row__platform">{getPlatformCode(rawEntry.platform, rawEntry.filename)}</span>
                    <span className="ws-scan-row__grade">{gradeText}</span>
                    <SeverityBadge severity={rowSeverity(rawEntry)} compact />
                    <span className="ws-scan-row__time">{relativeTimestamp(timestamp)}</span>
                    <button
                      type="button"
                      className="ws-scan-row__delete"
                      title="Delete this scan"
                      aria-label="Delete this scan"
                      onClick={(e) => handleDeleteScan(rawEntry.scan_id, e)}
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                )
              }) : (
                <div className="ws-recent__empty">
                  <FileScan size={18} />
                  <span>No scans yet. Upload a package to begin.</span>
                </div>
              )}
            </div>
          </section>
        </main>

        <footer className="ws-foot">
          <span className="ws-foot__copy">Built by Althaf Noushad (f3rb)</span>
          <span className="ws-foot__links">
            <a href="https://www.linkedin.com/in/althaf-noushad-6a096823a" target="_blank" rel="noopener noreferrer">LinkedIn</a>
            <a href="mailto:ferbhacker@gmail.com">Email</a>
          </span>
        </footer>
      </div>
    </div>
  )
}

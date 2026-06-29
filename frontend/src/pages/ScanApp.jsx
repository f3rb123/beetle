import { useEffect, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  ArrowRight,
  ChevronLeft,
  Clock3,
  FileScan,
  Trash2,
  UploadCloud,
} from 'lucide-react'
import SeverityBadge from '../components/SeverityBadge.jsx'
import { whiteMark as beetleIcon } from '../assets/brandLogos.js'
import { ENGINEERING_MODULES, isModuleAvailable } from '../lib/engineering-modules.js'
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

// Premium scan experience (Phase 11.9866). ONE stable activity line per real
// backend stage — no rapid cosmetic text shuffling. The line changes only when
// the pipeline actually advances, so it reads as honest progress.
const STAGE_ACTIVITY = {
  queued:      { title: 'Queued for analysis', sub: 'Waiting for an available worker' },
  preparing:   { title: 'Preparing package', sub: 'Unpacking and validating the archive' },
  decompiling: { title: 'Decompiling sources', sub: 'Running JADX and apktool' },
  analyzing:   { title: 'Analyzing application', sub: 'Scanning code, secrets, and attack chains' },
  finalizing:  { title: 'Finalizing report', sub: 'Scoring findings and building the report' },
  completed:   { title: 'Analysis complete', sub: 'Opening your workspace' },
}
// Real backend stage order (from scan-data.js SCAN_STAGES).
const REAL_STAGE_ORDER = ['queued', 'preparing', 'decompiling', 'analyzing', 'finalizing', 'completed']
// Visual timeline → index into REAL_STAGE_ORDER at which the step lights up.
const SCAN_TIMELINE = [
  { label: 'Queued', at: 0 },
  { label: 'Prepare', at: 1 },
  { label: 'Decompile', at: 2 },
  { label: 'Analyze', at: 3 },
  { label: 'Correlate', at: 3 },
  { label: 'Finalize', at: 4 },
]

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

export default function ScanApp() {
  const navigate = useNavigate()
  const { moduleId } = useParams()
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

  // The capability the user picked on the Workspace launcher. Drives the upload
  // card's accept filter + hint; the scan workflow itself is platform-agnostic.
  // Only upload modules (those with an `accept` filter) pre-select; investigation
  // modules navigate into a scan instead and never reach this page.
  const selectedModule = ENGINEERING_MODULES.find(
    m => m.id === moduleId && isModuleAvailable(m) && m.accept,
  ) || null

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

    if (!lower.endsWith('.apk') && !lower.endsWith('.ipa') && !lower.endsWith('.zip')) {
      setError('Only APK, IPA, and repository .zip files are supported.')
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
      <div className="ws-home">
        {/* Scan chrome — back to launcher on the left, utility actions on the right */}
        <header className="ws-topbar">
          <div className="ws-topbar__brand">
            <button
              type="button"
              className="ws-util-btn ws-util-btn--back"
              onClick={() => navigate('/')}
              title="Back to the Engineering Workspace"
            >
              <ChevronLeft size={16} /> Workspace
            </button>
            <img src={beetleIcon} alt="Beetle" className="ws-topbar__logo" />
            <div className="ws-topbar__id">
              <h1 className="ws-topbar__name">{selectedModule ? selectedModule.name : 'Scan Application'}</h1>
              <p className="ws-topbar__tagline">Upload a package to begin analysis</p>
            </div>
          </div>
          <nav className="ws-topbar__actions">
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
                <button
                  type="button"
                  className="ws-util-btn"
                  onClick={() => navigate('/settings/users')}
                  title="Manage users and roles"
                >
                  Users
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

        <main className="ws-home__main">
          {/* Upload card — login card visual language; workflow unchanged */}
          <div
            ref={uploadCardRef}
            className={`upload-card upload-card--ws${dragging ? ' is-dragging' : ''}${loading ? ' is-loading' : ''}${selectedModule ? ' is-module-active' : ''}`}
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
            <div className="upload-intro">
              <div className="upload-intro__title">
                {selectedModule ? selectedModule.name : 'Upload package'}
              </div>
              <div className="upload-intro__copy">
                {selectedModule
                  ? (selectedModule.platform === 'ios'
                      ? 'Drag an IPA to begin analysis'
                      : selectedModule.platform === 'android'
                        ? 'Drag an APK to begin analysis'
                        : selectedModule.platform === 'cicd'
                          ? 'Drag a repository .zip to begin analysis'
                          : 'Drag an APK or IPA to begin analysis')
                  : 'Drag an APK or IPA to begin analysis'}
              </div>
            </div>

            <button type="button" className={`upload-zone${file ? ' has-file' : ''}`} onClick={() => inputRef.current?.click()}>
              <span className="upload-zone__icon">
                {file ? <FileScan size={26} /> : <UploadCloud size={26} />}
              </span>
              <span className="upload-zone__title">{file ? file.name : 'Drop your package here'}</span>
              <span className="upload-zone__copy">{selectedFileMeta}</span>
              <span className="upload-zone__browse">Browse files <ArrowRight size={13} /></span>
            </button>

            <input ref={inputRef} type="file" accept={selectedModule?.accept || '.apk,.ipa'} hidden onChange={event => pickFile(event.target.files?.[0])} />

            {loading ? (
              <div className="scan-exp">
                {/* Calm orbit: a near-invisible highlight sweeps slowly around the mark */}
                <div className="scan-orbit" aria-hidden="true">
                  <span className="scan-orbit__ring" />
                  <span className="scan-orbit__sweep" />
                  <img src={beetleIcon} alt="" className="scan-orbit__logo" />
                </div>

                {/* One stable activity per stage */}
                <div className="scan-exp__activity">
                  <span className="scan-exp__label">
                    Current activity{streaming ? <span className="scan-live-dot" /> : null}
                  </span>
                  <span className="scan-exp__title">{(STAGE_ACTIVITY[activeStage] || STAGE_ACTIVITY.queued).title}</span>
                  <span className="scan-exp__sub">{(STAGE_ACTIVITY[activeStage] || STAGE_ACTIVITY.queued).sub}</span>
                </div>

                <div className="scan-exp__progress">
                  <div className="scan-progress__bar">
                    <div className="scan-progress__fill" style={{ width: `${progress}%` }} />
                  </div>
                  <span className="scan-exp__pct">{Math.round(progress)}%</span>
                </div>

                <ol className="scan-timeline">
                  {SCAN_TIMELINE.map((step, i) => {
                    const realIndex = REAL_STAGE_ORDER.indexOf(activeStage)
                    const state = realIndex > step.at ? 'is-done' : realIndex === step.at ? 'is-active' : 'is-pending'
                    return (
                      <li key={`${step.label}-${i}`} className={`scan-timeline__item ${state}`}>
                        <span className="scan-timeline__node"><span className="scan-timeline__dot" /></span>
                        <span className="scan-timeline__label">{step.label}</span>
                      </li>
                    )
                  })}
                </ol>

                {activeScanId ? <div className="upload-helper">Scan ID {activeScanId.slice(0, 8)}</div> : null}
              </div>
            ) : null}

            {error ? <div className="upload-error">{error}</div> : null}

            <div className="button-row">
              <button type="button" className="upload-start" disabled={!file || loading} onClick={startScan}>
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
          <span className="ws-foot__links">
            <a href="https://www.linkedin.com/in/althaf-noushad-6a096823a" target="_blank" rel="noopener noreferrer">LinkedIn</a>
            <a href="mailto:ferbhacker@gmail.com">Email</a>
          </span>
          <span className="ws-foot__copy">Built by Althaf Noushad (f3rb)</span>
        </footer>
      </div>
    </div>
  )
}

import { useEffect, useMemo, useState } from 'react'
import { Navigate, useLocation, useNavigate, useParams } from 'react-router-dom'
import {
  Activity,
  AppWindow,
  Binary,
  BookKey,
  Boxes,
  Bug,
  CheckCircle2,
  ChevronLeft,
  CircleGauge,
  Code2,
  Copy,
  FileCode2,
  Fingerprint,
  Globe2,
  HardDrive,
  KeyRound,
  Link2,
  Mail,
  Network,
  PackageSearch,
  Route,
  ScrollText,
  SearchCode,
  ShieldCheck,
  ShieldEllipsis,
  ShieldX,
  SquareCode,
  Waypoints,
  XCircle,
  NotebookPen,
  Pencil,
  Trash2,
} from 'lucide-react'
import BrandLogo from '../components/BrandLogo.jsx'
import CodeBlockViewer, { inferLanguage } from '../components/CodeBlockViewer.jsx'
import Footer from '../components/Footer.jsx'
import SectionViews from '../components/workspace/SectionViews.jsx'
import Workspace from '../components/workspace2/Workspace.jsx'
import {
  SECTION_IDS,
  SECTION_MAP,
  SEVERITY_META,
  SEVERITY_ORDER,
  formatTimestamp,
  getPlatformCode,
  getSectionGroups,
  loadLocalHistory,
  readJsonResponse,
  saveScanSnapshot,
  getStoredScan,
  normalizeSeverity,
  deriveSeveritySummary,
} from '../lib/scan-data.js'
import { apiFetch, clearAuth, getToken, getUser, isAdmin } from '../lib/auth.js'

function AppAvatar({ iconData, label, platform, filename }) {
  const badge = getPlatformCode(platform, filename)
  const initial = String(label || 'C').trim().charAt(0).toUpperCase() || 'C'

  return (
    <div className="app-avatar">
      {iconData ? <img src={iconData} alt={label || 'App icon'} /> : <span>{initial}</span>}
      <div className="app-avatar__badge">{badge}</div>
    </div>
  )
}

// Locate a snippet within fetched file content. Returns { lines:[...], focus }
// covering every consecutive snippet line that matches, or null. Matching the
// whole snippet block (not just one line) gives a real multi-line range.
export function locateSnippet(content, snippet) {
  if (!content || !snippet) return null
  const fileLines = content.split('\n')
  const snipLines = String(snippet).split('\n').map(s => s.trim()).filter(s => s.length > 4)
  if (!snipLines.length) return null
  // Anchor on the most distinctive snippet line, then extend to neighbours.
  const anchor = [...snipLines].sort((a, b) => b.length - a.length)[0]
  const idx = fileLines.findIndex(l => l.includes(anchor))
  if (idx < 0) return null
  const matched = new Set([idx + 1])
  for (const sl of snipLines) {
    const j = fileLines.findIndex(l => l.includes(sl))
    if (j >= 0 && Math.abs(j - idx) <= snipLines.length + 2) matched.add(j + 1)
  }
  const lines = [...matched].sort((a, b) => a - b)
  return { lines, focus: idx + 1 }
}

// Find the 1-based line of the first occurrence of any needle (case-sensitive).
function locateToken(content, needles) {
  if (!content) return null
  const fileLines = content.split('\n')
  for (const n of (Array.isArray(needles) ? needles : [needles])) {
    if (!n || String(n).length < 3) continue
    const idx = fileLines.findIndex(l => l.includes(n))
    if (idx >= 0) return idx + 1
  }
  return null
}

// Deterministic line-resolution chain (Phase 11.86 Task 2). Given fetched file
// content and an evidence entry, return { lines, focus, approximate, strategy }.
// Never fabricates an exact line: anything past declared lines is flagged
// approximate. Order: declared → snippet → class-name → method/title → line 1.
export function resolveEvidenceLines(content, ev = {}) {
  // Guard against a declared line that does not exist in the rendered content (e.g. a raw
  // binary-plist artifact line, or a decoded XML shorter than the claimed line). Trusting it
  // would scroll to a nonexistent row (silent no-scroll) or the wrong line. Keep only in-range
  // declared lines; if none survive, fall through to snippet/token resolution below.
  const totalLines = content ? content.split('\n').length : 0
  const inRange = n => Number.isInteger(n) && n >= 1 && n <= totalLines
  const declared = (ev.lines || []).filter(inRange)
  if (declared.length) return { lines: declared, focus: inRange(ev.highlightLine) ? ev.highlightLine : declared[0], approximate: false, strategy: ev.source || 'declared' }

  if (ev.snippet) {
    const hit = locateSnippet(content, ev.snippet)
    if (hit) return { ...hit, approximate: true, strategy: 'snippet match' }
  }
  if (ev.className) {
    const ln = locateToken(content, [`class ${ev.className}`, `interface ${ev.className}`, `object ${ev.className}`, ev.className])
    if (ln) return { lines: [ln], focus: ln, approximate: true, strategy: 'class-name match' }
  }
  if (ev.methodName) {
    const ln = locateToken(content, [`${ev.methodName}(`, ev.methodName])
    if (ln) return { lines: [ln], focus: ln, approximate: true, strategy: 'method-name match' }
  }
  if ((ev.titleKeywords || []).length) {
    const ln = locateToken(content, ev.titleKeywords)
    if (ln) return { lines: [ln], focus: ln, approximate: true, strategy: 'title-keyword match' }
  }
  return { lines: [1], focus: 1, approximate: true, strategy: 'file start (no anchor)' }
}

function WorkspaceCodeModal({ state, onClose, onNavigate }) {
  if (!state.open) return null

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-card modal-card--code" onClick={event => event.stopPropagation()}>
        <CodeBlockViewer
          title={state.path}
          meta={state.meta}
          content={state.content}
          rawContent={state.rawContent}
          binaryInfo={state.binaryInfo}
          language={state.language}
          highlightedLines={state.lines}
          focusLine={state.focus}
          approximate={state.approximate}
          evidenceSource={state.source}
          evidence={state.evidence}
          evidenceIndex={state.evidenceIndex}
          onNavigateEvidence={onNavigate}
          loading={state.loading}
          error={state.error}
          onClose={onClose}
        />
      </div>
    </div>
  )
}

const COMPLIANCE_FRAMEWORKS = [
  { id: 'masvs',        label: 'OWASP MASVS v2' },
  { id: 'pci_dss',      label: 'PCI-DSS v4.0 (Mobile)' },
  { id: 'owasp_mobile', label: 'OWASP Mobile Top 10' },
]

function ExportModal({ results, onClose }) {
  const [preparedBy, setPreparedBy] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  // 'standard' | 'sbom' | framework id
  const [reportType, setReportType] = useState('standard')

  const isCompliance = !['standard', 'sbom'].includes(reportType)
  const isSbom = reportType === 'sbom'

  const doDownload = async (endpoint, body, filename) => {
    const response = await apiFetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    if (!response.ok) {
      const err = await response.json().catch(() => ({}))
      throw new Error(err.detail || 'Export failed')
    }
    const blob = await response.blob()
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    link.click()
    URL.revokeObjectURL(url)
  }

  const handleExport = async () => {
    if (!isSbom && !preparedBy.trim()) return
    setLoading(true)
    setError('')
    try {
      if (isSbom) {
        await doDownload(
          '/api/sbom',
          { results },
          `beetle_${results.app_name || 'sbom'}_${(results.scan_id || '').slice(0, 8)}.cdx.json`,
        )
      } else if (isCompliance) {
        await doDownload(
          '/api/report/compliance',
          { results, framework: reportType, theme: 'light', prepared_by: preparedBy.trim() },
          `beetle_${results.app_name || 'report'}_${reportType}.pdf`,
        )
      } else {
        await doDownload(
          '/api/report',
          { results, theme: 'light', prepared_by: preparedBy.trim() },
          `beetle_${results.app_name || 'report'}_light.pdf`,
        )
      }
      onClose()
    } catch (e) {
      setError(e.message || 'Export failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-card export-modal" onClick={event => event.stopPropagation()}>
        <div className="export-modal__header">
          <div className="export-modal__icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
              <polyline points="14 2 14 8 20 8" />
              <line x1="16" y1="13" x2="8" y2="13" />
              <line x1="16" y1="17" x2="8" y2="17" />
              <polyline points="10 9 9 9 8 9" />
            </svg>
          </div>
          <div>
            <h3 className="export-modal__title">Export PDF Report</h3>
            <p className="export-modal__subtitle">
              Generate a report for <strong>{results.app_name || 'this scan'}</strong>.
            </p>
          </div>
        </div>

        <div className="export-modal__body">
          <div className="export-modal__field">
            <span className="export-modal__field-label">Export type</span>
            <div className="export-type-grid">
              <button
                type="button"
                className={`export-type-btn ${reportType === 'standard' ? 'is-active' : ''}`}
                onClick={() => setReportType('standard')}
              >
                <span className="export-type-btn__name">Security Report</span>
                <span className="export-type-btn__desc">Full technical findings, evidence, score</span>
              </button>
              {COMPLIANCE_FRAMEWORKS.map(fw => (
                <button
                  key={fw.id}
                  type="button"
                  className={`export-type-btn ${reportType === fw.id ? 'is-active' : ''}`}
                  onClick={() => setReportType(fw.id)}
                >
                  <span className="export-type-btn__name">{fw.label}</span>
                  <span className="export-type-btn__desc">Compliance scorecard + control detail</span>
                </button>
              ))}
              <button
                type="button"
                className={`export-type-btn ${isSbom ? 'is-active' : ''}`}
                onClick={() => setReportType('sbom')}
              >
                <span className="export-type-btn__name">CycloneDX SBOM</span>
                <span className="export-type-btn__desc">Software Bill of Materials (CycloneDX 1.5 JSON)</span>
              </button>
            </div>
          </div>

          {!isSbom && (
            <label className="export-modal__field">
              <span className="export-modal__field-label">Prepared by</span>
              <input
                className="export-modal__input"
                value={preparedBy}
                onChange={event => setPreparedBy(event.target.value)}
                placeholder="Enter analyst name or team"
                // eslint-disable-next-line jsx-a11y/no-autofocus
                autoFocus
                onKeyDown={event => {
                  if (event.key === 'Enter' && preparedBy.trim() && !loading) handleExport()
                }}
              />
            </label>
          )}

          {isSbom && (
            <div className="export-sbom-info">
              <span className="export-sbom-info__icon">📦</span>
              <div>
                <div className="export-sbom-info__title">CycloneDX 1.5 SBOM</div>
                <div className="export-sbom-info__body">
                  Exports all detected dependencies, SDKs, trackers, native libraries
                  {results.platform === 'ios' ? ', and embedded frameworks' : ''} with
                  known CVEs and SAST findings mapped to CWEs. Compatible with OWASP
                  Dependency-Track, AWS Inspector, and GitHub Dependency Review.
                </div>
              </div>
            </div>
          )}

          {error && <div className="export-modal__error">{error}</div>}
        </div>

        <div className="export-modal__footer">
          <button type="button" className="export-modal__cancel" onClick={onClose} disabled={loading}>
            Cancel
          </button>
          <button
            type="button"
            className="export-modal__export"
            onClick={handleExport}
            disabled={loading || (!isSbom && !preparedBy.trim())}
          >
            {loading
              ? <><span className="export-modal__spinner" />Generating…</>
              : isSbom
                ? 'Download SBOM'
                : isCompliance
                  ? 'Export Compliance PDF'
                  : 'Export PDF'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── CI Gate Modal ────────────────────────────────────────────────────────────

const DEFAULT_THRESHOLDS = {
  max_critical: 0,
  max_high: -1,
  max_medium: -1,
  max_low: -1,
  min_score: 0,
  block_on_malware: true,
  block_on_secrets: false,
}

function CopyButton({ text, label = 'Copy' }) {
  const [copied, setCopied] = useState(false)
  const doCopy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    })
  }
  return (
    <button type="button" className="ci-copy-btn" onClick={doCopy}>
      <Copy size={12} />
      {copied ? 'Copied!' : label}
    </button>
  )
}

function CiGateModal({ results, onClose }) {
  const [verdict, setVerdict]           = useState(null)
  const [loading, setLoading]           = useState(false)
  const [error, setError]               = useState('')
  const [policy, setPolicy]             = useState(null)
  const [editMode, setEditMode]         = useState(false)
  const [thresholds, setThresholds]     = useState(DEFAULT_THRESHOLDS)
  const [savingPolicy, setSavingPolicy] = useState(false)
  const admin = isAdmin()

  // Load current policy and run check on mount
  useEffect(() => {
    const run = async () => {
      setLoading(true)
      setError('')
      try {
        const [policyResp, checkResp] = await Promise.all([
          apiFetch('/api/policy'),
          apiFetch('/api/policy/check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ results }),
          }),
        ])
        if (policyResp.ok) {
          const p = await policyResp.json()
          setPolicy(p)
          setThresholds(p)
        }
        const checkData = await checkResp.json()
        setVerdict(checkData)
      } catch (e) {
        setError(e.message || 'Failed to run gate check')
      } finally {
        setLoading(false)
      }
    }
    run()
  }, [results])

  const runCheck = async (overrides) => {
    setLoading(true)
    setError('')
    try {
      const resp = await apiFetch('/api/policy/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ results, overrides }),
      })
      const data = await resp.json()
      setVerdict(data)
    } catch (e) {
      setError(e.message || 'Check failed')
    } finally {
      setLoading(false)
    }
  }

  const savePolicy = async () => {
    setSavingPolicy(true)
    try {
      const resp = await apiFetch('/api/policy', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(thresholds),
      })
      if (!resp.ok) throw new Error('Save failed')
      const saved = await resp.json()
      setPolicy(saved)
      setThresholds(saved)
      setEditMode(false)
      await runCheck(null)
    } catch (e) {
      setError(e.message || 'Failed to save policy')
    } finally {
      setSavingPolicy(false)
    }
  }

  const appName = results?.app_name || 'app'
  const scanId  = results?.scan_id  || ''
  // The API is served on the same origin as the UI (nginx proxies /api → backend
  // internally). Use the current origin verbatim so the snippet always points users
  // at the real, reachable address (http://localhost:9005).
  const apiBase = window.location.origin

  const curlCmd = `curl -s -X POST ${apiBase}/api/policy/check \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $BEETLE_TOKEN" \\
  -d @scan_results.json | jq .verdict`

  const _s = '$'
  const ghActionsYaml = `name: Beetle Security Gate
on: [push, pull_request]

jobs:
  beetle-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Upload and scan
        id: scan
        run: |
          SCAN=$(curl -s -X POST ${_s}BEETLE_URL/api/analyze \\
            -H "Authorization: Bearer ${_s}{{ secrets.BEETLE_TOKEN }}" \\
            -F "file=@app.apk")
          SCAN_ID=$(echo ${_s}SCAN | jq -r .scan_id)
          echo "scan_id=${_s}SCAN_ID" >> ${_s}GITHUB_OUTPUT

      - name: Wait for completion
        run: |
          for i in $(seq 1 60); do
            STATUS=$(curl -s "${_s}BEETLE_URL/api/scans/${_s}{{ steps.scan.outputs.scan_id }}/status" \\
              -H "Authorization: Bearer ${_s}{{ secrets.BEETLE_TOKEN }}" | jq -r .status)
            [ "${_s}STATUS" = "completed" ] && break
            sleep 5
          done

      - name: CI Gate check
        run: |
          RESULTS=$(curl -s "${_s}BEETLE_URL/api/scans/${_s}{{ steps.scan.outputs.scan_id }}" \\
            -H "Authorization: Bearer ${_s}{{ secrets.BEETLE_TOKEN }}")
          VERDICT=$(echo ${_s}RESULTS | curl -s -X POST ${_s}BEETLE_URL/api/policy/check \\
            -H "Authorization: Bearer ${_s}{{ secrets.BEETLE_TOKEN }}" \\
            -H "Content-Type: application/json" \\
            -d "{\\"results\\": ${_s}RESULTS}" | jq -r .verdict)
          echo "Gate verdict: ${_s}VERDICT"
          [ "${_s}VERDICT" = "pass" ] || exit 1`

  const ThresholdRow = ({ label, field, isBoolean }) => (
    <div className="ci-threshold-row">
      <span className="ci-threshold-label">{label}</span>
      {isBoolean ? (
        <label className="ci-toggle">
          <input
            type="checkbox"
            checked={!!thresholds[field]}
            onChange={e => setThresholds(prev => ({ ...prev, [field]: e.target.checked }))}
            disabled={!editMode}
          />
          <span className="ci-toggle-track" />
        </label>
      ) : (
        <input
          type="number"
          min="-1"
          className="ci-threshold-input"
          value={thresholds[field] ?? -1}
          onChange={e => setThresholds(prev => ({ ...prev, [field]: parseInt(e.target.value, 10) }))}
          disabled={!editMode}
          title="-1 = disabled (no limit)"
        />
      )}
    </div>
  )

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-card ci-gate-modal" onClick={e => e.stopPropagation()}>
        <div className="ci-gate-header">
          <div className="ci-gate-title-row">
            <ShieldX size={20} className="ci-gate-icon" />
            <h3 className="ci-gate-title">CI Gate</h3>
          </div>
          <button type="button" className="ci-gate-close" onClick={onClose}>×</button>
        </div>

        <div className="ci-gate-body">
          {/* Verdict */}
          {loading && !verdict && (
            <div className="ci-loading">Running gate check…</div>
          )}
          {error && <div className="ci-error">{error}</div>}

          {verdict && (
            <div className={`ci-verdict ci-verdict--${verdict.verdict}`}>
              {verdict.passed
                ? <CheckCircle2 size={28} className="ci-verdict-icon" />
                : <XCircle size={28} className="ci-verdict-icon" />
              }
              <div className="ci-verdict-body">
                <div className="ci-verdict-label">
                  {verdict.passed ? 'Gate passed' : 'Gate failed'}
                </div>
                {verdict.score != null && (
                  <div className="ci-verdict-score">
                    Security score: <strong>{verdict.score}/100</strong>
                  </div>
                )}
                {!verdict.passed && verdict.reasons.length > 0 && (
                  <ul className="ci-reasons">
                    {verdict.reasons.map((r, i) => <li key={i}>{r}</li>)}
                  </ul>
                )}
              </div>
            </div>
          )}

          {/* Policy thresholds */}
          <div className="ci-section">
            <div className="ci-section-header">
              <span className="ci-section-title">Policy thresholds</span>
              {admin && !editMode && (
                <button type="button" className="ci-edit-btn" onClick={() => setEditMode(true)}>
                  Edit
                </button>
              )}
              {admin && editMode && (
                <div className="ci-edit-actions">
                  <button type="button" className="ci-cancel-btn" onClick={() => { setEditMode(false); setThresholds(policy || DEFAULT_THRESHOLDS) }}>
                    Cancel
                  </button>
                  <button type="button" className="ci-save-btn" onClick={savePolicy} disabled={savingPolicy}>
                    {savingPolicy ? 'Saving…' : 'Save & recheck'}
                  </button>
                </div>
              )}
            </div>
            <div className="ci-thresholds">
              <ThresholdRow label="Max critical"          field="max_critical"     />
              <ThresholdRow label="Max high"              field="max_high"         />
              <ThresholdRow label="Max medium"            field="max_medium"       />
              <ThresholdRow label="Max low"               field="max_low"          />
              <ThresholdRow label="Minimum score"         field="min_score"        />
              <ThresholdRow label="Block on malware (VT)" field="block_on_malware" isBoolean />
              <ThresholdRow label="Block on live secrets" field="block_on_secrets" isBoolean />
            </div>
            <div className="ci-threshold-hint">-1 = disabled (no limit applied)</div>
          </div>

          {/* curl command */}
          <div className="ci-section">
            <div className="ci-section-header">
              <span className="ci-section-title">CLI / curl</span>
              <CopyButton text={curlCmd} />
            </div>
            <pre className="ci-code-block">{curlCmd}</pre>
          </div>

          {/* GitHub Actions */}
          <div className="ci-section">
            <div className="ci-section-header">
              <span className="ci-section-title">GitHub Actions</span>
              <CopyButton text={ghActionsYaml} />
            </div>
            <pre className="ci-code-block ci-code-block--tall">{ghActionsYaml}</pre>
          </div>
        </div>
      </div>
    </div>
  )
}

const SECTION_ICONS = {
  dashboard: CircleGauge,
  findings: ShieldEllipsis,
  compare: Activity,
  info: AppWindow,
  source: FileCode2,
  code: SearchCode,
  manifest: ScrollText,
  strings: SquareCode,
  secrets: KeyRound,
  jwts: BookKey,
  ips: HardDrive,
  permissions: ShieldCheck,
  surface: Waypoints,
  browsable: Route,
  endpoints: Link2,
  domains: Globe2,
  api: Code2,
  binary: Binary,
  cert: Fingerprint,
  apkid: Bug,
  masvs: ShieldCheck,
  trackers: Network,
  sdks: Boxes,
  emails: Mail,
  deps: PackageSearch,
}

const NAV_ORDER = [
  'dashboard',
  'findings',
  'info',
  'secrets',
  'endpoints',
  'cert',
  'manifest',
  'source',
  'trackers',
  'permissions',
  'surface',
  'code',
  'domains',
  'binary',
  'api',
  'strings',
  'jwts',
  'ips',
  'masvs',
  'sdks',
  'deps',
  'emails',
  'compare',
  'browsable',
]

const SECTION_LABEL_OVERRIDES = {
  source: 'Resources',
  cert: 'Certificates',
  surface: 'Attack Surface',
  code: 'Code Analysis',
  binary: 'Binaries',
  info: 'App Info',
  deps: 'Dependencies',
}

const SECTION_COPY = {
  dashboard: 'Start here to understand the app, the security score, and the highest-impact signals before drilling into details.',
  findings: 'Review compact vulnerability cards, expand only what matters, and jump directly into code evidence.',
  info: 'Check package identity, hashes, versions, and artifact metadata without leaving the workspace.',
  compare: 'Diff this scan against prior runs to see whether security posture improved or regressed.',
}

function ScanNotes({ scanId }) {
  const [notes,   setNotes]   = useState([])
  const [open,    setOpen]    = useState(false)
  const [text,    setText]    = useState('')
  const [editId,  setEditId]  = useState(null)
  const [editTxt, setEditTxt] = useState('')
  const [saving,  setSaving]  = useState(false)

  useEffect(() => {
    if (!open) return
    apiFetch(`/api/scans/${scanId}/notes`)
      .then(r => r.json())
      .then(data => Array.isArray(data) && setNotes(data))
      .catch(() => {})
  }, [open, scanId])

  const handleAdd = async () => {
    if (!text.trim()) return
    setSaving(true)
    try {
      const res = await apiFetch(`/api/scans/${scanId}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: text.trim() }),
      })
      if (res.ok) {
        const note = await res.json()
        setNotes(prev => [note, ...prev])
        setText('')
      }
    } finally { setSaving(false) }
  }

  const handleEditSave = async (noteId) => {
    if (!editTxt.trim()) return
    const res = await apiFetch(`/api/scans/${scanId}/notes/${noteId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note: editTxt.trim() }),
    })
    if (res.ok) {
      const updated = await res.json()
      setNotes(prev => prev.map(n => n.id === noteId ? updated : n))
      setEditId(null)
    }
  }

  const handleDelete = async (noteId) => {
    await apiFetch(`/api/scans/${scanId}/notes/${noteId}`, { method: 'DELETE' })
    setNotes(prev => prev.filter(n => n.id !== noteId))
  }

  return (
    <div className="scan-notes">
      <button type="button" className="scan-notes__toggle" onClick={() => setOpen(o => !o)}>
        <NotebookPen size={13} />
        Analyst Notes
        {notes.length > 0 && open && <span className="scan-notes__count">{notes.length}</span>}
      </button>

      {open && (
        <div className="scan-notes__body">
          <div className="scan-notes__compose">
            <textarea
              className="scan-notes__input"
              value={text}
              onChange={e => setText(e.target.value)}
              placeholder="Add a note about this scan…"
              rows={2}
            />
            <button
              type="button"
              className="button button--small"
              onClick={handleAdd}
              disabled={saving || !text.trim()}
            >
              {saving ? 'Saving…' : 'Add note'}
            </button>
          </div>

          {notes.length === 0 && (
            <div className="scan-notes__empty">No notes yet.</div>
          )}

          {notes.map(n => (
            <div key={n.id} className="scan-notes__item">
              {editId === n.id ? (
                <div className="scan-notes__edit">
                  <textarea
                    className="scan-notes__input"
                    value={editTxt}
                    onChange={e => setEditTxt(e.target.value)}
                    rows={2}
                  />
                  <div className="scan-notes__edit-actions">
                    <button type="button" className="button button--small" onClick={() => handleEditSave(n.id)}>Save</button>
                    <button type="button" className="scan-notes__cancel" onClick={() => setEditId(null)}>Cancel</button>
                  </div>
                </div>
              ) : (
                <>
                  <div className="scan-notes__text">{n.note}</div>
                  <div className="scan-notes__meta">
                    {n.author && <span>{n.author}</span>}
                    {n.created_at && <span>· {n.created_at.slice(0, 16).replace('T', ' ')} UTC</span>}
                    {n.updated_at && n.updated_at !== n.created_at && <span>· edited</span>}
                    <button type="button" className="scan-notes__icon-btn" onClick={() => { setEditId(n.id); setEditTxt(n.note) }} title="Edit"><Pencil size={11} /></button>
                    <button type="button" className="scan-notes__icon-btn scan-notes__icon-btn--danger" onClick={() => handleDelete(n.id)} title="Delete"><Trash2 size={11} /></button>
                  </div>
                </>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function SeveritySummaryBox({ severity, count }) {
  const meta = SEVERITY_META[severity] || SEVERITY_META.info

  return (
    <div
      className={`severity-summary-card severity-summary-card--${severity}`}
      style={{
        '--severity-card-bg': meta.bg,
        '--severity-card-border': meta.border,
        '--severity-card-text': meta.text,
      }}
    >
      <strong>{count}</strong>
      <span>{meta.label}</span>
    </div>
  )
}

export default function Results() {
  const { scanId, sectionId } = useParams()
  const location = useLocation()
  const navigate = useNavigate()
  const [results, setResults] = useState(location.state?.results || null)
  const [loading, setLoading] = useState(!location.state?.results)
  const [error, setError] = useState('')
  const [viewMode, setViewMode] = useState(() => window.localStorage.getItem('cortex-view-mode') || 'quick')
  const [exportOpen, setExportOpen] = useState(false)
  const [gateOpen, setGateOpen]     = useState(false)
  const [codeState, setCodeState] = useState({
    open: false,
    path: '',
    content: '',
    language: 'txt',
    lines: [],
    focus: null,
    loading: false,
    error: '',
    meta: '',
    approximate: false,
    source: '',
    evidence: [],
    evidenceIndex: 0,
  })

  const handleSbomDownload = async (scanResults) => {
    try {
      const resp = await apiFetch('/api/sbom', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ results: scanResults }),
      })
      if (!resp.ok) throw new Error(`Server error ${resp.status}`)
      const blob = await resp.blob()
      const appName = scanResults?.app_name || 'scan'
      const sid = (scanResults?.scan_id || 'unknown').slice(0, 8)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `beetle_${appName}_${sid}.cdx.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      // eslint-disable-next-line no-alert
      alert(`SBOM export failed: ${err.message}`)
    }
  }

  const handleSarifDownload = async (scanResults) => {
    try {
      const resp = await apiFetch('/api/sarif', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ results: scanResults }),
      })
      if (!resp.ok) throw new Error(`Server error ${resp.status}`)
      const blob = await resp.blob()
      const appName = scanResults?.app_name || 'scan'
      const scanId  = (scanResults?.scan_id || 'unknown').slice(0, 8)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `beetle_${appName}_${scanId}.sarif.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      // eslint-disable-next-line no-alert
      alert(`SARIF export failed: ${err.message}`)
    }
  }

  const resolvedSectionId = SECTION_IDS.includes(sectionId) ? sectionId : 'dashboard'
  const visibleGroups = useMemo(
    () => getSectionGroups(viewMode, results?.platform || '', results),
    [viewMode, results?.platform, results?.components, results?.taint_flows, results?.findings, results?.virustotal, results?.vt_report],
  )
  const allowedSectionIds = useMemo(() => new Set(visibleGroups.flatMap(group => group.items.map(item => item.id))), [visibleGroups])

  useEffect(() => {
    window.localStorage.setItem('cortex-view-mode', viewMode)
  }, [viewMode])

  useEffect(() => {
    if (!SECTION_IDS.includes(sectionId || '')) {
      navigate(`/scans/${scanId}/dashboard`, { replace: true })
    }
  }, [navigate, scanId, sectionId])

  useEffect(() => {
    if (viewMode === 'quick' && !allowedSectionIds.has(resolvedSectionId)) {
      navigate(`/scans/${scanId}/dashboard`, { replace: true })
    }
  }, [allowedSectionIds, navigate, resolvedSectionId, scanId, viewMode])

  useEffect(() => {
    let cancelled = false

    if (!scanId) return undefined

    const loadResults = async () => {
      setLoading(true)
      setError('')

      const stored = location.state?.results || getStoredScan(scanId)
      if (stored) {
        if (cancelled) return
        setResults(stored)
        setLoading(false)
        saveScanSnapshot(stored)
      }

      try {
        const response = await apiFetch(`/api/scans/${scanId}`, { cache: 'no-store' })
        const { data, text } = await readJsonResponse(response)
        if (!response.ok) throw new Error(data?.detail || text || `Unable to load scan ${scanId}`)
        if (cancelled) return
        setResults(data)
        saveScanSnapshot(data)
      } catch (loadError) {
        if (cancelled) return
        if (!stored) setError(loadError.message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    loadResults()

    return () => {
      cancelled = true
    }
  }, [location.state?.results, scanId])

  const counts = useMemo(() => {
    if (!results) return {}

    const findings = results.findings || []
    const surface = results.attack_surface || {}

    return {
      findings: findings.length,
      source: 0,
      code: findings.filter(item => item.source === 'SAST' || item.rule_id).length,
      permissions: results.permissions?.classified?.length || results.permissions?.all?.length || 0,
      browsable: (surface.activities || []).filter(item => item.browsable && (item.deeplinks || []).length).length,
      trackers: (results.trackers || []).length,
      secrets: (results.secrets || []).length,
      jwts: (results.jwts || []).length,
      ips: (results.ips || []).length,
      strings: Object.keys(results.string_analysis || {}).length,
      surface: ['activities', 'services', 'receivers', 'providers'].reduce((sum, key) => sum + ((surface[key] || []).length), 0),
      endpoints: (results.endpoints || []).length,
      domains: (results.domain_intel || []).length,
      binary: (results.binaries || []).length,
      api: Object.keys(results.android_api || {}).length,
      emails: (results.emails || []).length,
      sdks: (results.sdks || []).length,
      deps: (results.dependencies?.deps || []).length,
      apkid: Object.keys(results.apkid || {}).length,
      masvs: findings.filter(item => item.masvs || item.owasp).length,
      compare: loadLocalHistory().filter(item => item.scan_id !== scanId).length,
      info: 0,
      dashboard: 0,
      manifest: 0,
      cert: 0,
    }
  }, [results, scanId])

  const navItems = useMemo(() => {
    const visibleIds = new Set(visibleGroups.flatMap(group => group.items.map(item => item.id)))
    const orderedIds = [
      ...NAV_ORDER.filter(id => visibleIds.has(id)),
      ...[...visibleIds].filter(id => !NAV_ORDER.includes(id)),
    ]

    return orderedIds.map(id => ({
      ...(SECTION_MAP[id] || { id, label: id }),
      label: SECTION_LABEL_OVERRIDES[id] || SECTION_MAP[id]?.label || id,
    }))
  }, [visibleGroups])

  // opts: { lines, snippet, className, methodName, titleKeywords, highlightLine,
  //         source, approximate, evidence, index }
  const openCode = async (path, lines = [], opts = {}) => {
    if (!path || !scanId) return

    const base = {
      open: true,
      path,
      lines,
      focus: opts.highlightLine || (lines || [])[0] || null,
      language: inferLanguage(path),
      approximate: !!opts.approximate,
      source: opts.source || '',
      evidence: opts.evidence || [],
      evidenceIndex: opts.index || 0,
      binaryInfo: null,
    }
    setCodeState({ ...base, content: '', binaryInfo: null, loading: true, error: '', meta: 'Loading source…' })

    try {
      // RUN 28 / BUG 1: a binary FINDING passes its Mach-O string index — ask the server for the
      // extracted-strings listing (text) so we scroll to the matched symbol instead of showing a
      // generic protections card. A plain tree browse (no index) still gets the card.
      const stringsQ = opts.stringsIndex ? `&strings_index=${encodeURIComponent(opts.stringsIndex)}` : ''
      const response = await apiFetch(`/api/scans/${scanId}/file?path=${encodeURIComponent(path)}${stringsQ}`)
      if (!response.ok) throw new Error(response.status === 404 ? 'Source file not available for this scan.' : 'Unable to open source file.')

      // Compiled artifacts come back as a JSON envelope — render a binary card,
      // never decoded bytes. Text source comes back as plain text.
      const contentType = response.headers.get('content-type') || ''
      if (contentType.includes('application/json')) {
        const payload = await response.json().catch(() => null)
        if (payload && payload.binary) {
          setCodeState({
            ...base, content: '', binaryInfo: payload.info || {}, lines: [], focus: null,
            approximate: false, loading: false, error: '',
            meta: `${payload.info?.label || 'Binary file'}${payload.info?.size ? ` · ${payload.info.size}` : ''}`,
          })
          return
        }
      }
      const rawContent = await response.text()
      // RUN 29 / BUG 1: pretty-print JSON HERE (not in the viewer) so the line the resolver picks
      // and the lines the viewer renders are the SAME — otherwise a JSON finding's declared line
      // (numbered against the minified bytes) no longer matched the beautified rows and the scroll
      // went nowhere. rawContent is kept for the Copy button (original bytes).
      let content = rawContent
      if (inferLanguage(path) === 'json' && rawContent.trim()) {
        try { content = JSON.stringify(JSON.parse(rawContent), null, 2) } catch { content = rawContent }
      }

      // Deterministic resolution chain (declared → snippet → class → method →
      // title → line 1). Never fabricates an exact line; non-declared is ≈approx.
      const r = resolveEvidenceLines(content, {
        lines: (lines || []).filter(Boolean),
        highlightLine: opts.highlightLine,
        snippet: opts.snippet,
        className: opts.className,
        methodName: opts.methodName,
        titleKeywords: opts.titleKeywords,
        source: opts.source,
      })

      const span = r.lines.length > 1 ? `${r.lines[0]}–${r.lines[r.lines.length - 1]}` : `${r.lines[0]}`
      // RUN 29 / BUG 1+2: label the strings view. A binary FINDING scrolls to its symbol; a bare
      // binary BROWSE (X-Beetle-View header) shows the compiled binary's extracted strings.
      const isBinaryStrings = response.headers.get('X-Beetle-View') === 'binary-strings'
      const meta = opts.stringsIndex
        ? `Extracted strings${opts.symbol ? ` · ${opts.symbol}` : ''} · string #${opts.stringsIndex}`
        : isBinaryStrings
          ? 'Compiled binary — extracted strings (searchable)'
          : `${r.approximate ? '≈ lines' : 'Lines'} ${span}${opts.source ? ` · ${opts.source}` : ''}${r.approximate ? ` · ${r.strategy}` : ''}`
      setCodeState({
        ...base,
        lines: r.lines,
        focus: r.focus,
        approximate: r.approximate,
        content,
        rawContent,
        loading: false,
        error: '',
        meta,
      })
    } catch (openError) {
      setCodeState({
        ...base,
        content: '',
        loading: false,
        error: openError.message,
        meta: 'Source viewer',
      })
    }
  }

  if (!scanId) return <Navigate to="/" replace />

  if (loading && !results) {
    return (
      <div className="workspace-page">
        <div className="workspace-loading">
          <BrandLogo animated />
          <div className="workspace-loading__title">Loading scan workspace</div>
          <div className="workspace-loading__subtitle">Fetching the latest results for scan {scanId.slice(0, 8)}.</div>
        </div>
      </div>
    )
  }

  if (error && !results) {
    return (
      <div className="workspace-page">
        <div className="workspace-loading">
          <div className="workspace-loading__title">Scan unavailable</div>
          <div className="workspace-loading__subtitle">{error}</div>
          <button type="button" className="button" onClick={() => navigate('/')}>Back home</button>
        </div>
      </div>
    )
  }

  if (!results) return null

  const info = results.app_info || {}
  const score = results.score || {}
  // Always derive severity summary from the findings array so the dashboard
  // cards can never disagree with the findings list (fixes "1 critical vs 28
  // total" mismatch when backend blob had stale or mixed-case counts).
  const summary = deriveSeveritySummary(results.findings || [])
  const sectionMeta = {
    ...(SECTION_MAP[resolvedSectionId] || SECTION_MAP.dashboard),
    label: SECTION_LABEL_OVERRIDES[resolvedSectionId] || SECTION_MAP[resolvedSectionId]?.label || SECTION_MAP.dashboard.label,
  }
  const summaryChips = [
    (results.decompile_info?.tools_used || []).length ? `${results.decompile_info.tools_used.join(' + ')} ready` : null,
    counts.findings ? `${counts.findings} findings` : null,
    counts.endpoints ? `${counts.endpoints} endpoints` : null,
  ].filter(Boolean)
  const severityBoxes = SEVERITY_ORDER.filter(key => (summary[key] || 0) > 0)
  const sectionDescription = SECTION_COPY[resolvedSectionId] || sectionMeta.hint

  const workspaceActions = {
    onHome: () => navigate('/'),
    onExport: () => setExportOpen(true),
    onSbom: handleSbomDownload,
    onSarif: handleSarifDownload,
    onCiGate: () => setGateOpen(true),
    onSignOut: () => { clearAuth(); window.location.href = '/login' },
    user: getToken() ? (getUser()?.username ?? 'Sign out') : '',
  }

  return (
    <>
      <Workspace results={results} scanId={scanId} onOpenCode={openCode} actions={workspaceActions} />
      <WorkspaceCodeModal
        state={codeState}
        onClose={() => setCodeState(state => ({ ...state, open: false }))}
        onNavigate={i => {
          const ev = (codeState.evidence || [])[i]
          if (!ev) return
          openCode(ev.path, ev.lines, {
            snippet: ev.snippet, source: ev.source, approximate: ev.approximate,
            highlightLine: ev.highlightLine, className: ev.className, methodName: ev.methodName,
            titleKeywords: ev.titleKeywords, evidence: codeState.evidence, index: i,
          })
        }}
      />
      {exportOpen ? <ExportModal results={results} onClose={() => setExportOpen(false)} /> : null}
      {gateOpen   ? <CiGateModal results={results} onClose={() => setGateOpen(false)}   /> : null}
    </>
  )
}

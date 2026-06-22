// Phase 11.99 — Scan History workspace page. Reads the persistent server-side
// history (/api/scans/history) with search, sort and pagination; supports open,
// delete, per-scan report export, and full workspace export/import.
import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ChevronLeft, Search, Trash2, FileDown, Download, Upload, RefreshCw,
  ArrowUp, ArrowDown, Eraser,
} from 'lucide-react'
import BrandLogo from '../components/BrandLogo.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import Footer from '../components/Footer.jsx'
import { apiFetch, isAdmin } from '../lib/auth.js'
import { formatTimestamp, getGradeMeta, getPlatformCode } from '../lib/scan-data.js'

const PAGE_SIZE = 15
const SORTS = [
  { id: 'created_at', label: 'Date' },
  { id: 'app_name', label: 'App' },
  { id: 'score', label: 'Risk' },
  { id: 'trust', label: 'Trust' },
  { id: 'findings', label: 'Findings' },
]

function rowSeverity(r) {
  if ((r.s_critical || 0) > 0) return 'critical'
  if ((r.s_high || 0) > 0) return 'high'
  if ((r.s_medium || 0) > 0) return 'medium'
  if ((r.s_low || 0) > 0) return 'low'
  return 'info'
}

export default function History() {
  const navigate = useNavigate()
  const [items, setItems] = useState([])
  const [total, setTotal] = useState(0)
  const [search, setSearch] = useState('')
  const [sort, setSort] = useState('created_at')
  const [order, setOrder] = useState('desc')
  const [offset, setOffset] = useState(0)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState('')
  const fileRef = useRef(null)

  const load = useCallback(() => {
    setLoading(true)
    const q = new URLSearchParams({ limit: PAGE_SIZE, offset, search, sort, order })
    apiFetch(`/api/scans/history?${q}`)
      .then(r => (r.ok ? r.json() : { items: [], total: 0 }))
      .then(d => { setItems(d.items || []); setTotal(d.total || 0) })
      .catch(() => { setItems([]); setTotal(0) })
      .finally(() => setLoading(false))
  }, [offset, search, sort, order])

  useEffect(() => { load() }, [load])
  // Reset to first page when the query changes.
  useEffect(() => { setOffset(0) }, [search, sort, order])

  const openScan = id => navigate(`/scans/${id}/dashboard`)

  const deleteScan = async (id, e) => {
    e.stopPropagation()
    if (!window.confirm('Delete this scan and its stored results?')) return
    setBusy(id)
    try {
      await apiFetch(`/api/scans/${id}`, { method: 'DELETE' })
      load()
    } finally { setBusy('') }
  }

  const exportReport = async (id, e) => {
    e.stopPropagation()
    setBusy(id)
    try {
      const res = await apiFetch(`/api/scans/${id}`)
      if (!res.ok) return
      const results = await res.json()
      const rep = await apiFetch('/api/report', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ results }),
      })
      if (!rep.ok) return
      downloadBlob(await rep.blob(), `beetle_${results.app_name || id}.pdf`)
    } finally { setBusy('') }
  }

  const exportWorkspace = async () => {
    setBusy('workspace')
    try {
      const res = await apiFetch('/api/scans/export', { method: 'POST' })
      if (res.ok) downloadBlob(await res.blob(), 'workspace.zip')
    } finally { setBusy('') }
  }

  const importWorkspace = async e => {
    const f = e.target.files?.[0]
    if (!f) return
    setBusy('workspace')
    try {
      const fd = new FormData()
      fd.append('file', f)
      await apiFetch('/api/scans/import', { method: 'POST', body: fd })
      load()
    } finally { setBusy(''); if (fileRef.current) fileRef.current.value = '' }
  }

  const page = Math.floor(offset / PAGE_SIZE) + 1
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  return (
    <div className="workspace-page">
      <div className="history-page">
        <header className="history-page__top">
          <button type="button" className="button button--ghost" onClick={() => navigate('/')}>
            <ChevronLeft size={15} /> Home
          </button>
          <BrandLogo />
          <div className="history-page__top-actions">
            <button type="button" className="button button--ghost" onClick={load} title="Refresh"><RefreshCw size={14} /></button>
            <button type="button" className="button button--ghost" disabled={busy === 'workspace'} onClick={exportWorkspace}>
              <Download size={14} /> Export workspace
            </button>
            {isAdmin() ? (
              <>
                <button type="button" className="button button--ghost" disabled={busy === 'workspace'} onClick={() => fileRef.current?.click()}>
                  <Upload size={14} /> Import
                </button>
                <input ref={fileRef} type="file" accept=".zip" style={{ display: 'none' }} onChange={importWorkspace} />
              </>
            ) : null}
          </div>
        </header>

        <h1 className="history-page__title">Scan History</h1>
        <p className="history-page__subtitle">{total} persisted scan{total !== 1 ? 's' : ''} — survives backend restarts.</p>

        <div className="history-toolbar">
          <div className="history-search">
            <Search size={15} />
            <input placeholder="Search app, package, file…" value={search} onChange={e => setSearch(e.target.value)} />
          </div>
          <div className="history-sorts">
            {SORTS.map(s => (
              <button key={s.id} type="button"
                className={`history-chip${sort === s.id ? ' is-active' : ''}`}
                onClick={() => sort === s.id ? setOrder(o => (o === 'desc' ? 'asc' : 'desc')) : setSort(s.id)}>
                {s.label}{sort === s.id ? (order === 'desc' ? <ArrowDown size={12} /> : <ArrowUp size={12} />) : null}
              </button>
            ))}
          </div>
        </div>

        <div className="history-table">
          <div className="history-row history-row--head">
            <span>App</span><span>Package</span><span>Date</span><span>Risk</span>
            <span>Trust</span><span>Findings</span><span>Status</span><span>Actions</span>
          </div>
          {loading ? (
            <div className="history-empty">Loading…</div>
          ) : items.length ? items.map(r => {
            const grade = getGradeMeta(r.grade)
            const broken = r.status === 'BROKEN'
            return (
              <div key={r.scan_id} className={`history-row${broken ? ' history-row--broken' : ''}`}
                role="button" tabIndex={0} onClick={() => !broken && openScan(r.scan_id)}
                onKeyDown={e => { if ((e.key === 'Enter') && !broken) openScan(r.scan_id) }}>
                <span className="history-app">
                  {r.icon_data ? <img src={r.icon_data} alt="" /> : <i>{(r.app_name || '?')[0].toUpperCase()}</i>}
                  <b>{r.app_name || r.filename || 'Untitled'}</b>
                </span>
                <span className="history-mono" title={r.package}>{r.package || '—'}</span>
                <span>{formatTimestamp(r.completed_at || r.created_at || r.scan_time)}</span>
                <span style={{ color: grade.color, fontWeight: 700 }}>{r.grade || '—'}{r.score != null ? ` · ${r.score}` : ''}</span>
                <span>{r.trust_score != null ? r.trust_score : '—'}</span>
                <span><SeverityBadge severity={rowSeverity(r)} compact /> {r.findings_count ?? 0}</span>
                <span className={`history-status history-status--${(r.status || 'completed').toLowerCase()}`}>{r.status || 'completed'}</span>
                <span className="history-actions" onClick={e => e.stopPropagation()}>
                  <button type="button" title="Export report" disabled={busy === r.scan_id || broken} onClick={e => exportReport(r.scan_id, e)}><FileDown size={14} /></button>
                  <button type="button" title="Delete scan" disabled={busy === r.scan_id} onClick={e => deleteScan(r.scan_id, e)}><Trash2 size={14} /></button>
                </span>
              </div>
            )
          }) : (
            <div className="history-empty"><Eraser size={18} /> No scans match.</div>
          )}
        </div>

        {pages > 1 ? (
          <div className="history-pager">
            <button type="button" className="button button--ghost" disabled={offset === 0} onClick={() => setOffset(o => Math.max(0, o - PAGE_SIZE))}>Prev</button>
            <span>Page {page} / {pages}</span>
            <button type="button" className="button button--ghost" disabled={page >= pages} onClick={() => setOffset(o => o + PAGE_SIZE)}>Next</button>
          </div>
        ) : null}
      </div>
      <Footer />
    </div>
  )
}

function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

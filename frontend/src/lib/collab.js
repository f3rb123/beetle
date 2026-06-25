// Collaboration client — finding states, assignment, comments, suppression,
// sharing. Talks to the app-keyed backend so everything survives a rescan.
import { useCallback, useEffect, useState } from 'react'
import { apiFetch, getUser } from './auth.js'

// Stable finding identity — MUST match backend collaboration.finding_key and the
// legacy _triageKey: rule_id if present, else a slug of the title.
export function findingKey(f) {
  return (f.rule_id || '').trim() ||
    (f.title || '').trim().replace(/\s+/g, '_').slice(0, 80) || 'unknown'
}

// The six formal finding states (label + dot colour for badges).
export const FINDING_STATES = [
  { id: 'open',           label: 'Open',           color: '#9ca3af' },
  { id: 'confirmed',      label: 'Confirmed',      color: '#dc2626' },
  { id: 'need_review',    label: 'Need Review',    color: '#f59e0b' },
  { id: 'mitigated',      label: 'Mitigated',      color: '#10b981' },
  { id: 'accepted_risk',  label: 'Accepted Risk',  color: '#6366f1' },
  { id: 'false_positive', label: 'False Positive', color: '#9ca3af' },
]
export const STATE_META = Object.fromEntries(FINDING_STATES.map(s => [s.id, s]))
export const PRIORITIES = ['P1', 'P2', 'P3', 'P4']
export const SHARE_MODES = [
  { id: 'private', label: 'Private', hint: 'Only the owner and managers can view.' },
  { id: 'shared',  label: 'Shared',  hint: 'Any signed-in user with the link can view.' },
  { id: 'team',    label: 'Team',    hint: 'Visible to the whole team.' },
]

export function canWrite()  { return (getUser()?.role || 'analyst') !== 'readonly' }
export function canManage() { return ['admin', 'manager'].includes(getUser()?.role) }

// Minimal, safe markdown → HTML for comment bodies. Escapes first, then applies
// a small whitelist: **bold**, *italic*, `code`, [text](http…link), line breaks.
export function renderMarkdown(src = '') {
  const esc = src
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  return esc
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*]+)\*/g, '<em>$1</em>')
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g,
      '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>')
    .replace(/\n/g, '<br/>')
}

// ── Per-scan collaboration state hook ────────────────────────────────────────
export function useCollab(scanId) {
  const [data, setData] = useState({ meta: {}, comments: {}, suppressions: [], share: { share_mode: 'team' } })
  const [loading, setLoading] = useState(true)

  const reload = useCallback(() => {
    if (!scanId) return
    apiFetch(`/api/scans/${scanId}/collab`)
      .then(r => (r.ok ? r.json() : null))
      .then(d => { if (d) setData(d) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [scanId])

  useEffect(() => { reload() }, [reload])

  const setState = useCallback(async (f, state) => {
    const key = findingKey(f)
    const r = await apiFetch(`/api/scans/${scanId}/findings/${encodeURIComponent(key)}/state`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ state }),
    })
    if (r.ok) setData(d => ({ ...d, meta: { ...d.meta, [key]: { ...(d.meta[key] || {}), state } } }))
    return r.ok
  }, [scanId])

  const assign = useCallback(async (f, { assignee, priority }) => {
    const key = findingKey(f)
    const r = await apiFetch(`/api/scans/${scanId}/findings/${encodeURIComponent(key)}/assign`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assignee, priority }),
    })
    if (r.ok) {
      const next = await r.json()
      setData(d => ({ ...d, meta: { ...d.meta, [key]: { ...(d.meta[key] || {}), ...next } } }))
    }
    return r.ok
  }, [scanId])

  const addComment = useCallback(async (f, body) => {
    const key = findingKey(f)
    const r = await apiFetch(`/api/scans/${scanId}/findings/${encodeURIComponent(key)}/comments`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ body }),
    })
    if (!r.ok) return false
    const c = await r.json()
    setData(d => ({ ...d, comments: { ...d.comments, [key]: [...(d.comments[key] || []), c] } }))
    return true
  }, [scanId])

  const suppress = useCallback(async ({ rule_id, file_pattern, reason }) => {
    const r = await apiFetch('/api/suppressions', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_id: scanId, rule_id, file_pattern, reason }),
    })
    if (r.ok) reload()
    return r.ok
  }, [scanId, reload])

  const unsuppress = useCallback(async (id) => {
    const r = await apiFetch(`/api/suppressions/${id}`, { method: 'DELETE' })
    if (r.ok) reload()
    return r.ok
  }, [reload])

  const setShare = useCallback(async (mode) => {
    const r = await apiFetch(`/api/scans/${scanId}/share`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ share_mode: mode }),
    })
    if (r.ok) setData(d => ({ ...d, share: { ...d.share, share_mode: mode } }))
    return r.ok
  }, [scanId])

  return { collab: data, loading, reload, setState, assign, addComment, suppress, unsuppress, setShare }
}

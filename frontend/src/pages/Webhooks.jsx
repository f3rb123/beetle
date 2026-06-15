import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ChevronLeft, ChevronDown, ChevronRight, Plus, Trash2, Zap } from 'lucide-react'
import { apiFetch } from '../lib/auth.js'

const EVENT_OPTIONS = [
  { id: 'scan.completed', label: 'Scan completed' },
  { id: 'scan.failed',    label: 'Scan failed' },
]

const TYPE_OPTIONS = [
  { id: 'generic', label: 'Generic HTTP POST' },
  { id: 'slack',   label: 'Slack Incoming Webhook' },
]

function StatusDot({ status }) {
  if (!status) return <span className="wh-status wh-status--none">—</span>
  if (status === 'ok') return <span className="wh-status wh-status--ok">OK</span>
  return <span className="wh-status wh-status--error" title={status}>Error</span>
}

function WebhookRow({ wh, onDelete, onToggle, onTest }) {
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState('')

  const handleTest = async () => {
    setTesting(true)
    setTestResult('')
    try {
      const res = await apiFetch(`/api/webhooks/${wh.id}/test`, { method: 'POST' })
      const data = await res.json()
      setTestResult(res.ok ? 'Delivered' : data.detail || 'Failed')
    } catch {
      setTestResult('Network error')
    } finally {
      setTesting(false)
    }
  }

  return (
    <div className="wh-row">
      <div className="wh-row__main">
        <div className="wh-row__info">
          <div className="wh-row__label">
            {wh.label || <em>Unlabeled</em>}
            <span className={`wh-type-badge wh-type-badge--${wh.type}`}>{wh.type}</span>
            {!wh.active && <span className="wh-type-badge wh-type-badge--disabled">disabled</span>}
          </div>
          <div className="wh-row__url">{wh.url}</div>
          <div className="wh-row__meta">
            Events: {wh.events.join(', ')} · Last: <StatusDot status={wh.last_status} />
            {wh.last_fired && <> · {wh.last_fired.slice(0, 16).replace('T', ' ')} UTC</>}
          </div>
        </div>
        <div className="wh-row__actions">
          <button
            type="button"
            className="wh-action-btn"
            onClick={handleTest}
            disabled={testing}
            title="Send test payload"
          >
            <Zap size={14} />
            {testing ? 'Sending…' : 'Test'}
          </button>
          <button
            type="button"
            className="wh-action-btn"
            onClick={() => onToggle(wh.id, !wh.active)}
            title={wh.active ? 'Disable' : 'Enable'}
          >
            {wh.active ? 'Disable' : 'Enable'}
          </button>
          <button
            type="button"
            className="wh-action-btn wh-action-btn--danger"
            onClick={() => onDelete(wh.id)}
            title="Delete webhook"
          >
            <Trash2 size={14} />
          </button>
        </div>
      </div>
      {testResult && (
        <div className={`wh-test-result ${testResult === 'Delivered' ? 'wh-test-result--ok' : 'wh-test-result--err'}`}>
          {testResult}
        </div>
      )}
    </div>
  )
}

function AddWebhookForm({ onAdded }) {
  const [label,  setLabel]  = useState('')
  const [url,    setUrl]    = useState('')
  const [type,   setType]   = useState('generic')
  const [events, setEvents] = useState(['scan.completed'])
  const [secret, setSecret] = useState('')
  const [error,  setError]  = useState('')
  const [saving, setSaving] = useState(false)

  const toggleEvent = id => {
    setEvents(prev =>
      prev.includes(id) ? prev.filter(e => e !== id) : [...prev, id]
    )
  }

  const handleSubmit = async e => {
    e.preventDefault()
    if (!url.trim()) { setError('URL is required'); return }
    if (events.length === 0) { setError('Select at least one event'); return }
    setSaving(true)
    setError('')
    try {
      const res = await apiFetch('/api/webhooks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label: label.trim(), url: url.trim(), type, events, secret: secret.trim() }),
      })
      if (!res.ok) {
        const d = await res.json().catch(() => ({}))
        setError(d.detail || 'Failed to create webhook')
        return
      }
      const wh = await res.json()
      onAdded(wh)
      setLabel(''); setUrl(''); setType('generic'); setEvents(['scan.completed']); setSecret('')
    } catch {
      setError('Network error')
    } finally {
      setSaving(false)
    }
  }

  return (
    <form className="wh-form" onSubmit={handleSubmit}>
      <div className="wh-form__title">Add webhook</div>

      <div className="wh-form__row">
        <div className="wh-form__field">
          <label className="wh-form__label">Label</label>
          <input className="wh-form__input" value={label} onChange={e => setLabel(e.target.value)} placeholder="e.g. Slack #security" />
        </div>
        <div className="wh-form__field wh-form__field--type">
          <label className="wh-form__label">Type</label>
          <select className="wh-form__input" value={type} onChange={e => setType(e.target.value)}>
            {TYPE_OPTIONS.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
          </select>
        </div>
      </div>

      <div className="wh-form__field">
        <label className="wh-form__label">URL *</label>
        <input
          className="wh-form__input"
          value={url}
          onChange={e => setUrl(e.target.value)}
          placeholder={type === 'slack' ? 'https://hooks.slack.com/services/…' : 'https://your-server.com/hook'}
          required
        />
      </div>

      <div className="wh-form__field">
        <label className="wh-form__label">Events</label>
        <div className="wh-form__checkboxes">
          {EVENT_OPTIONS.map(ev => (
            <label key={ev.id} className="wh-form__checkbox">
              <input
                type="checkbox"
                checked={events.includes(ev.id)}
                onChange={() => toggleEvent(ev.id)}
              />
              {ev.label}
            </label>
          ))}
        </div>
      </div>

      <div className="wh-form__field">
        <label className="wh-form__label">Secret (optional — sent as X-Cortex-Signature HMAC-SHA256)</label>
        <input className="wh-form__input" value={secret} onChange={e => setSecret(e.target.value)} type="password" placeholder="Leave blank to skip signing" />
      </div>

      {error && <div className="wh-form__error">{error}</div>}

      <div className="wh-form__footer">
        <button type="submit" className="button" disabled={saving}>
          {saving ? 'Saving…' : 'Add webhook'}
        </button>
      </div>
    </form>
  )
}

const AUDIT_EVENT_COLORS = {
  'auth.login':        '#10b981',
  'auth.login.fail':   '#ef4444',
  'scan.started':      '#3b82f6',
  'scan.completed':    '#10b981',
  'scan.deleted':      '#f59e0b',
  'triage.set':        '#6366f1',
  'policy.updated':    '#f97316',
  'user.created':      '#8b5cf6',
  'auth.key_created':  '#06b6d4',
  'auth.key_revoked':  '#f59e0b',
}

function AuditLog() {
  const [open, setOpen]         = useState(false)
  const [entries, setEntries]   = useState([])
  const [loading, setLoading]   = useState(false)
  const [eventFilter, setEventFilter] = useState('')

  const load = async () => {
    setLoading(true)
    try {
      const res  = await apiFetch(`/api/audit?limit=200${eventFilter ? `&event=${encodeURIComponent(eventFilter)}` : ''}`)
      const data = await res.json()
      setEntries(data.entries || [])
    } catch { /* noop */ }
    finally { setLoading(false) }
  }

  useEffect(() => { if (open) load() }, [open, eventFilter])

  return (
    <div className="audit-section">
      <button
        type="button"
        className="audit-toggle"
        onClick={() => setOpen(o => !o)}
      >
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        Audit Log
        {entries.length > 0 && !loading && (
          <span className="audit-count">{entries.length}</span>
        )}
      </button>

      {open && (
        <div className="audit-body">
          <div className="audit-filters">
            <input
              className="audit-filter-input"
              placeholder="Filter by event (e.g. auth, scan)"
              value={eventFilter}
              onChange={e => setEventFilter(e.target.value)}
            />
            <button type="button" className="audit-refresh-btn" onClick={load} disabled={loading}>
              {loading ? 'Loading…' : 'Refresh'}
            </button>
          </div>

          {entries.length === 0 && !loading && (
            <div className="audit-empty">No audit entries found.</div>
          )}

          <div className="audit-table-wrap">
            <table className="audit-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Event</th>
                  <th>Actor</th>
                  <th>Scan</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {entries.map(e => (
                  <tr key={e.id}>
                    <td className="audit-td-time">{e.created_at?.slice(0, 19).replace('T', ' ')}</td>
                    <td>
                      <span
                        className="audit-event-badge"
                        style={{ background: `${AUDIT_EVENT_COLORS[e.event] || '#6b7280'}18`, color: AUDIT_EVENT_COLORS[e.event] || '#6b7280' }}
                      >
                        {e.event}
                      </span>
                    </td>
                    <td className="audit-td-actor">{e.actor || '—'}</td>
                    <td className="audit-td-scan">{e.scan_id ? e.scan_id.slice(0, 8) : '—'}</td>
                    <td className="audit-td-detail">
                      {e.detail && Object.keys(e.detail).length > 0
                        ? Object.entries(e.detail).map(([k, v]) => `${k}: ${v}`).join(' · ')
                        : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

export default function Webhooks() {
  const navigate   = useNavigate()
  const [webhooks, setWebhooks] = useState([])
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState('')

  const load = async () => {
    setLoading(true)
    try {
      const res = await apiFetch('/api/webhooks')
      if (res.status === 403) { setError('Admin role required'); setLoading(false); return }
      if (!res.ok) { setError('Failed to load webhooks'); setLoading(false); return }
      setWebhooks(await res.json())
    } catch {
      setError('Network error')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const handleAdded = wh => setWebhooks(prev => [...prev, wh])

  const handleDelete = async id => {
    await apiFetch(`/api/webhooks/${id}`, { method: 'DELETE' })
    setWebhooks(prev => prev.filter(w => w.id !== id))
  }

  const handleToggle = async (id, active) => {
    const res = await apiFetch(`/api/webhooks/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ active: active ? 1 : 0 }),
    })
    if (res.ok) {
      const updated = await res.json()
      setWebhooks(prev => prev.map(w => w.id === id ? updated : w))
    }
  }

  return (
    <div className="settings-page">
      <div className="settings-shell">
        <header className="settings-header">
          <button type="button" className="settings-back" onClick={() => navigate('/')}>
            <ChevronLeft size={14} /> Home
          </button>
          <h1 className="settings-title">Webhooks</h1>
          <p className="settings-subtitle">
            Receive HTTP notifications when scans complete or fail.
          </p>
        </header>

        {error && <div className="settings-error">{error}</div>}

        {loading ? (
          <div className="settings-loading">Loading…</div>
        ) : (
          <>
            {webhooks.length > 0 && (
              <div className="wh-list">
                {webhooks.map(wh => (
                  <WebhookRow
                    key={wh.id}
                    wh={wh}
                    onDelete={handleDelete}
                    onToggle={handleToggle}
                    onTest={() => {}}
                  />
                ))}
              </div>
            )}

            <AddWebhookForm onAdded={handleAdded} />
            <AuditLog />
          </>
        )}
      </div>
    </div>
  )
}

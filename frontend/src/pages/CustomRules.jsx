import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ChevronLeft, Plus, Trash2, Pencil, Check, X } from 'lucide-react'
import { apiFetch } from '../lib/auth.js'

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'info']
const PLATFORM_OPTIONS = ['both', 'android', 'ios']

const SEV_COLORS = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#f59e0b',
  low:      '#3b82f6',
  info:     '#6b7280',
}

function SevBadge({ severity }) {
  const color = SEV_COLORS[severity] || '#6b7280'
  return (
    <span className="cr-sev-badge" style={{ background: `${color}18`, color }}>
      {severity}
    </span>
  )
}

const BLANK_FORM = {
  rule_id: '', title: '', pattern: '', severity: 'medium',
  platform: 'both', category: '', cwe: '', masvs: '', owasp: '',
  description: '', recommendation: '',
}

function RuleForm({ initial, onSave, onCancel, saving, error }) {
  const [form, setForm] = useState(initial || BLANK_FORM)
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  return (
    <div className="cr-form">
      <div className="cr-form__grid">
        <div className="cr-form__field cr-form__field--full">
          <label className="cr-form__label">Title *</label>
          <input className="cr-form__input" value={form.title} onChange={e => set('title', e.target.value)} placeholder="e.g. Hardcoded JWT secret" />
        </div>

        <div className="cr-form__field cr-form__field--full">
          <label className="cr-form__label">Regex pattern *</label>
          <input className="cr-form__input cr-form__input--mono" value={form.pattern} onChange={e => set('pattern', e.target.value)} placeholder='e.g. (?i)jwt\s*=\s*["\x27][A-Za-z0-9._-]{20,}' />
        </div>

        <div className="cr-form__field">
          <label className="cr-form__label">Severity</label>
          <select className="cr-form__input" value={form.severity} onChange={e => set('severity', e.target.value)}>
            {SEVERITY_OPTIONS.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>

        <div className="cr-form__field">
          <label className="cr-form__label">Platform</label>
          <select className="cr-form__input" value={form.platform} onChange={e => set('platform', e.target.value)}>
            {PLATFORM_OPTIONS.map(p => <option key={p} value={p}>{p}</option>)}
          </select>
        </div>

        <div className="cr-form__field">
          <label className="cr-form__label">Category</label>
          <input className="cr-form__input" value={form.category} onChange={e => set('category', e.target.value)} placeholder="e.g. Secrets Detection" />
        </div>

        <div className="cr-form__field">
          <label className="cr-form__label">Rule ID (auto-generated if blank)</label>
          <input className="cr-form__input cr-form__input--mono" value={form.rule_id} onChange={e => set('rule_id', e.target.value)} placeholder="e.g. custom_jwt_leak" />
        </div>

        <div className="cr-form__field">
          <label className="cr-form__label">CWE</label>
          <input className="cr-form__input" value={form.cwe} onChange={e => set('cwe', e.target.value)} placeholder="e.g. CWE-312" />
        </div>

        <div className="cr-form__field">
          <label className="cr-form__label">MASVS</label>
          <input className="cr-form__input" value={form.masvs} onChange={e => set('masvs', e.target.value)} placeholder="e.g. MASVS-CODE-4" />
        </div>

        <div className="cr-form__field">
          <label className="cr-form__label">OWASP</label>
          <input className="cr-form__input" value={form.owasp} onChange={e => set('owasp', e.target.value)} placeholder="e.g. M9" />
        </div>

        <div className="cr-form__field cr-form__field--full">
          <label className="cr-form__label">Description</label>
          <textarea className="cr-form__input cr-form__textarea" value={form.description} onChange={e => set('description', e.target.value)} rows={2} placeholder="Explain what this rule detects" />
        </div>

        <div className="cr-form__field cr-form__field--full">
          <label className="cr-form__label">Recommendation</label>
          <textarea className="cr-form__input cr-form__textarea" value={form.recommendation} onChange={e => set('recommendation', e.target.value)} rows={2} placeholder="How to fix this issue" />
        </div>
      </div>

      {error && <div className="cr-form__error">{error}</div>}

      <div className="cr-form__footer">
        <button type="button" className="button" onClick={() => onSave(form)} disabled={saving}>
          {saving ? 'Saving…' : 'Save rule'}
        </button>
        <button type="button" className="cr-form__cancel" onClick={onCancel}>Cancel</button>
      </div>
    </div>
  )
}

function RuleRow({ rule, onDelete, onToggle, onEdit }) {
  return (
    <div className={`cr-row ${!rule.enabled ? 'cr-row--disabled' : ''}`}>
      <div className="cr-row__main">
        <div className="cr-row__top">
          <span className="cr-row__title">{rule.title}</span>
          <SevBadge severity={rule.severity} />
          <span className="cr-plat-badge">{rule.platform}</span>
          {rule.category && <span className="cr-cat-badge">{rule.category}</span>}
          {!rule.enabled && <span className="cr-disabled-badge">disabled</span>}
        </div>
        <div className="cr-row__pattern">{rule.pattern}</div>
        <div className="cr-row__meta">
          <span className="cr-row__id">{rule.rule_id}</span>
          {rule.cwe && <span>· {rule.cwe}</span>}
          {rule.masvs && <span>· {rule.masvs}</span>}
          {rule.owasp && <span>· {rule.owasp}</span>}
          {rule.created_by && <span>· by {rule.created_by}</span>}
        </div>
      </div>
      <div className="cr-row__actions">
        <button type="button" className="cr-action-btn" onClick={() => onEdit(rule)} title="Edit">
          <Pencil size={13} />
        </button>
        <button type="button" className="cr-action-btn" onClick={() => onToggle(rule.rule_id, !rule.enabled)} title={rule.enabled ? 'Disable' : 'Enable'}>
          {rule.enabled ? <X size={13} /> : <Check size={13} />}
          {rule.enabled ? 'Disable' : 'Enable'}
        </button>
        <button type="button" className="cr-action-btn cr-action-btn--danger" onClick={() => onDelete(rule.rule_id)} title="Delete">
          <Trash2 size={13} />
        </button>
      </div>
    </div>
  )
}

export default function CustomRules() {
  const navigate = useNavigate()
  const [rules, setRules] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [showForm, setShowForm] = useState(false)
  const [editRule, setEditRule] = useState(null)
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState('')

  const load = async () => {
    setLoading(true)
    try {
      const res = await apiFetch('/api/rules')
      if (res.status === 403) { setError('Admin role required'); setLoading(false); return }
      if (!res.ok) { setError('Failed to load rules'); setLoading(false); return }
      setRules(await res.json())
    } catch { setError('Network error') }
    finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  const handleSave = async (form) => {
    if (!form.title.trim()) { setFormError('Title is required'); return }
    if (!form.pattern.trim()) { setFormError('Pattern is required'); return }
    setSaving(true)
    setFormError('')
    try {
      let res
      if (editRule) {
        res = await apiFetch(`/api/rules/${editRule.rule_id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(form),
        })
      } else {
        res = await apiFetch('/api/rules', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(form),
        })
      }
      if (!res.ok) {
        const d = await res.json().catch(() => ({}))
        setFormError(d.detail || 'Failed to save rule')
        return
      }
      const saved = await res.json()
      if (editRule) {
        setRules(prev => prev.map(r => r.rule_id === editRule.rule_id ? saved : r))
      } else {
        setRules(prev => [...prev, saved])
      }
      setShowForm(false)
      setEditRule(null)
    } catch { setFormError('Network error') }
    finally { setSaving(false) }
  }

  const handleDelete = async (ruleId) => {
    await apiFetch(`/api/rules/${ruleId}`, { method: 'DELETE' })
    setRules(prev => prev.filter(r => r.rule_id !== ruleId))
  }

  const handleToggle = async (ruleId, enabled) => {
    const res = await apiFetch(`/api/rules/${ruleId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    })
    if (res.ok) {
      const updated = await res.json()
      setRules(prev => prev.map(r => r.rule_id === ruleId ? updated : r))
    }
  }

  const handleEdit = (rule) => {
    setEditRule(rule)
    setShowForm(true)
    setFormError('')
  }

  const handleAddNew = () => {
    setEditRule(null)
    setShowForm(true)
    setFormError('')
  }

  const handleCancel = () => {
    setShowForm(false)
    setEditRule(null)
    setFormError('')
  }

  return (
    <div className="settings-page">
      <div className="settings-shell">
        <header className="settings-header">
          <button type="button" className="settings-back" onClick={() => navigate('/')}>
            <ChevronLeft size={14} /> Home
          </button>
          <h1 className="settings-title">Custom SAST Rules</h1>
          <p className="settings-subtitle">
            Define custom regex patterns that run alongside the built-in rule set during every scan.
          </p>
        </header>

        {error && <div className="settings-error">{error}</div>}

        {!error && (
          <div className="cr-toolbar">
            <span className="cr-toolbar__count">{rules.length} rule{rules.length !== 1 ? 's' : ''}</span>
            {!showForm && (
              <button type="button" className="button cr-add-btn" onClick={handleAddNew}>
                <Plus size={14} /> Add rule
              </button>
            )}
          </div>
        )}

        {showForm && (
          <RuleForm
            initial={editRule}
            onSave={handleSave}
            onCancel={handleCancel}
            saving={saving}
            error={formError}
          />
        )}

        {loading ? (
          <div className="settings-loading">Loading…</div>
        ) : (
          <div className="cr-list">
            {rules.length === 0 && !showForm && (
              <div className="cr-empty">
                No custom rules yet. Add one above to extend the built-in SAST engine.
              </div>
            )}
            {rules.map(rule => (
              <RuleRow
                key={rule.rule_id}
                rule={rule}
                onDelete={handleDelete}
                onToggle={handleToggle}
                onEdit={handleEdit}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

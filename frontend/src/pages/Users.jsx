import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ChevronLeft, Plus, UserCog } from 'lucide-react'
import { apiFetch } from '../lib/auth.js'

// Roles mirror backend auth.VALID_ROLES (highest → lowest privilege).
const ROLES = [
  { id: 'admin',    label: 'Admin',     hint: 'Full control, incl. user management' },
  { id: 'manager',  label: 'Manager',   hint: 'Manage suppressions, sharing, assignments' },
  { id: 'analyst',  label: 'Analyst',   hint: 'Triage, comment, assign, suppress' },
  { id: 'readonly', label: 'Read-only', hint: 'View only — no changes' },
]
const ROLE_LABEL = Object.fromEntries(ROLES.map(r => [r.id, r.label]))

function AddUserForm({ onAdded }) {
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('analyst')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async e => {
    e.preventDefault()
    setErr(''); setBusy(true)
    try {
      const res = await apiFetch('/api/users', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password, role }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) { setErr(data.detail || 'Failed to create user'); return }
      onAdded(data)
      setUsername(''); setEmail(''); setPassword(''); setRole('analyst')
    } catch {
      setErr('Network error')
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="up-card up-form" onSubmit={submit}>
      <h2 className="up-form__title"><Plus size={15} /> Add user</h2>
      {err && <div className="up-error">{err}</div>}
      <div className="up-form__grid">
        <label className="up-field">
          <span className="up-field__label">Username</span>
          <input className="up-input" value={username} onChange={e => setUsername(e.target.value)} required minLength={3} />
        </label>
        <label className="up-field">
          <span className="up-field__label">Email</span>
          <input className="up-input" type="email" value={email} onChange={e => setEmail(e.target.value)} />
        </label>
        <label className="up-field">
          <span className="up-field__label">Password</span>
          <input className="up-input" type="password" value={password} onChange={e => setPassword(e.target.value)} required minLength={8} />
        </label>
        <label className="up-field">
          <span className="up-field__label">Role</span>
          <select className="up-input" value={role} onChange={e => setRole(e.target.value)}>
            {ROLES.map(r => <option key={r.id} value={r.id}>{r.label} — {r.hint}</option>)}
          </select>
        </label>
      </div>
      <div className="up-form__footer">
        <button type="submit" className="up-btn-primary" disabled={busy}>{busy ? 'Creating…' : 'Create user'}</button>
      </div>
    </form>
  )
}

export default function Users() {
  const navigate = useNavigate()
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = async () => {
    setLoading(true)
    try {
      const res = await apiFetch('/api/users')
      if (res.status === 403) { setError('Admin role required'); return }
      if (!res.ok) { setError('Failed to load users'); return }
      setUsers(await res.json())
    } catch {
      setError('Network error')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const toggleActive = async (u) => {
    const res = await apiFetch(`/api/users/${encodeURIComponent(u.username)}/active`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ active: u.active ? 0 : 1 }),
    })
    if (res.ok) load()
  }

  const fmtDate = v => (v ? v.slice(0, 16).replace('T', ' ') : '—')

  return (
    <div className="login-page login-page--workspace">
      <div className="up-shell">
        <header className="up-head">
          <button type="button" className="up-back" onClick={() => navigate('/')}>
            <ChevronLeft size={14} /> Home
          </button>
          <h1 className="up-title"><UserCog size={20} /> Users &amp; Roles</h1>
          <p className="up-subtitle">Manage workspace members and their access level.</p>
        </header>

        {error && <div className="up-error">{error}</div>}

        {loading ? (
          <div className="up-loading">Loading…</div>
        ) : (
          <>
            <AddUserForm onAdded={() => load()} />

            {users.length > 0 && (
              <div className="up-grid">
                {users.map(u => (
                  <div key={u.username} className={`up-card up-user-card${u.active ? '' : ' is-disabled'}`}>
                    <div className="up-user-card__head">
                      <span className="up-user-card__name">{u.username}</span>
                      <span className="up-badge">{ROLE_LABEL[u.role] || u.role}</span>
                      {!u.active && <span className="up-badge up-badge--off">disabled</span>}
                    </div>
                    <dl className="up-user-card__meta">
                      <div><dt>Email</dt><dd>{u.email || '—'}</dd></div>
                      <div><dt>Created</dt><dd>{fmtDate(u.created_at)}</dd></div>
                      <div><dt>Last login</dt><dd>{u.last_login ? fmtDate(u.last_login) : 'Never'}</dd></div>
                    </dl>
                    <div className="up-user-card__foot">
                      <button type="button" className="up-action" onClick={() => toggleActive(u)}>
                        {u.active ? 'Disable' : 'Enable'}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}

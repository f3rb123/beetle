import { useEffect, useRef, useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { login, getToken } from '../lib/auth.js'
import { whiteMark as beetleIcon } from '../assets/brandLogos.js'

export default function Login() {
  const navigate  = useNavigate()
  const location  = useLocation()
  const from      = location.state?.from || '/'
  const userRef   = useRef(null)

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error,    setError]    = useState('')
  const [loading,  setLoading]  = useState(false)
  const [bootstrap, setBootstrap] = useState(null)

  // Already authenticated — skip login
  useEffect(() => {
    if (getToken()) navigate(from, { replace: true })
    else userRef.current?.focus()
  }, []) // eslint-disable-line

  // Fresh-install hint: show the default credentials only while the instance
  // still uses them (the backend reports active=false once the password changes).
  useEffect(() => {
    fetch('/api/auth/bootstrap-status')
      .then(r => (r.ok ? r.json() : null))
      .then(d => setBootstrap(d))
      .catch(() => {})
  }, [])

  async function handleSubmit(e) {
    e.preventDefault()
    if (!username.trim() || !password) {
      setError('Enter your username and password')
      return
    }
    setLoading(true)
    setError('')
    const result = await login(username.trim(), password)
    setLoading(false)
    if (result.ok) {
      navigate(from, { replace: true })
    } else {
      setError(result.error)
      setPassword('')
    }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-card__header">
          <div className="login-card__logo-ring">
            <img src={beetleIcon} alt="Beetle" className="login-card__logo" />
          </div>
          <h1 className="login-card__title">Beetle</h1>
          <p className="login-card__sub">Mobile Static Security Workspace</p>
        </div>

        <form className="login-form" onSubmit={handleSubmit} autoComplete="on">
          <div className="login-form__field">
            <label className="login-form__label" htmlFor="username">Username</label>
            <input
              id="username"
              ref={userRef}
              type="text"
              className="login-form__input"
              autoComplete="username"
              spellCheck={false}
              placeholder="beetle"
              value={username}
              onChange={e => setUsername(e.target.value)}
              disabled={loading}
            />
          </div>

          <div className="login-form__field">
            <label className="login-form__label" htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              className="login-form__input"
              autoComplete="current-password"
              placeholder="••••••••"
              value={password}
              onChange={e => setPassword(e.target.value)}
              disabled={loading}
            />
          </div>

          {error && (
            <div className="login-form__error" role="alert">
              <span>⚠</span>
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            className="login-form__submit"
            disabled={loading}
          >
            {loading ? 'Signing in…' : 'Sign in →'}
          </button>
        </form>

        <hr className="login-card__divider" />
        {bootstrap?.active ? (
          <div
            className="login-card__hint"
            style={{
              textAlign: 'left',
              padding: '10px 12px',
              border: '1px solid rgba(255,255,255,0.14)',
              borderRadius: 8,
              lineHeight: 1.5,
            }}
          >
            <div style={{ fontWeight: 600, marginBottom: 4 }}>
              Default credentials (first installation only)
            </div>
            <div>Username: <code>{bootstrap.username || 'beetle'}</code></div>
            <div>Password: <code>beetle</code></div>
            <div style={{ marginTop: 6, opacity: 0.7 }}>
              Change the password after signing in — this notice disappears once you do.
            </div>
          </div>
        ) : (
          <p className="login-card__hint">
            Enter your administrator credentials to continue.
          </p>
        )}
      </div>
    </div>
  )
}

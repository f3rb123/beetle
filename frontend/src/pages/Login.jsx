import { useEffect, useRef, useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { ShieldCheck } from 'lucide-react'
import { login, getToken } from '../lib/auth.js'

export default function Login() {
  const navigate  = useNavigate()
  const location  = useLocation()
  const from      = location.state?.from || '/'
  const userRef   = useRef(null)

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error,    setError]    = useState('')
  const [loading,  setLoading]  = useState(false)

  // Already authenticated — skip login
  useEffect(() => {
    if (getToken()) navigate(from, { replace: true })
    else userRef.current?.focus()
  }, []) // eslint-disable-line

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
      {/* subtle grid background */}
      <div className="login-page__grid" aria-hidden="true" />

      <div className="login-card">
        <div className="login-card__header">
          <div className="login-card__logo-ring">
            <ShieldCheck size={26} strokeWidth={1.75} className="login-card__icon" />
          </div>
          <h1 className="login-card__title">Beetle</h1>
          <p className="login-card__sub">Mobile Security Platform</p>
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
              placeholder="admin"
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
        <p className="login-card__hint">
          Default credentials are printed in the server logs on first run.
        </p>
      </div>
    </div>
  )
}

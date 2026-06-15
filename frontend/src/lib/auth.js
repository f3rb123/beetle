/**
 * Cortex auth utilities — token storage + authenticated fetch
 */

const TOKEN_KEY = 'cortex_token'
const USER_KEY  = 'cortex_user'

export function getToken() {
  return localStorage.getItem(TOKEN_KEY)
}

export function getUser() {
  try {
    const raw = localStorage.getItem(USER_KEY)
    return raw ? JSON.parse(raw) : null
  } catch {
    return null
  }
}

export function setAuth(token, user) {
  localStorage.setItem(TOKEN_KEY, token)
  localStorage.setItem(USER_KEY, JSON.stringify(user))
}

export function clearAuth() {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
}

export function isAdmin() {
  return getUser()?.role === 'admin'
}

/**
 * Drop-in replacement for fetch() that adds Authorization header.
 *   - 401 → clear token and bounce to /login.
 *   - 5xx / network error → tag the response with `.cortexServerError = true`
 *     so callers can render a friendly "service unavailable" state instead of
 *     the raw fetch exception that used to bubble up as a crashed component.
 * The returned value is always a Response-like object so callers never have to
 * branch on try/catch just to read `.status`.
 */
export function apiFetch(url, options = {}) {
  const token = getToken()
  const headers = new Headers(options.headers || {})
  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`)
  }
  return fetch(url, { ...options, headers })
    .then(res => {
      if (res.status === 401) {
        clearAuth()
        if (typeof window !== 'undefined' && !window.location.pathname.startsWith('/login')) {
          window.location.href = '/login'
        }
      }
      if (res.status >= 500 && res.status <= 599) {
        res.cortexServerError = true
      }
      return res
    })
    .catch(err => {
      // Normalize network failures into a Response-shaped sentinel so callers
      // that do `res.ok` or `res.status` never throw. Two common causes: the
      // backend is down, or the browser is offline.
      const sentinel = new Response(
        JSON.stringify({ detail: 'Service unavailable — please retry.' }),
        { status: 503, headers: { 'Content-Type': 'application/json' } },
      )
      sentinel.cortexServerError = true
      sentinel.cortexNetworkError = true
      sentinel.cortexOriginalError = err?.message || String(err)
      return sentinel
    })
}

/**
 * Call backend login endpoint.
 * Returns { ok: true, user } or { ok: false, error }.
 */
export async function login(username, password) {
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
    if (res.ok) {
      const data = await res.json()
      setAuth(data.access_token, { username: data.username, role: data.role })
      return { ok: true, user: { username: data.username, role: data.role } }
    }
    const err = await res.json().catch(() => ({}))
    return { ok: false, error: err.detail || 'Login failed' }
  } catch (e) {
    return { ok: false, error: 'Network error — is the server running?' }
  }
}

/**
 * Check if server has auth enabled.
 * Returns true if /api/auth/me returns 401 (auth is active),
 * false if it returns 200 with anonymous (auth disabled).
 */
export async function probeAuthEnabled() {
  try {
    const res = await fetch('/api/auth/me')
    if (res.status === 401) return true
    if (res.ok) {
      const data = await res.json()
      return data.username !== 'anonymous'
    }
    return false
  } catch {
    return false
  }
}

import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import EngineeringWorkspace from '../components/EngineeringWorkspace.jsx'
import beetleIcon from '../assets/beetle-icon.png'
import { loadLocalHistory, normalizeHistoryEntry } from '../lib/scan-data.js'
import { apiFetch, clearAuth, getToken, getUser, isAdmin } from '../lib/auth.js'

export default function Home() {
  const navigate = useNavigate()
  // History is only needed so investigation modules (Source / Security Explorer,
  // Semgrep) can open the most recent scan. The scan list itself now lives on the
  // dedicated Scan page.
  const [history, setHistory] = useState([])

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

  // The Engineering Workspace is the application launcher. Selecting a capability
  // routes into its dedicated stage; the Workspace itself never performs a scan.
  //   • Upload modules (Android/iOS/Flutter/React Native) → dedicated Scan page.
  //   • Investigation modules (Source/Security Explorer, Semgrep) → deep-link into
  //     the latest scan's section (with optional panel filters), or fall back to the
  //     Scan page when no scans exist yet.
  //   • Coming Soon modules show their inline notice (handled in EngineeringWorkspace).
  const launchModule = module => {
    if (module.deepLink) {
      const latest = history[0]?.scan_id
      if (!latest) { navigate('/scan'); return }
      const { section, category, detectedBy } = module.deepLink
      const params = new URLSearchParams()
      if (category) params.set('cat', category)
      if (detectedBy) params.set('src', detectedBy)
      const qs = params.toString()
      navigate(`/scans/${latest}/${section}${qs ? `?${qs}` : ''}`)
      return
    }
    navigate(`/scan/${module.id}`)
  }

  return (
    <div className="login-page login-page--workspace">
      <div className="ws-home">
        {/* Launcher chrome — brand top-left, utility actions top-right */}
        <header className="ws-topbar">
          <div className="ws-topbar__brand">
            <img src={beetleIcon} alt="Beetle" className="ws-topbar__logo" />
            <div className="ws-topbar__id">
              <h1 className="ws-topbar__name">Beetle</h1>
              <p className="ws-topbar__tagline">Mobile Static Security Workspace</p>
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
          {/* Engineering Workspace — the application launcher. Each capability routes
              into its own stage; no scanning happens on the Home page. */}
          <EngineeringWorkspace onLaunch={launchModule} />
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

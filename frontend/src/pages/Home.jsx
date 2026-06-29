import { useNavigate } from 'react-router-dom'
import EngineeringWorkspace from '../components/EngineeringWorkspace.jsx'
import beetleIcon from '../assets/beetle-icon.png'
import { clearAuth, getToken, getUser, isAdmin } from '../lib/auth.js'

export default function Home() {
  const navigate = useNavigate()

  // The Engineering Workspace is the application launcher: it launches ANALYSIS
  // modules only (Phase 2.5.2–2.5.4). Selecting one opens the dedicated Scan page;
  // the Workspace itself never performs a scan or exposes investigation tools.
  // Coming Soon modules show their inline notice (handled in EngineeringWorkspace).
  const launchModule = module => {
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

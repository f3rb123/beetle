import { Component } from 'react'
import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import Home from './pages/Home.jsx'
import Results from './pages/Results.jsx'
import Login from './pages/Login.jsx'
import Webhooks from './pages/Webhooks.jsx'
import CustomRules from './pages/CustomRules.jsx'
import Users from './pages/Users.jsx'
import History from './pages/History.jsx'
import { getToken } from './lib/auth.js'

class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    console.error('Beetle UI error:', error, info)
  }

  render() {
    if (this.state.error) {
      return (
        <div className="workspace-page">
          <div className="workspace-loading">
            <div className="workspace-loading__title">The workspace hit an unexpected error</div>
            <div className="workspace-loading__subtitle">
              Your scan data is still safe. Reload the page or return home to reopen the scan.
            </div>
            <button type="button" className="button" onClick={() => { this.setState({ error: null }); window.location.href = '/' }}>
              Back home
            </button>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

/**
 * Wrap a route so unauthenticated visitors are redirected to /login.
 * Token-only check — the UI always requires creds. If an operator wants an
 * anonymous-mode deployment, they can log in with the seeded admin account;
 * there is no back-door "auth probe" anymore.
 */
function RequireAuth({ children }) {
  const location = useLocation()
  if (!getToken()) {
    return <Navigate to="/login" state={{ from: location.pathname + location.search }} replace />
  }
  return children
}

export default function App() {
  return (
    <BrowserRouter>
      <ErrorBoundary>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <RequireAuth>
                <Home />
              </RequireAuth>
            }
          />
          <Route
            path="/scans/:scanId/:sectionId"
            element={
              <RequireAuth>
                <Results />
              </RequireAuth>
            }
          />
          <Route
            path="/history"
            element={
              <RequireAuth>
                <History />
              </RequireAuth>
            }
          />
          <Route
            path="/settings/webhooks"
            element={
              <RequireAuth>
                <Webhooks />
              </RequireAuth>
            }
          />
          <Route
            path="/settings/rules"
            element={
              <RequireAuth>
                <CustomRules />
              </RequireAuth>
            }
          />
          <Route
            path="/settings/users"
            element={
              <RequireAuth>
                <Users />
              </RequireAuth>
            }
          />
          <Route path="/scans/:scanId" element={<Navigate to="dashboard" replace />} />
          <Route path="/results" element={<Navigate to="/" replace />} />
        </Routes>
      </ErrorBoundary>
    </BrowserRouter>
  )
}

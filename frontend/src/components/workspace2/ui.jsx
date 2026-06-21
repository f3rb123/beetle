// Shared atoms + data helpers for the Phase 13 workspace. Presentation only.
import { useEffect } from 'react'

export const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
export const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
export const SEV_COLOR = {
  critical: '#7f1d1d', high: '#dc2626', medium: '#ea8600', low: '#3b82f6', info: '#6b7280',
}

export function normSev(s) {
  const v = String(s || 'info').toLowerCase()
  return SEV_ORDER.includes(v) ? v : 'info'
}

export function SeverityTag({ severity, compact }) {
  const s = normSev(severity)
  return <span className={`ws-tag ws-sev ws-sev--${s}`}>{compact ? s[0].toUpperCase() : s.toUpperCase()}</span>
}

export function SoftTag({ children, title }) {
  if (!children) return null
  return <span className="ws-tag ws-tag--soft" title={title}>{children}</span>
}

export function Dot({ color }) {
  return <span className="ws-dot" style={{ background: color }} />
}

export function EmptyState({ title, body }) {
  return (
    <div className="ws-empty">
      <h3>{title}</h3>
      {body ? <p style={{ textAlign: 'center' }}>{body}</p> : null}
    </div>
  )
}

export function Metric({ label, value, sub, rating }) {
  return (
    <div className="ws-metric">
      <div className="ws-metric__label">{label}</div>
      <div className="ws-metric__value">{value}</div>
      {rating ? <span className={`ws-rating ws-rating--${rating}`} style={{ marginTop: 6 }}>{rating}</span> : null}
      {sub ? <div className="ws-metric__sub">{sub}</div> : null}
    </div>
  )
}

// Derive severity counts from findings (never trust a possibly-stale blob count).
export function severityCounts(findings = []) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of findings) c[normSev(f.severity)] += 1
  return c
}

export function ownershipLabel(f) {
  const l = f.ownership_label || f.ownership || ''
  return l ? l.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, m => m.toUpperCase()) : ''
}

export function confidenceLabel(f) {
  if (f.evidence_quality) return f.evidence_quality
  const n = Number(f.confidence_score ?? f.confidence)
  if (Number.isFinite(n)) return n >= 70 ? 'HIGH' : n >= 40 ? 'MEDIUM' : 'LOW'
  return ''
}

export function findingPath(f) {
  return f.file_path || f.full_path || (f.file_evidence?.[0]?.path) || ''
}

export function findingLines(f) {
  if (f.line) return [f.line]
  const fe = f.file_evidence?.[0]
  return fe?.lines || []
}

// Esc-to-close hook
export function useEscape(onClose) {
  useEffect(() => {
    const h = e => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [onClose])
}

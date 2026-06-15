import { SEVERITY_META } from '../lib/scan-data.js'

export default function SeverityBadge({ severity = 'info', compact = false }) {
  const key = String(severity || 'info').toLowerCase()
  const meta = SEVERITY_META[key] || SEVERITY_META.info

  return (
    <span
      className={`severity-badge${compact ? ' compact' : ''}`}
      style={{
        '--severity-bg': meta.bg,
        '--severity-text': meta.text,
        '--severity-border': meta.border,
        '--severity-accent': meta.accent,
      }}
    >
      <span className="severity-badge__dot" />
      {meta.label}
    </span>
  )
}

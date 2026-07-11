// Shared atoms + data helpers for the Phase 13 workspace. Presentation only.
import { useEffect } from 'react'
import { chainEvidenceTargets, humanizeOwnership } from './evidence-model.js'

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
  return humanizeOwnership((f && (f.ownership_label || f.ownership)) || '')
}

export function confidenceLabel(f) {
  if (f.evidence_quality) return f.evidence_quality
  // Prefer the Confidence Engine's computed overall_confidence; fall back to the
  // legacy confidence_score/confidence for un-annotated scans (same source as chains).
  const n = Number(f.overall_confidence ?? f.confidence_score ?? f.confidence)
  if (Number.isFinite(n)) return n >= 70 ? 'HIGH' : n >= 40 ? 'MEDIUM' : 'LOW'
  return ''
}

export function findingPath(f) {
  return f.file_path || f.full_path || (f.file_evidence?.[0]?.path) || ''
}

export function findingLines(f) {
  if (f.line) return [f.line]
  if (f.line_number) return [f.line_number]
  const ex = f.analyst_explanation || {}
  const loc = (ex.evidence_locations || [])[0]
  if (loc && (loc.highlight_line || loc.line_start)) return [loc.highlight_line || loc.line_start]
  const fe = f.file_evidence?.[0]
  if (fe?.lines?.length) return fe.lines
  if (fe?.line) return [fe.line]
  return []
}

// Expand an inclusive [start..end] line span into an array (capped so a bad
// range can't explode the highlight). Returns [] when no usable span.
function lineRange(start, end, cap = 60) {
  const s = Number(start), e = Number(end)
  if (!Number.isFinite(s)) return []
  if (!Number.isFinite(e) || e < s) return [s]
  return Array.from({ length: Math.min(e - s + 1, cap) }, (_, i) => s + i)
}

// Distinctive keyword tokens from a finding title, for last-resort file search.
export function titleKeywords(title) {
  const STOP = new Set(['the', 'and', 'for', 'with', 'this', 'that', 'into', 'from', 'over',
    'chain', 'attack', 'finding', 'issue', 'risk', 'used', 'via', 'app', 'android', 'detected',
    'missing', 'insecure', 'exposed', 'enabled', 'disabled', 'usage', 'use', 'potential'])
  return String(title || '')
    .replace(/[^A-Za-z0-9_.\s-]/g, ' ')
    .split(/\s+/)
    .map(t => t.trim())
    .filter(t => t.length >= 4 && !STOP.has(t.toLowerCase()))
    .slice(0, 6)
}

// Class identifier implied by a source file path (e.g. .../PrivateActivity.java
// → "PrivateActivity"). Used for class-name search when no line is declared.
export function classFromPath(path) {
  if (!path) return ''
  const base = String(path).split('/').pop().split('\\').pop()
  const stem = base.replace(/\.(java|kt|kts|smali|swift|m|mm|js|ts)$/i, '')
  return /^[A-Za-z_]\w*$/.test(stem) ? stem : ''
}

// Normalize every evidence location for a finding into one ordered list so the
// code viewer can navigate prev/next. Each entry:
//   { path, line, lines, lineStart, lineEnd, highlightLine, snippet, source,
//     approximate, className, titleKeywords }
// `approximate` means the line was not declared and must be resolved/estimated.
export function buildEvidence(finding) {
  const f = finding || {}
  const ex = f.analyst_explanation || {}
  const kws = titleKeywords(f.title || f.name)
  const out = []
  const seen = new Set()
  const push = ({ path, lineStart, lineEnd, highlightLine, snippet, source }) => {
    if (!path) return
    const declared = highlightLine || lineStart || null
    // Collapse the same physical location reported by multiple sources (analyst
    // evidence + code reference + finding location often all point at one line):
    // when the line is known, dedup by path#line so it is ONE navigable location,
    // not three identical ones. Approximate entries (no line) stay distinct by
    // source+snippet so genuinely different guesses are still shown.
    const key = declared ? `${path}#${declared}` : `${path}#${source}#${(snippet || '').slice(0, 40)}`
    if (seen.has(key)) return
    seen.add(key)
    const lines = highlightLine && lineStart
      ? lineRange(lineStart, lineEnd).concat(lineRange(highlightLine, highlightLine)).filter((v, i, a) => a.indexOf(v) === i).sort((a, b) => a - b)
      : (lineStart ? lineRange(lineStart, lineEnd) : (highlightLine ? [highlightLine] : []))
    out.push({
      path,
      line: declared,
      lines,
      lineStart: lineStart || null,
      lineEnd: lineEnd || null,
      highlightLine: highlightLine || null,
      snippet: snippet || '',
      source,
      approximate: !declared,
      className: classFromPath(path),
      titleKeywords: kws,
    })
  }
  // 0. Chain findings aggregate evidence as evidence_references[] + steps[].evidence,
  // not the regular file_path/file_evidence shape. Normalize them so "View Code"
  // lands on the exact line like a regular finding (each step's own file:line).
  if (f.is_attack_chain || f.in_attack_chain) {
    for (const t of chainEvidenceTargets(f)) {
      push({ path: t.file, lineStart: t.line || null, lineEnd: t.line || null, snippet: t.snippet, source: 'chain evidence' })
    }
    if (out.length) return out   // a chain's proof is its references/steps, nothing else
  }
  // 1. Analyst evidence_locations — most precise (carry true ranges).
  for (const l of (Array.isArray(ex.evidence_locations) ? ex.evidence_locations : [])) {
    if (l && l.file) push({ path: l.file, lineStart: l.line_start, lineEnd: l.line_end, highlightLine: l.highlight_line, snippet: l.snippet, source: 'analyst evidence' })
  }
  // 2. Structured code references.
  for (const e of (Array.isArray(f.file_evidence) ? f.file_evidence : [])) {
    if (e && e.path) {
      const ls = (e.lines && e.lines.length) ? e.lines[0] : e.line
      const le = (e.lines && e.lines.length) ? e.lines[e.lines.length - 1] : e.line
      push({ path: e.path, lineStart: ls, lineEnd: le, snippet: e.snippet, source: 'code reference' })
    }
  }
  // 3. Top-level finding location.
  const p = f.file_path || f.full_path
  if (p) push({ path: p, lineStart: f.line || f.line_number, lineEnd: f.line || f.line_number, snippet: f.snippet || f.code_context, source: 'finding location' })
  return out
}

// When a finding legitimately has no source mapping, surface the backend's real
// reason — never invent a code location. Returns a reason string, or '' when the
// finding does have evidence.
export function evidenceUnavailableReason(finding) {
  const f = finding || {}
  if (buildEvidence(f).length) return ''
  if (f.source_unavailable_reason) return f.source_unavailable_reason
  if (f.source_applicable === false) return 'This issue originates from manifest metadata or higher-level analysis, not a single source line.'
  return 'No source mapping exists for this finding. This issue originates from manifest metadata or higher-level analysis.'
}

// Esc-to-close hook
export function useEscape(onClose) {
  useEffect(() => {
    const h = e => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [onClose])
}

import { useCallback, useEffect, useRef, useState } from 'react'
import {
  AlertTriangle,
  ArrowUpRight,
  BarChart2,
  Boxes,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Copy,
  FileCode2,
  Globe,
  HardDrive,
  KeyRound,
  Megaphone,
  Network,
  Route,
  Shield,
  UserCheck,
  Users,
  Zap,
} from 'lucide-react'
import CodeBlockViewer from '../CodeBlockViewer.jsx'
import SeverityBadge from '../SeverityBadge.jsx'
import { apiFetch } from '../../lib/auth.js'
import {
  SEVERITY_META,
  SEVERITY_ORDER,
  canViewSource,
  countLinkedFindings,
  formatDuration,
  formatFileSize,
  formatTimestamp,
  getEvidenceEntries,
  getGradeMeta,
  getPrimaryEvidence,
  getTopFindings,
  isQuickFinding,
  normLines,
} from '../../lib/scan-data.js'

// ─── Triage System ────────────────────────────────────────────────────────────
const TRIAGE_STATES = [
  { id: 'open',           label: 'Open',           color: null },
  { id: 'in_progress',    label: 'In Progress',    color: '#f59e0b' },
  { id: 'fixed',          label: 'Fixed',          color: '#10b981' },
  { id: 'accepted_risk',  label: 'Accepted Risk',  color: '#6366f1' },
  { id: 'false_positive', label: 'False Positive', color: '#9ca3af' },
]

const TRIAGE_META = Object.fromEntries(TRIAGE_STATES.map(s => [s.id, s]))

function _triageKey(finding) {
  // Stable key: rule_id if present, else title slug
  return finding.rule_id || finding.title?.replace(/\s+/g, '_').slice(0, 80) || 'unknown'
}

function _lsKey(scanId, findingKey) {
  return `cortex_triage:${scanId}:${findingKey}`
}

function useTriage(scanId) {
  // Map of findingKey → { state, note }
  const [triage, setTriage] = useState(() => {
    // Seed from localStorage as an optimistic starting point
    const result = {}
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const lk = localStorage.key(i)
        const prefix = `cortex_triage:${scanId}:`
        if (lk && lk.startsWith(prefix)) {
          const val = localStorage.getItem(lk)
          if (val && val !== 'open') {
            const fk = lk.slice(prefix.length)
            try { result[fk] = JSON.parse(val) } catch { result[fk] = { state: val, note: '' } }
          }
        }
      }
    } catch {}
    return result
  })

  // Hydrate from server on mount
  useEffect(() => {
    if (!scanId) return
    apiFetch(`/api/scans/${scanId}/triage`)
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (!data) return
        setTriage(prev => {
          const next = { ...prev }
          for (const [fk, entry] of Object.entries(data)) {
            if (entry.state && entry.state !== 'open') {
              next[fk] = { state: entry.state, note: entry.note || '' }
            }
          }
          return next
        })
      })
      .catch(() => {}) // server unavailable — keep localStorage state
  }, [scanId])

  const setFindingTriage = useCallback((finding, state, note = '') => {
    const fk = _triageKey(finding)
    const lk = _lsKey(scanId, fk)

    // Optimistic local update
    setTriage(prev => {
      const next = { ...prev }
      if (!state || state === 'open') {
        delete next[fk]
        try { localStorage.removeItem(lk) } catch {}
      } else {
        next[fk] = { state, note }
        try { localStorage.setItem(lk, JSON.stringify({ state, note })) } catch {}
      }
      return next
    })

    // Persist to server (fire-and-forget)
    apiFetch(`/api/scans/${scanId}/triage/${encodeURIComponent(fk)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ state: state || 'open', note }),
    }).catch(() => {}) // server unavailable — localStorage is the fallback
  }, [scanId])

  const getFindingTriage = useCallback((finding) => {
    const fk = _triageKey(finding)
    return triage[fk]?.state || 'open'
  }, [triage])

  const getFindingNote = useCallback((finding) => {
    const fk = _triageKey(finding)
    return triage[fk]?.note || ''
  }, [triage])

  const triageCount = Object.keys(triage).length

  return { getFindingTriage, getFindingNote, setFindingTriage, triageCount }
}

// Triage dropdown button on each finding card
function TriageButton({ state, note, onChange }) {
  const [open, setOpen]       = useState(false)
  const [noteVal, setNoteVal] = useState(note || '')
  const [noteMode, setNoteMode] = useState(false)
  const ref = useRef(null)
  const meta = TRIAGE_META[state] || TRIAGE_META.open

  useEffect(() => { setNoteVal(note || '') }, [note])

  useEffect(() => {
    if (!open) return
    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target)) {
        setOpen(false)
        setNoteMode(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  const selectState = (id) => {
    setNoteMode(true)  // show note field after picking state
    onChange(id, noteVal)
  }

  const saveNote = () => {
    onChange(state, noteVal)
    setOpen(false)
    setNoteMode(false)
  }

  return (
    <div className="triage-btn-wrap" ref={ref} onClick={e => e.stopPropagation()}>
      <button
        type="button"
        className={`triage-btn triage-btn--${state}`}
        style={meta.color ? { '--triage-color': meta.color } : {}}
        onClick={() => { setOpen(o => !o); setNoteMode(false) }}
        title="Set triage status"
      >
        <span className="triage-btn__dot" />
        {meta.label}
        <svg width="10" height="10" viewBox="0 0 10 10" fill="none" style={{ marginLeft: 2 }}>
          <path d="M2.5 3.5L5 6.5L7.5 3.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
      {open && (
        <div className="triage-dropdown">
          {!noteMode ? (
            <>
              {TRIAGE_STATES.map(s => (
                <button
                  key={s.id}
                  type="button"
                  className={`triage-dropdown__item${s.id === state ? ' is-active' : ''}`}
                  onClick={() => selectState(s.id)}
                >
                  <span className="triage-dropdown__dot" style={s.color ? { background: s.color } : {}} />
                  {s.label}
                </button>
              ))}
              <div className="triage-dropdown__divider" />
              <button
                type="button"
                className="triage-dropdown__item triage-dropdown__item--note"
                onClick={() => setNoteMode(true)}
              >
                {note ? 'Edit note…' : 'Add note…'}
              </button>
            </>
          ) : (
            <div className="triage-note-form">
              <textarea
                className="triage-note-input"
                value={noteVal}
                onChange={e => setNoteVal(e.target.value)}
                placeholder="Optional analyst note…"
                rows={3}
                // eslint-disable-next-line jsx-a11y/no-autofocus
                autoFocus
              />
              <div className="triage-note-actions">
                <button type="button" className="triage-note-cancel" onClick={() => setNoteMode(false)}>Back</button>
                <button type="button" className="triage-note-save" onClick={saveNote}>Save</button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function Panel({ title, subtitle, actions, children, tone = 'default', className = '', interactive = false, onClick }) {
  return (
    <section
      className={`panel panel--${tone}${interactive ? ' panel--interactive' : ''}${className ? ` ${className}` : ''}`}
      onClick={interactive ? onClick : undefined}
      role={interactive ? 'button' : undefined}
      tabIndex={interactive ? 0 : undefined}
      onKeyDown={interactive ? event => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault()
          onClick?.()
        }
      } : undefined}
    >
      {(title || subtitle || actions) ? (
        <div className="panel__header">
          <div>
            {title ? <h3 className="panel__title">{title}</h3> : null}
            {subtitle ? <p className="panel__subtitle">{subtitle}</p> : null}
          </div>
          {actions ? <div className="panel__actions">{actions}</div> : null}
        </div>
      ) : null}
      {children}
    </section>
  )
}

function EmptyState({ title, description, dark = false }) {
  return (
    <div className={`empty-state${dark ? ' empty-state--dark' : ''}`}>
      <div className="empty-state__title">{title}</div>
      {description ? <div className="empty-state__description">{description}</div> : null}
    </div>
  )
}

function StatCard({ label, value, helper, accent = '#00C896', onClick }) {
  const Element = onClick ? 'button' : 'div'

  return (
    <Element
      {...(onClick ? { type: 'button' } : {})}
      className={`stat-card${onClick ? ' stat-card--interactive' : ''}`}
      style={{ '--stat-accent': accent }}
      onClick={onClick}
    >
      <div className="stat-card__label">{label}</div>
      <div className="stat-card__value">{value}</div>
      {helper ? <div className="stat-card__helper">{helper}</div> : null}
    </Element>
  )
}

function Tag({ children, tone = 'neutral' }) {
  return <span className={`tag tag--${tone}`}>{children}</span>
}

const JAVA_SOURCE_UNAVAILABLE_TIP =
  'Java/Kotlin source is unavailable for this scan — JADX decompilation produced ' +
  'no output (see the Source section for details). smali, manifest and resource ' +
  'evidence remain viewable.'

function FileLinkButton({ path, lines, onOpenCode, label = 'Open code', decompileInfo }) {
  if (!path || !onOpenCode) return null
  const normalizedLines = normLines(lines)

  // Only gate when decompile metadata is supplied. Without it we never hide a
  // link we can't prove is broken (older scans / callers that don't pass it).
  const available = decompileInfo === undefined ? true : canViewSource(path, decompileInfo)
  if (!available) {
    return (
      <button
        type="button"
        className="button button--secondary button--small"
        disabled
        aria-disabled="true"
        title={JAVA_SOURCE_UNAVAILABLE_TIP}
      >
        <FileCode2 size={14} />
        {label}
      </button>
    )
  }

  return (
    <button type="button" className="button button--secondary button--small" onClick={() => onOpenCode(path, normalizedLines)}>
      <FileCode2 size={14} />
      {label}
    </button>
  )
}

function CopyValueButton({ value, label = 'Copy' }) {
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (!copied) return undefined
    const timer = window.setTimeout(() => setCopied(false), 1400)
    return () => window.clearTimeout(timer)
  }, [copied])

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(String(value || ''))
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }

  return (
    <button type="button" className="button button--ghost button--small" onClick={handleCopy}>
      <Copy size={14} />
      {copied ? 'Copied ✓' : label}
    </button>
  )
}

function DefinitionRows({ items }) {
  return (
    <div className="definition-list">
      {items.filter(([, value]) => value != null && value !== '').map(([label, value]) => (
        <div key={label} className="definition-list__row">
          <div className="definition-list__label">{label}</div>
          <div className="definition-list__value">{String(value)}</div>
        </div>
      ))}
    </div>
  )
}

function formatKeyLabel(value = '') {
  return String(value || '')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, char => char.toUpperCase())
}

// ── AI Enrichment ─────────────────────────────────────────────────────────────
function AIEnrichmentPanel({ finding, appContext }) {
  const [status,     setStatus]     = useState('idle') // idle | loading | done | error
  const [enrichment, setEnrichment] = useState(null)
  const [errMsg,     setErrMsg]     = useState('')

  const handleEnrich = async (e) => {
    e.stopPropagation()
    if (status === 'loading') return
    setStatus('loading')
    setErrMsg('')
    try {
      const res = await apiFetch('/api/ai/enrich', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding, app_context: appContext || {} }),
      })
      const data = await res.json()
      if (data.error) {
        setErrMsg(data.error)
        setStatus('error')
      } else {
        setEnrichment(data)
        setStatus('done')
      }
    } catch (err) {
      setErrMsg('Network error')
      setStatus('error')
    }
  }

  if (status === 'idle') {
    return (
      <button type="button" className="ai-enrich-btn" onClick={handleEnrich}>
        <Zap size={12} />
        AI Enrichment
      </button>
    )
  }

  if (status === 'loading') {
    return (
      <div className="ai-enrich-loading">
        <span className="ai-enrich-loading__dot" />
        Analysing with AI…
      </div>
    )
  }

  if (status === 'error') {
    return (
      <div className="ai-enrich-error">
        <span>{errMsg}</span>
        <button type="button" className="ai-enrich-retry" onClick={handleEnrich}>Retry</button>
      </div>
    )
  }

  // status === 'done'
  const remItems = Array.isArray(enrichment.remediation) ? enrichment.remediation : []
  const refs     = Array.isArray(enrichment.references)  ? enrichment.references  : []

  return (
    <div className="ai-enrichment-panel">
      <div className="ai-enrichment-panel__header">
        <Zap size={13} className="ai-enrichment-panel__icon" />
        <span>AI Enrichment</span>
        {enrichment.cached && <span className="ai-enrichment-panel__cached">cached</span>}
        {enrichment.model && <span className="ai-enrichment-panel__model">{enrichment.model}</span>}
      </div>

      {enrichment.exploit_scenario && (
        <div className="ai-enrichment-panel__block">
          <div className="ai-enrichment-panel__label">Exploit Scenario</div>
          <div className="ai-enrichment-panel__body">{enrichment.exploit_scenario}</div>
        </div>
      )}

      {enrichment.real_world_impact && (
        <div className="ai-enrichment-panel__block">
          <div className="ai-enrichment-panel__label">Real-World Impact</div>
          <div className="ai-enrichment-panel__body">{enrichment.real_world_impact}</div>
        </div>
      )}

      {enrichment.exploitability_notes && (
        <div className="ai-enrichment-panel__block">
          <div className="ai-enrichment-panel__label">Exploitability</div>
          <div className="ai-enrichment-panel__body">{enrichment.exploitability_notes}</div>
        </div>
      )}

      {remItems.length > 0 && (
        <div className="ai-enrichment-panel__block">
          <div className="ai-enrichment-panel__label">Remediation Steps</div>
          <ol className="ai-enrichment-panel__list">
            {remItems.map((item, i) => (
              <li key={i} className="ai-enrichment-panel__list-item">{item}</li>
            ))}
          </ol>
        </div>
      )}

      {refs.length > 0 && (
        <div className="ai-enrichment-panel__block">
          <div className="ai-enrichment-panel__label">References</div>
          <div className="tag-row">
            {refs.map((ref, i) => <Tag key={i}>{ref}</Tag>)}
          </div>
        </div>
      )}
    </div>
  )
}

function FindingsList({ findings, onOpenCode, emptyTitle = 'No findings found', emptyDescription = 'This section has no issues for the current filter.', getFindingTriage, getFindingNote, setFindingTriage, decompileInfo }) {
  const [openItems, setOpenItems] = useState(() => Object.fromEntries(findings.slice(0, 1).map((finding, index) => [`${finding.title}-${index}`, true])))

  useEffect(() => {
    setOpenItems(current => {
      const next = {}
      findings.forEach((finding, index) => {
        const key = `${finding.title}-${index}`
        next[key] = current[key] ?? index < 1
      })
      return next
    })
  }, [findings])

  if (!findings.length) {
    return <EmptyState title={emptyTitle} description={emptyDescription} />
  }

  return (
    <div className="stack">
      {findings.map((finding, index) => {
        const evidence = getEvidenceEntries(finding)
        const primary = evidence[0]
        const severity = SEVERITY_META[finding.severity] || SEVERITY_META.info
        const key = `${finding.title}-${index}`
        const open = Boolean(openItems[key])
        const summary = finding.summary || finding.description || 'No summary provided for this finding.'
        const references = [finding.cwe, finding.masvs, finding.owasp ? `OWASP ${finding.owasp}` : null].filter(Boolean)
        const triageState = getFindingTriage ? getFindingTriage(finding) : 'open'
        const triageNote  = getFindingNote  ? getFindingNote(finding)  : ''
        const triageMeta  = TRIAGE_META[triageState] || TRIAGE_META.open
        const isTriaged   = triageState !== 'open'

        return (
          <article
            key={key}
            className={`finding-card${open ? ' is-open' : ''}${isTriaged ? ` finding-card--triaged finding-card--triaged-${triageState}` : ''}`}
            style={{
              '--finding-accent': severity.accent,
              '--finding-accent-soft': severity.bg,
              '--finding-accent-border': severity.border,
            }}
          >
            <div
              className="finding-card__summary"
              role="button"
              tabIndex={0}
              onClick={() => setOpenItems(current => ({ ...current, [key]: !current[key] }))}
              onKeyDown={event => {
                if (event.key === 'Enter' || event.key === ' ') {
                  event.preventDefault()
                  setOpenItems(current => ({ ...current, [key]: !current[key] }))
                }
              }}
            >
                <div className="finding-card__heading">
                  <div className="finding-card__topline">
                    <SeverityBadge severity={finding.severity} compact />
                    <div className="finding-card__title">{finding.title}</div>
                    {isTriaged && (
                      <span className={`triage-state-badge triage-state-badge--${triageState}`} style={triageMeta.color ? { '--triage-color': triageMeta.color } : {}}>
                        {triageMeta.label}
                      </span>
                    )}
                    {finding.category ? <Tag>{finding.category}</Tag> : null}
                    {finding.owasp ? <Tag tone="danger">{`OWASP ${finding.owasp}`}</Tag> : null}
                    {finding.masvs ? <Tag tone="info">{finding.masvs}</Tag> : null}
                    {finding.source === 'semgrep'
                      ? <Tag tone="info">Semgrep</Tag>
                      : (finding.source === 'SAST' || finding.rule_id ? <Tag tone="info">SAST</Tag> : null)
                    }
                    {finding.confidence != null ? <Tag>{finding.confidence}% confidence</Tag> : null}
                  </div>
                <div className="finding-card__summary-copy">{summary}</div>
              </div>
              <div className="finding-card__actions">
                {setFindingTriage && (
                  <TriageButton
                    state={triageState}
                    note={triageNote}
                    onChange={(state, note) => setFindingTriage(finding, state, note)}
                  />
                )}
                {primary?.path ? <span onClick={event => event.stopPropagation()}><FileLinkButton path={primary.path} lines={primary.lines} onOpenCode={onOpenCode} label="View Code" decompileInfo={decompileInfo} /></span> : null}
                <span className="finding-card__signal" style={{ color: severity.text }}>
                  <ChevronRight size={16} />
                </span>
              </div>
            </div>

            <div className="finding-card__expand">
              <div className="finding-card__body">
                {triageNote && (
                  <div className="triage-note-banner">
                    <span className="triage-note-banner__label">Analyst note</span>
                    <span className="triage-note-banner__text">{triageNote}</span>
                  </div>
                )}
                <div className="finding-detail-grid">
                  <div className="mini-surface">
                    <div className="mini-surface__label">Impact</div>
                    <div className="mini-surface__body">{finding.impact || 'Impact details were not supplied for this finding.'}</div>
                  </div>

                  <div className="mini-surface">
                    <div className="mini-surface__label">Why It Matters</div>
                    <div className="mini-surface__body">{finding.description || 'Review the code evidence and references to validate exploitability.'}</div>
                  </div>

                  <div className="mini-surface">
                    <div className="mini-surface__label">Fix</div>
                    <div className="mini-surface__body">{finding.recommendation || 'No remediation guidance was attached to this finding.'}</div>
                  </div>

                  <div className="mini-surface">
                    <div className="mini-surface__label">References</div>
                    <div className="tag-row">
                      {references.length ? references.map(reference => (
                        <Tag key={reference}>{reference}</Tag>
                      )) : <span className="mini-surface__body">No standards references attached.</span>}
                    </div>
                  </div>
                </div>

                {evidence.length > 0 ? (
                  <div className="stack stack--tight">
                    <div className="mini-surface__label">Evidence</div>
                    <div className="evidence-stack">
                      {evidence.map((entry, evidenceIndex) => (
                        <div key={`${entry.path}-${evidenceIndex}`} className="evidence-row">
                          <div className="evidence-row__meta">
                            <div className="evidence-row__path">{entry.path}</div>
                            <div className="evidence-row__lines">
                              {entry.lines.length ? `Lines ${entry.lines.join(', ')}` : 'Line references unavailable'}
                            </div>
                          </div>
                          <FileLinkButton
                            path={entry.path}
                            lines={entry.lines}
                            onOpenCode={onOpenCode}
                            decompileInfo={decompileInfo}
                            label={entry.lines[0] ? `Open :${entry.lines[0]}` : 'View Code'}
                          />
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}

                {primary?.snippet || finding.poc || finding.code_context ? (
                  <div className="stack stack--tight">
                    {primary?.snippet ? (
                      <div className="code-snippet">
                        <div className="code-snippet__header">
                          <span>Evidence</span>
                          <CopyValueButton value={primary.snippet} label="Copy evidence" />
                        </div>
                        <pre>{primary.snippet}</pre>
                      </div>
                    ) : null}
                    {finding.poc ? (
                      <div className="code-snippet">
                        <div className="code-snippet__header">
                          <span>Reference PoC</span>
                          <CopyValueButton value={finding.poc} label="Copy PoC" />
                        </div>
                        <pre>{finding.poc}</pre>
                      </div>
                    ) : null}
                    {finding.code_context ? (
                      <div className="code-snippet">
                        <div className="code-snippet__header">
                          <span>Code Context</span>
                          <CopyValueButton value={finding.code_context} label="Copy context" />
                        </div>
                        <pre>{finding.code_context}</pre>
                      </div>
                    ) : null}
                  </div>
                ) : null}
                {finding.source === 'semgrep' && (finding.semgrep_rule || finding.help_url) && (
                  <div className="semgrep-rule-row">
                    <span className="semgrep-rule-badge">Semgrep</span>
                    {finding.semgrep_rule && <span className="semgrep-rule-id">{finding.semgrep_rule}</span>}
                    {finding.help_url && (
                      <a className="semgrep-rule-link" href={finding.help_url} target="_blank" rel="noopener noreferrer">
                        Rule docs ↗
                      </a>
                    )}
                  </div>
                )}

                <AIEnrichmentPanel finding={finding} appContext={null} />
              </div>
            </div>
          </article>
        )
      })}
    </div>
  )
}

// Phase 4: dense, triage-first table view for findings. Same data as the card
// view; severity-anchored, sticky header, View Code + triage status inline.
function FindingsTable({ findings, onOpenCode, decompileInfo, getFindingTriage }) {
  if (!findings.length) {
    return <EmptyState title="No findings match this filter" description="Try another severity filter or search phrase." />
  }
  return (
    <div className="table-shell">
      <table className="data-table findings-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Title</th>
            <th>Location</th>
            <th>Category</th>
            <th>Confidence</th>
            <th>Status</th>
            <th>View Code</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding, index) => {
            const sev = SEVERITY_META[finding.severity] ? finding.severity : 'info'
            const primary = getEvidenceEntries(finding)[0]
            const triageState = getFindingTriage ? getFindingTriage(finding) : 'open'
            const triageMeta = TRIAGE_META[triageState] || TRIAGE_META.open
            const loc = primary?.path ? `${primary.path}${primary.lines?.[0] ? `:${primary.lines[0]}` : ''}` : '—'
            return (
              <tr key={`${finding.title}-${index}`}>
                <td><span className={`sev-tag sev-tag--${sev}`}>{SEVERITY_META[sev].label}</span></td>
                <td><span className="ft-title">{finding.title}</span></td>
                <td><span className="ft-loc" title={loc}>{loc}</span></td>
                <td>{finding.category || '—'}</td>
                <td className="num">{finding.confidence != null ? `${finding.confidence}%` : '—'}</td>
                <td>
                  <span className={`triage-state-badge triage-state-badge--${triageState}`} style={triageMeta.color ? { '--triage-color': triageMeta.color } : {}}>
                    {triageMeta.label}
                  </span>
                </td>
                <td>
                  {primary?.path
                    ? <FileLinkButton path={primary.path} lines={primary.lines} onOpenCode={onOpenCode} label="View Code" decompileInfo={decompileInfo} />
                    : <span className="ft-loc">—</span>}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function DashboardSection({ results, onNavigateSection, onOpenCode, viewMode }) {
  const info = results.app_info || {}
  const score = results.score || {}
  const findings = results.findings || []
  const severitySummary = results.severity_summary || {}
  const trackers = results.trackers || []
  const secrets = results.secrets || []
  const surface = results.attack_surface || {}
  const manifestSecurity = results.manifest_security || {}
  const scanMetrics = results.scan_metrics || {}
  const gradeMeta = getGradeMeta(score.grade)
  const scoreValue = Math.max(0, Math.min(100, Number(score.score ?? 0)))
  const primaryRiskCount = (severitySummary.critical || 0) + (severitySummary.high || 0)
  const slowModules = Object.entries(scanMetrics.modules || {}).sort((a, b) => (b[1]?.duration_ms || 0) - (a[1]?.duration_ms || 0)).slice(0, 4)
  const quickSummary = results.quick_summary || {}
  const manifestChecks = Object.entries(manifestSecurity)
    .filter(([, value]) => value && typeof value === 'object')
    .map(([key, value]) => ({
      key,
      label: formatKeyLabel(key),
      status: value.status || 'Not evaluated',
      reason: value.reason || value.description || 'No additional manifest security detail is available.',
      severity: value.severity || 'info',
    }))
  const primaryManifestCheck = manifestChecks[0] || {
    key: 'manifest',
    label: 'Manifest',
    status: 'Not evaluated',
    reason: 'Manifest security checks are unavailable for this scan.',
    severity: 'info',
  }
  const summaryTiles = [
    { label: 'Total', value: findings.length, tone: 'neutral' },
    { label: 'High / Critical', value: primaryRiskCount, tone: 'danger' },
    { label: 'Trackers', value: trackers.length, tone: 'warning' },
    { label: 'Secrets', value: secrets.length, tone: 'success' },
  ]
  const performanceItems = slowModules.length
    ? slowModules.map(([name, meta]) => ({
      label: name.replace(/_/g, ' '),
      value: formatDuration(meta?.duration_ms),
    }))
    : [
      { label: 'Total scan', value: formatDuration(scanMetrics.summary?.total_duration_ms) },
      { label: 'Parallel phase', value: formatDuration(scanMetrics.summary?.parallel_phase_ms) },
      { label: 'Modules', value: scanMetrics.summary?.module_count || '—' },
    ]

  // ── Extended dashboard data ──
  const cert = results.certificate || {}
  const activities = surface.activities || []
  const services = surface.services || []
  const receivers = surface.receivers || []
  const providers = surface.providers || []
  const exportedCount = [...activities, ...services, ...receivers, ...providers].filter(i => i.exported).length
  const browsableCount = activities.filter(i => i.browsable).length

  const surfaceCards = [
    { label: 'Activities', total: activities.length, exported: activities.filter(i => i.exported).length, nav: 'surface', accent: '#10b981', accentBg: 'rgba(16,185,129,0.08)', accentBorder: 'rgba(16,185,129,0.25)' },
    { label: 'Services',   total: services.length,   exported: services.filter(i => i.exported).length,   nav: 'surface', accent: '#3b82f6', accentBg: 'rgba(59,130,246,0.08)',  accentBorder: 'rgba(59,130,246,0.25)'  },
    { label: 'Receivers',  total: receivers.length,  exported: receivers.filter(i => i.exported).length,  nav: 'surface', accent: '#f59e0b', accentBg: 'rgba(245,158,11,0.08)', accentBorder: 'rgba(245,158,11,0.25)' },
    { label: 'Providers',  total: providers.length,  exported: providers.filter(i => i.exported).length,  nav: 'surface', accent: '#dc2626', accentBg: 'rgba(220,38,38,0.08)',  accentBorder: 'rgba(220,38,38,0.25)'  },
  ]

  const maxFindingCount = Math.max(1, findings.length)
  const severityBars = SEVERITY_ORDER.map(sev => ({
    key: sev,
    label: SEVERITY_META[sev].label,
    count: severitySummary[sev] || 0,
    color: SEVERITY_META[sev].text,
  }))

  const critHighFindings = getTopFindings(
    findings.filter(f => ['critical', 'high'].includes(f.severity)),
    6,
  )

  const attackChain = quickSummary.attack_chain || []
  const pentestHints = quickSummary.pentest_hints || quickSummary.pentest_playbook || []
  const analystSignals = quickSummary.key_critical_issues || quickSummary.analyst_signals || []
  const scoreBreakdown = Object.entries(score.breakdown || {})

  // Normalise attack chain data — backend emits rich chain objects with steps[],
  // narrative, exploitability etc. Fall back to top findings when not present.
  const chainCards = attackChain.length > 0
    ? attackChain.map(item => {
        if (typeof item !== 'object') return { title: String(item), severity: 'high', description: '', exploitability: null, owasp: [] }
        return {
          title: item.title || '',
          severity: item.severity || 'high',
          description: item.narrative || item.description || '',
          exploitability: item.exploitability ?? null,
          impact: item.impact || '',
          owasp: item.owasp || [],
          steps: item.steps || [],
        }
      })
    : critHighFindings.slice(0, 4).map(f => ({
        title: f.title,
        description: f.description || '',
        severity: f.severity === 'critical' ? 'high' : (f.severity || 'medium'),
        exploitability: null,
        owasp: [],
        steps: [],
      }))

  // Normalise pentest playbook — backend emits plain strings or {title,description} objects.
  // Fall back to derived steps when not present.
  const playbookSteps = pentestHints.length > 0
    ? pentestHints.map(h => typeof h === 'string' ? h : (h.title ? (h.description ? `${h.title} — ${h.description}` : h.title) : String(h)))
    : [
        exportedCount > 0 && `Test ${exportedCount} exported component${exportedCount !== 1 ? 's' : ''} for intent injection and unauthorized access`,
        secrets.length > 0 && `Revoke ${secrets.length} hardcoded credential${secrets.length !== 1 ? 's' : ''} and rotate all affected keys immediately`,
        browsableCount > 0 && `Fuzz ${browsableCount} browsable activit${browsableCount !== 1 ? 'ies' : 'y'} with malformed URI inputs and boundary test cases`,
        (severitySummary.critical || 0) > 0 && `Prioritize ${severitySummary.critical} critical finding${severitySummary.critical !== 1 ? 's' : ''} for immediate patching before release`,
        trackers.length > 0 && `Audit ${trackers.length} embedded tracker${trackers.length !== 1 ? 's' : ''} for GDPR and privacy compliance`,
      ].filter(Boolean).slice(0, 5)

  const insightPills = [
    severitySummary.critical > 0 && { label: `${severitySummary.critical} Critical`, tone: 'critical', nav: 'findings' },
    severitySummary.high > 0 && { label: `${severitySummary.high} High`, tone: 'high', nav: 'findings' },
    trackers.length > 0 && { label: `${trackers.length} Trackers`, tone: 'warning', nav: 'trackers' },
    secrets.length > 0 && { label: `${secrets.length} Secrets`, tone: 'danger', nav: 'secrets' },
    exportedCount > 0 && { label: `${exportedCount} Exported`, tone: 'info', nav: 'surface' },
    browsableCount > 0 && { label: `${browsableCount} Browsable`, tone: 'info', nav: 'browsable' },
    cert.debug_cert && { label: 'Debug Cert', tone: 'danger', nav: 'cert' },
    cert.expired && { label: 'Cert Expired', tone: 'critical', nav: 'cert' },
  ].filter(Boolean)

  const sevTotal = SEVERITY_ORDER.reduce((sum, s) => sum + (severitySummary[s] || 0), 0)

  return (
    <div className="dashboard-stack">

      {/* ── Phase 3: Risk Summary Banner — how bad / where / what now ── */}
      <div className="risk-banner" style={{ '--grade-color': gradeMeta.color }}>
        <div className="risk-banner__grade">
          <div className="risk-banner__grade-letter">{score.grade || '—'}</div>
          <div>
            <div className="risk-banner__score">{score.score ?? 0}<small>/100</small></div>
            <div className="risk-banner__grade-label">{score.grade_label || gradeMeta.label}</div>
          </div>
        </div>
        <div className="risk-banner__sev">
          <div className="risk-banner__bar" role="img" aria-label="Severity distribution">
            {SEVERITY_ORDER.map(sev => {
              const count = severitySummary[sev] || 0
              if (!count) return null
              return <span key={sev} style={{ width: `${(count / Math.max(1, sevTotal)) * 100}%`, background: SEVERITY_META[sev].accent }} title={`${count} ${SEVERITY_META[sev].label}`} />
            })}
          </div>
          <div className="risk-banner__counts">
            {SEVERITY_ORDER.map(sev => {
              const count = severitySummary[sev] || 0
              const toneClass = sev === 'critical' ? ' is-critical' : sev === 'high' ? ' is-high' : ''
              return (
                <button
                  key={sev}
                  type="button"
                  className={`risk-count${toneClass}${count ? '' : ' is-zero'}`}
                  onClick={() => onNavigateSection('findings')}
                >
                  <span className="risk-count__dot" style={{ background: SEVERITY_META[sev].accent }} />
                  {SEVERITY_META[sev].label}
                  <span className="risk-count__n">{count}</span>
                </button>
              )
            })}
            <button type="button" className="risk-count" onClick={() => onNavigateSection('surface')}>
              Exported <span className="risk-count__n">{exportedCount}</span>
            </button>
            <button type="button" className="risk-count" onClick={() => onNavigateSection('browsable')}>
              Browsable <span className="risk-count__n">{browsableCount}</span>
            </button>
            <button type="button" className="risk-count" onClick={() => onNavigateSection('trackers')}>
              Trackers <span className="risk-count__n">{trackers.length}</span>
            </button>
            <button type="button" className="risk-count" onClick={() => onNavigateSection('secrets')}>
              Secrets <span className="risk-count__n">{secrets.length}</span>
            </button>
          </div>
        </div>
      </div>

      {/* ── Quick Insight Bar ── */}
      {insightPills.length > 0 && (
        <div className="dash-insight-bar">
          {insightPills.map(pill => (
            <button
              key={pill.label}
              type="button"
              className={`dash-insight-pill dash-insight-pill--${pill.tone}`}
              onClick={() => onNavigateSection(pill.nav)}
            >
              {pill.label}
            </button>
          ))}
        </div>
      )}

      {/* ── Original 3×2 grid — unchanged ── */}
      <div className="dashboard-grid">
        <Panel className="dashboard-card dashboard-card--score" interactive onClick={() => onNavigateSection('findings')}>
          <div className="dashboard-score-shell">
            <div className="score-ring" style={{ '--score-value': `${scoreValue}%`, '--score-color': gradeMeta.color }}>
              <div className="score-ring__inner">
                <strong>{score.score ?? 0}</strong>
                <span>/100</span>
              </div>
            </div>
            <div className="dashboard-score-copy">
              <div className="dashboard-score-grade" style={{ color: gradeMeta.color }}>{score.grade || '—'}</div>
              <div className="dashboard-score-label">{score.grade_label || gradeMeta.label}</div>
              <button type="button" className="dashboard-inline-link" onClick={() => onNavigateSection('findings')}>
                View findings →
              </button>
            </div>
          </div>
        </Panel>

        <Panel title="App Information" className="dashboard-card" interactive onClick={() => onNavigateSection('info')}>
          <DefinitionRows
            items={[
              ['App Name', results.app_name || info.app_name],
              ['Package', info.package || info.bundle_id || results.filename],
              ['Version', info.version_name || info.version],
              ['Min SDK', info.min_sdk],
              ['Target SDK', info.target_sdk],
              ['Main Activity', info.main_activity],
            ]}
          />
        </Panel>

        <Panel title="File Information" className="dashboard-card">
          <DefinitionRows
            items={[
              ['Filename', results.filename],
              ['Size', formatFileSize(info.size_mb)],
              ['MD5', info.md5],
              ['SHA-256', info.sha256 ? `${String(info.sha256).slice(0, 32)}...` : ''],
              ['Scanned At', formatTimestamp(results.scan_time)],
            ]}
          />
        </Panel>

        <Panel title="Quick Summary" className="dashboard-card dashboard-card--summary" interactive onClick={() => onNavigateSection('findings')}>
          <div className="dashboard-summary-grid">
            {summaryTiles.map(tile => (
              <div key={tile.label} className={`summary-tile summary-tile--${tile.tone}`}>
                <div className="summary-tile__label">{tile.label}</div>
                <div className="summary-tile__value">{tile.value}</div>
              </div>
            ))}
          </div>
          {(quickSummary.key_critical_issues || []).length ? (
            <div className="dashboard-note-list">
              {quickSummary.key_critical_issues.slice(0, viewMode === 'quick' ? 2 : 3).map(issue => (
                <div key={issue} className="dashboard-note">{issue}</div>
              ))}
            </div>
          ) : null}
        </Panel>

        <Panel title="Manifest Security" className="dashboard-card dashboard-card--manifest" interactive onClick={() => onNavigateSection('manifest')}>
          <div className={`manifest-status manifest-status--${primaryManifestCheck.severity}`}>
            <div className="manifest-status__label">{primaryManifestCheck.label}</div>
            <div className="manifest-status__title">{primaryManifestCheck.status}</div>
            <div className="manifest-status__copy">{primaryManifestCheck.reason}</div>
          </div>
          <div className="manifest-check-list">
            {manifestChecks.slice(1, 4).map(check => (
              <div key={check.key} className="manifest-check">
                <span>{check.label}</span>
                <strong>{check.status}</strong>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Performance Breakdown" className="dashboard-card dashboard-card--performance">
          <div className="performance-breakdown">
            {performanceItems.map(item => (
              <div key={item.label} className="performance-row">
                <span>{item.label}</span>
                <strong>{item.value}</strong>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      {/* ── Exported Components Summary (Android) ── */}
      {(activities.length + services.length + receivers.length + providers.length) > 0 && (
        <Panel
          title="Exported Components"
          subtitle="Exposed attack surface — each exported component is reachable from outside the app boundary."
          actions={<button type="button" className="dashboard-inline-link" onClick={() => onNavigateSection('surface')}>View surface →</button>}
        >
          <div className="dash-surface-row">
            {surfaceCards.map(card => (
              <button
                key={card.label}
                type="button"
                className="dash-surface-card"
                style={{ '--card-accent': card.accent, '--card-accent-bg': card.accentBg, '--card-accent-border': card.accentBorder }}
                onClick={() => onNavigateSection(card.nav)}
              >
                <div className="dash-surface-card__exported-count">
                  {card.exported}
                  <span className="dash-surface-card__of-total"> / {card.total}</span>
                </div>
                <div className="dash-surface-card__label">Exported {card.label}</div>
                <div className="dash-surface-card__hint">tap to view →</div>
              </button>
            ))}
          </div>
        </Panel>
      )}

      {/* ── iOS Attack Surface Summary ── */}
      {results.platform === 'ios' && ((surface.url_schemes || []).length > 0 || (surface.universal_links || []).length > 0) && (
        <Panel
          title="iOS Attack Surface"
          subtitle="URL schemes and universal links expose the app to external invocations from other apps and web pages."
          actions={<button type="button" className="dashboard-inline-link" onClick={() => onNavigateSection('surface')}>View surface →</button>}
        >
          <div className="dash-surface-row">
            {(surface.url_schemes || []).length > 0 && (
              <button type="button" className="dash-surface-card" style={{ '--card-accent': '#dc2626', '--card-accent-bg': 'rgba(220,38,38,0.08)', '--card-accent-border': 'rgba(220,38,38,0.25)' }} onClick={() => onNavigateSection('surface')}>
                <div className="dash-surface-card__exported-count">{(surface.url_schemes || []).length}</div>
                <div className="dash-surface-card__label">URL Schemes</div>
                <div className="dash-surface-card__hint">custom URI entry points →</div>
              </button>
            )}
            {(surface.universal_links || []).length > 0 && (
              <button type="button" className="dash-surface-card" style={{ '--card-accent': '#3b82f6', '--card-accent-bg': 'rgba(59,130,246,0.08)', '--card-accent-border': 'rgba(59,130,246,0.25)' }} onClick={() => onNavigateSection('surface')}>
                <div className="dash-surface-card__exported-count">{(surface.universal_links || []).length}</div>
                <div className="dash-surface-card__label">Universal Links</div>
                <div className="dash-surface-card__hint">HTTPS deep links →</div>
              </button>
            )}
          </div>
        </Panel>
      )}

      {/* ── Severity Bars + Trackers ── */}
      <div className="dashboard-2col">
        <Panel
          title="Findings by Severity"
          subtitle="Distribution across severity tiers."
          actions={<button type="button" className="dashboard-inline-link" onClick={() => onNavigateSection('findings')}>View all →</button>}
        >
          <div className="dash-severity-bars">
            {severityBars.filter(bar => bar.count > 0).length > 0
              ? severityBars.filter(bar => bar.count > 0).map(bar => (
                <div key={bar.key} className="dash-severity-row">
                  <span className="dash-severity-label">{bar.label}</span>
                  <div className="dash-severity-track">
                    <div
                      className="dash-severity-fill"
                      style={{ width: `${Math.max(4, (bar.count / maxFindingCount) * 100)}%`, background: bar.color }}
                    />
                  </div>
                  <span className="dash-severity-count">{bar.count}</span>
                </div>
              ))
              : <div className="dash-empty-note">No findings recorded.</div>
            }
          </div>
        </Panel>

        <Panel
          title="Trackers Detected"
          subtitle="Privacy-impacting SDKs embedded in the package."
          actions={trackers.length > 0 ? <button type="button" className="dashboard-inline-link" onClick={() => onNavigateSection('trackers')}>View all →</button> : null}
        >
          {trackers.length > 0 ? (
            <div className="dash-tracker-list">
              {trackers.slice(0, 7).map((tracker, idx) => {
                const name = tracker.name || tracker.tracker_name || 'Unknown tracker'
                const category = tracker.category || tracker.type || ''
                return (
                  <div key={`${name}-${idx}`} className="dash-tracker-row">
                    <span className="dash-tracker-name">{name}</span>
                    {category && <span className="dash-tracker-cat">{category}</span>}
                  </div>
                )
              })}
              {trackers.length > 7 && (
                <button type="button" className="dash-more-note" onClick={() => onNavigateSection('trackers')}>
                  +{trackers.length - 7} more trackers →
                </button>
              )}
            </div>
          ) : (
            <div className="dash-empty-note">No trackers detected in this package.</div>
          )}
        </Panel>
      </div>

      {/* ── Attack Chain + Pentest Playbook ── */}
      {(chainCards.length > 0 || playbookSteps.length > 0) && (
        <div className="dashboard-2col">
          {chainCards.length > 0 && (
            <Panel title="Attack Chain Insight" subtitle="Linked sequence of exploitable weaknesses in this app.">
              <div className="dash-chain">
                {chainCards.map((card, idx) => {
                  const sev = card.severity === 'critical' ? 'high' : (card.severity || 'medium')
                  return (
                    <div key={idx} className={`dash-chain-card dash-chain-card--${sev}`}>
                      <div className="dash-chain-card__header">
                        <span className="dash-chain-card__num">{idx + 1}</span>
                        <span className="dash-chain-card__title">{card.title}</span>
                        <div className="dash-chain-card__badges">
                          <span className={`dash-chain-card__badge dash-chain-card__badge--${sev}`}>
                            {sev.toUpperCase()}
                          </span>
                          {card.exploitability != null && (
                            <span className="dash-chain-card__badge dash-chain-card__badge--exploit">
                              {card.exploitability}% exploitability
                            </span>
                          )}
                        </div>
                      </div>
                      {card.description && (
                        <div className="dash-chain-card__desc">{card.description}</div>
                      )}
                      {card.impact && (
                        <div className="dash-chain-card__impact">
                          <span className="dash-chain-card__impact-label">Impact: </span>{card.impact}
                        </div>
                      )}
                      {card.owasp && card.owasp.length > 0 && (
                        <div className="dash-chain-card__tags">
                          {card.owasp.map(tag => (
                            <span key={tag} className="dash-chain-card__tag">{tag}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </Panel>
          )}
          {playbookSteps.length > 0 && (
            <Panel title="Pentest Playbook" subtitle="Recommended verification steps based on detected issues.">
              <div className="dash-playbook">
                {playbookSteps.map((hint, idx) => (
                  <div key={idx} className="dash-playbook-step">
                    <div className="dash-playbook-step__num">{idx + 1}</div>
                    <span>{hint}</span>
                  </div>
                ))}
              </div>
            </Panel>
          )}
        </div>
      )}

      {/* ── Critical & High Findings ── */}
      {critHighFindings.length > 0 && (
        <Panel
          title="Critical & High Findings"
          subtitle="Priority issues requiring immediate attention."
          actions={<button type="button" className="dashboard-inline-link" onClick={() => onNavigateSection('findings')}>View all findings →</button>}
        >
          <div className="sec-list">
            {critHighFindings.map(finding => {
              const evidence = getPrimaryEvidence(finding)
              const evidenceViewable = evidence && canViewSource(evidence.path, results.decompile_info)
              return (
                <div key={finding.id || finding.title} className={`sec-list-item sec-list-item--${finding.severity}`}>
                  <div className="sec-list-item__header">
                    <div className="sec-list-item__header-left">
                      <SeverityBadge severity={finding.severity} compact />
                      <span className="sec-list-item__name">{finding.title}</span>
                    </div>
                    {evidence && onOpenCode && (
                      evidenceViewable ? (
                        <button type="button" className="icon-button" title="Open in code viewer" onClick={() => onOpenCode(evidence.path, evidence.lines)}>
                          <ArrowUpRight size={14} />
                        </button>
                      ) : (
                        <button type="button" className="icon-button" disabled aria-disabled="true" title={JAVA_SOURCE_UNAVAILABLE_TIP}>
                          <ArrowUpRight size={14} />
                        </button>
                      )
                    )}
                  </div>
                  {finding.description && <div className="sec-list-item__desc">{finding.description}</div>}
                  {evidence && (
                    <div className="sec-list-item__value code-tag">
                      {evidence.path}{evidence.lines.length ? `:${evidence.lines[0]}` : ''}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </Panel>
      )}

      {/* ── Score Breakdown + Certificate + Analyst Signals ── */}
      {(scoreBreakdown.length > 0 || cert.available || analystSignals.length > 0) && (
        <div className="dashboard-2col">
          {scoreBreakdown.length > 0 && (
            <Panel title="Score Breakdown" subtitle="Contribution of each category to the overall score.">
              <div className="dash-score-rows">
                {scoreBreakdown.map(([key, val]) => (
                  <div key={key} className="dash-score-item">
                    <span className="dash-score-item__label">{formatKeyLabel(key)}</span>
                    <span className="dash-score-item__value">{typeof val === 'number' ? val.toFixed(0) : String(val ?? '—')}</span>
                  </div>
                ))}
              </div>
            </Panel>
          )}

          <div className="stack">
            {cert.available && (
              <Panel
                title="Certificate"
                subtitle="Signing certificate summary."
                actions={<button type="button" className="dashboard-inline-link" onClick={() => onNavigateSection('cert')}>View cert →</button>}
              >
                <div className="dash-cert-rows">
                  {[
                    ['Status', cert.debug_cert ? '⚠ Debug certificate' : cert.expired ? '✗ Expired' : '✓ Release-signed'],
                    ['Scheme', (cert.scheme || []).join(', ')],
                    ['Key', cert.key_type ? `${cert.key_type} ${cert.key_size}-bit` : null],
                    ['Valid to', cert.valid_to],
                  ].filter(([, v]) => v).map(([label, value]) => (
                    <div key={label} className={`dash-cert-row${label === 'Status' && (cert.debug_cert || cert.expired) ? ' dash-cert-row--warn' : ''}`}>
                      <span>{label}</span>
                      <strong>{value}</strong>
                    </div>
                  ))}
                </div>
              </Panel>
            )}

            {analystSignals.length > 0 && (
              <Panel title="Analyst Signals" subtitle="Key issues surfaced during analysis.">
                <div className="dash-signals">
                  {analystSignals.slice(0, 5).map((signal, idx) => (
                    <div key={idx} className="dash-signal-row">
                      <AlertTriangle size={12} className="dash-signal-icon" />
                      <span>{signal}</span>
                    </div>
                  ))}
                </div>
                {scanMetrics.semgrep && (
                  <div className="semgrep-status-row">
                    {scanMetrics.semgrep.ran ? (
                      <>
                        <span className="semgrep-status-dot semgrep-status-dot--on" />
                        <span>Semgrep SAST — <strong>{scanMetrics.semgrep.finding_count}</strong> finding{scanMetrics.semgrep.finding_count !== 1 ? 's' : ''} ({Math.round((scanMetrics.semgrep.duration_ms || 0) / 1000)}s)</span>
                      </>
                    ) : (
                      <>
                        <span className="semgrep-status-dot semgrep-status-dot--off" />
                        <span>Semgrep SAST — not installed (run <code>pip install semgrep</code> to enable)</span>
                      </>
                    )}
                  </div>
                )}
              </Panel>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function FindingsSection({ results, onOpenCode, viewMode }) {
  const [severity, setSeverity] = useState('all')
  const [search, setSearch] = useState('')
  const [showTriaged, setShowTriaged] = useState(false)
  const [triageFilter, setTriageFilter] = useState('all')  // 'all' | triage state id

  const scanId = results.scan_id || 'default'
  const { getFindingTriage, getFindingNote, setFindingTriage, triageCount } = useTriage(scanId)
  // Phase 4: table view is the default triage surface; cards stay for deep review.
  const [layout, setLayout] = useState(() => window.localStorage.getItem('beetle-findings-layout') || 'table')
  useEffect(() => { window.localStorage.setItem('beetle-findings-layout', layout) }, [layout])

  const allFindings = results.findings || []
  const workingSet = viewMode === 'quick' ? allFindings.filter(isQuickFinding) : allFindings

  const filtered = workingSet.filter(finding => {
    if (severity !== 'all' && finding.severity !== severity) return false

    const ts = getFindingTriage(finding)
    // Hide triaged (non-open) by default unless showTriaged is on
    if (!showTriaged && ts !== 'open') return false
    // Triage filter
    if (triageFilter !== 'all' && ts !== triageFilter) return false

    if (!search.trim()) return true
    const query = search.toLowerCase()
    return [finding.title, finding.description, finding.category, finding.rule_id]
      .filter(Boolean)
      .some(value => String(value).toLowerCase().includes(query))
  })

  const openCount    = workingSet.filter(f => getFindingTriage(f) === 'open').length
  const triagedCount = workingSet.filter(f => getFindingTriage(f) !== 'open').length

  return (
    <div className="stack">
      <Panel className="findings-toolbar-panel">
        <div className="toolbar">
          <label className="search-field">
            <input value={search} onChange={event => setSearch(event.target.value)} placeholder="Search findings…" />
          </label>
          <div className="chip-row">
            {['all', ...SEVERITY_ORDER].map(key => {
              const baseSet = showTriaged ? workingSet : workingSet.filter(f => getFindingTriage(f) === 'open')
              const count = key === 'all' ? baseSet.length : baseSet.filter(item => item.severity === key).length
              if (key !== 'all' && count === 0) return null
              return (
                <button
                  key={key}
                  type="button"
                  className={`filter-chip${severity === key ? ' is-active' : ''}`}
                  onClick={() => setSeverity(key)}
                >
                  {key === 'all' ? 'All' : (SEVERITY_META[key]?.label || key)} ({count})
                </button>
              )
            })}
          </div>
        </div>

        {/* Triage controls row */}
        <div className="triage-toolbar">
          <div className="triage-toolbar__left">
            <span className="triage-toolbar__label">Triage:</span>
            {(['all', ...TRIAGE_STATES.slice(1).map(s => s.id)]).map(id => {
              const meta  = TRIAGE_META[id]
              const count = id === 'all'
                ? triagedCount
                : workingSet.filter(f => getFindingTriage(f) === id).length
              if (id !== 'all' && count === 0) return null
              return (
                <button
                  key={id}
                  type="button"
                  className={`triage-filter-chip${triageFilter === id && showTriaged ? ' is-active' : ''}`}
                  style={meta?.color ? { '--triage-color': meta.color } : {}}
                  onClick={() => {
                    if (id === 'all') {
                      setShowTriaged(v => !v)
                      setTriageFilter('all')
                    } else {
                      setShowTriaged(true)
                      setTriageFilter(prev => prev === id ? 'all' : id)
                    }
                  }}
                >
                  {id === 'all' ? `Show resolved (${triagedCount})` : `${meta?.label} (${count})`}
                </button>
              )
            })}
          </div>
          {triagedCount > 0 && (
            <span className="triage-toolbar__hint">
              {triagedCount} finding{triagedCount !== 1 ? 's' : ''} triaged · {openCount} open
            </span>
          )}
        </div>
      </Panel>

      <div className="findings-viewtoggle" style={{ marginBottom: 12 }}>
        <button type="button" className={layout === 'table' ? 'is-active' : ''} onClick={() => setLayout('table')}>Table</button>
        <button type="button" className={layout === 'card' ? 'is-active' : ''} onClick={() => setLayout('card')}>Cards</button>
      </div>

      {layout === 'table' ? (
        <FindingsTable
          findings={filtered}
          onOpenCode={onOpenCode}
          decompileInfo={results.decompile_info}
          getFindingTriage={getFindingTriage}
        />
      ) : (
        <FindingsList
          findings={filtered}
          onOpenCode={onOpenCode}
          decompileInfo={results.decompile_info}
          getFindingTriage={getFindingTriage}
          getFindingNote={getFindingNote}
          setFindingTriage={setFindingTriage}
          emptyTitle="No findings match this filter"
          emptyDescription="Try another severity filter or search phrase."
        />
      )}
    </div>
  )
}

function NetworkSecurityPanel({ networkConfig }) {
  if (!networkConfig || !networkConfig.present) {
    return (
      <Panel title="Network Security Config" subtitle="network_security_config.xml">
        <div className="nsc-absent">
          <span className="nsc-absent__icon">⚠</span>
          <div>
            <strong>No network_security_config.xml found.</strong>
            <p>The app relies on Android platform defaults: all system CAs trusted, no certificate pinning, cleartext allowed on Android &lt; 9.</p>
          </div>
        </div>
      </Panel>
    )
  }

  const { base_config, debug_overrides, domain_configs = [], summary = {} } = networkConfig

  const statusDot = (ok) => (
    <span className={`nsc-dot nsc-dot--${ok ? 'good' : 'bad'}`} />
  )

  return (
    <Panel title="Network Security Config" subtitle="Parsed network_security_config.xml — full structural analysis">
      {/* Summary row */}
      <div className="nsc-summary-row">
        <div className="nsc-summary-chip">
          {statusDot(!summary.cleartext_global)}
          <span>Cleartext HTTP: <strong>{summary.cleartext_global ? 'Permitted globally' : 'Restricted'}</strong></span>
        </div>
        <div className="nsc-summary-chip">
          {statusDot(!summary.user_ca_trusted)}
          <span>User CAs: <strong>{summary.user_ca_trusted ? 'Trusted ⚠' : 'Not trusted'}</strong></span>
        </div>
        <div className="nsc-summary-chip">
          {statusDot(summary.has_pinning)}
          <span>Cert Pinning: <strong>{summary.has_pinning ? `${summary.pinned_domain_count} domain(s)` : 'None'}</strong></span>
        </div>
        <div className="nsc-summary-chip">
          {statusDot(!summary.pin_override)}
          <span>Pin Override: <strong>{summary.pin_override ? 'Present ⚠' : 'None'}</strong></span>
        </div>
      </div>

      {/* Base config */}
      {base_config && (
        <div className="nsc-section">
          <div className="nsc-section__label">base-config (applies to all connections)</div>
          <div className="nsc-row">
            <span className="nsc-row__key">Cleartext Traffic</span>
            <span className={`nsc-row__val nsc-row__val--${base_config.cleartextTrafficPermitted ? 'bad' : 'good'}`}>
              {base_config.cleartextTrafficPermitted ? 'Permitted' : 'Blocked'}
            </span>
          </div>
          <div className="nsc-row">
            <span className="nsc-row__key">Trust Anchors</span>
            <span className="nsc-row__val">
              {[
                base_config.trust_anchors?.system && 'System CAs',
                base_config.trust_anchors?.user && <span key="user" className="nsc-tag nsc-tag--warn">User CAs</span>,
                ...(base_config.trust_anchors?.custom_certs || []).map((c, i) => (
                  <span key={i} className="nsc-tag">Custom: {c.src}</span>
                )),
              ].filter(Boolean)}
            </span>
          </div>
        </div>
      )}

      {/* Debug overrides */}
      {debug_overrides && (
        <div className="nsc-section nsc-section--debug">
          <div className="nsc-section__label">debug-overrides <span className="nsc-tag nsc-tag--debug">DEBUG ONLY</span></div>
          <div className="nsc-row">
            <span className="nsc-row__key">User CAs in debug</span>
            <span className="nsc-row__val">{debug_overrides.trust_anchors?.user ? 'Trusted' : 'Not trusted'}</span>
          </div>
          {debug_overrides.overridePins && (
            <div className="nsc-row">
              <span className="nsc-row__key">Pin Override</span>
              <span className="nsc-row__val nsc-row__val--bad">overridePins="true" — pinning bypassed in debug</span>
            </div>
          )}
        </div>
      )}

      {/* Domain configs */}
      {domain_configs.length > 0 && (
        <div className="nsc-section">
          <div className="nsc-section__label">domain-config ({domain_configs.length} block{domain_configs.length !== 1 ? 's' : ''})</div>
          {domain_configs.map((dc, idx) => (
            <div key={idx} className="nsc-domain-block">
              <div className="nsc-domain-block__header">
                {dc.domains.map((d, di) => (
                  <span key={di} className="nsc-domain-tag">
                    {dc.includeSubdomains?.[di] ? `*.${d}` : d}
                  </span>
                ))}
                {dc.cleartextTrafficPermitted && <span className="nsc-tag nsc-tag--warn">Cleartext</span>}
                {dc.pin_set && <span className="nsc-tag nsc-tag--pin">Pinned ({dc.pin_set.pins.length} pin{dc.pin_set.pins.length !== 1 ? 's' : ''})</span>}
              </div>
              {dc.trust_anchors?.user && (
                <div className="nsc-domain-block__row nsc-domain-block__row--warn">User CAs trusted for these domains</div>
              )}
              {dc.pin_set && (
                <div className="nsc-domain-block__pins">
                  {dc.pin_set.expiration && (
                    <span className="nsc-pin-exp">Expires: {dc.pin_set.expiration}</span>
                  )}
                  {dc.pin_set.pins.map((p, pi) => (
                    <div key={pi} className="nsc-pin-row">
                      <span className="nsc-pin-digest">{p.digest}</span>
                      <span className="nsc-pin-val">{p.value.slice(0, 24)}…</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </Panel>
  )
}

function ManifestSection({ results, scanId }) {
  const [manifest, setManifest] = useState(results.manifest_xml || '')
  const [loading, setLoading] = useState(!results.manifest_xml)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false

    if (results.manifest_xml) {
      setManifest(results.manifest_xml)
      setLoading(false)
      setError('')
      return undefined
    }

    setLoading(true)
    setError('')

    apiFetch(`/api/scans/${scanId}/manifest`)
      .then(response => (response.ok ? response.text() : Promise.reject(new Error('Manifest not available for this scan.'))))
      .then(text => {
        if (cancelled) return
        setManifest(text)
      })
      .catch(loadError => {
        if (cancelled) return
        setError(loadError.message)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [results.manifest_xml, scanId])

  return (
    <div className="stack">
      <NetworkSecurityPanel networkConfig={results.network_config} />
      <Panel title="Manifest" subtitle="AndroidManifest.xml — raw source">
        <CodeBlockViewer
          title="AndroidManifest.xml"
          meta="Sticky header, copy action, line numbers, and shared code styling."
          content={manifest}
          language="xml"
          loading={loading}
          error={!loading && !manifest ? error || 'Manifest not available for this scan.' : error}
        />
      </Panel>
    </div>
  )
}

function SourceSection({ scanId, decompileInfo, onOpenCode }) {
  const [files, setFiles] = useState({})
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')

  useEffect(() => {
    let cancelled = false

    setLoading(true)
    apiFetch(`/api/scans/${scanId}/files`)
      .then(response => (response.ok ? response.json() : Promise.reject(new Error('Source listing unavailable.'))))
      .then(payload => {
        if (!cancelled) setFiles(payload.files || {})
      })
      .catch(() => {
        if (!cancelled) setFiles({})
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [scanId])

  const toolNames = decompileInfo?.tools_used || []
  const filteredGroups = Object.entries(files).map(([tool, items]) => ({
    tool,
    items: items.filter(item => !search || item.toLowerCase().includes(search.toLowerCase())),
  })).filter(group => group.items.length)

  return (
    <div className="stack">
      <div className="metric-grid">
        {['jadx', 'apktool'].map(tool => {
          const enabled = toolNames.includes(tool)
          return (
            <Panel key={tool} tone={enabled ? 'accent' : 'default'}>
              <div className="split-row">
                <div>
                  <div className="eyebrow">{tool.toUpperCase()}</div>
                  <div className="panel__title">{tool === 'jadx' ? 'Decompiler ready' : 'Resources ready'}</div>
                </div>
                <Tag tone={enabled ? 'success' : 'neutral'}>{enabled ? 'Enabled' : 'Unavailable'}</Tag>
              </div>
            </Panel>
          )
        })}
      </div>

      <Panel title="Decompiled files" subtitle="Choose a file to open it in the unified code viewer.">
        <div className="toolbar">
          <label className="search-field">
            <input value={search} onChange={event => setSearch(event.target.value)} placeholder="Filter source files…" />
          </label>
        </div>

        {loading ? <EmptyState title="Loading source files" description="Decompiler output is being indexed." /> : null}

        {!loading && !filteredGroups.length ? (
          <EmptyState title="Source output not available" description="Enable JADX or apktool and rescan to populate this browser." />
        ) : null}

        {!loading && filteredGroups.length ? (
          <div className="stack">
            {filteredGroups.map(group => (
              <div key={group.tool} className="stack stack--tight">
                <div className="eyebrow">{group.tool}</div>
                <div className="file-list">
                  {group.items.map(item => (
                    <button key={item} type="button" className="file-list__item" onClick={() => onOpenCode(item, [])}>
                      <span>{item}</span>
                      <ChevronRight size={15} />
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        ) : null}
      </Panel>
    </div>
  )
}

function CodeAnalysisSection({ results, scanId, onOpenCode }) {
  const sastFindings = (results.findings || []).filter(finding => finding.source === 'SAST' || finding.rule_id)

  // ── File browser state (jadx / apktool side-by-side manual explorer) ──
  const [files, setFiles] = useState({})
  const [loading, setLoading] = useState(true)
  const [jadxSearch, setJadxSearch] = useState('')
  const [apktoolSearch, setApktoolSearch] = useState('')
  const [extractSearch, setExtractSearch] = useState('')
  const [jadxLimit, setJadxLimit] = useState(200)
  const [apktoolLimit, setApktoolLimit] = useState(200)
  const [extractLimit, setExtractLimit] = useState(200)

  useEffect(() => {
    if (!scanId) return
    let cancelled = false
    setLoading(true)
    apiFetch(`/api/scans/${scanId}/files`)
      .then(response => (response.ok ? response.json() : Promise.reject(new Error('Source listing unavailable.'))))
      .then(payload => { if (!cancelled) setFiles(payload.files || {}) })
      .catch(() => { if (!cancelled) setFiles({}) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [scanId])

  const jadxFiles    = files.jadx || []
  const apktoolFiles = files.apktool || []
  const extractFiles = files.apk_extract || []

  const filterFiles = (list, q) => {
    if (!q) return list
    const needle = q.toLowerCase()
    return list.filter(item => item.toLowerCase().includes(needle))
  }

  const jadxFiltered    = filterFiles(jadxFiles, jadxSearch)
  const apktoolFiltered = filterFiles(apktoolFiles, apktoolSearch)
  const extractFiltered = filterFiles(extractFiles, extractSearch)

  const renderColumn = (title, subtitle, list, filtered, search, setSearch, limit, setLimit, tree) => (
    <Panel title={title} subtitle={subtitle}>
      <div className="toolbar">
        <label className="search-field">
          <input
            value={search}
            onChange={event => { setSearch(event.target.value); setLimit(200) }}
            placeholder={`Filter ${list.length} files…`}
          />
        </label>
        <Tag tone="neutral">{filtered.length} / {list.length}</Tag>
      </div>
      {list.length === 0 ? (
        <EmptyState title="No files" description={`No ${tree} output was produced for this scan.`} />
      ) : (
        <>
          <div className="file-list" style={{ maxHeight: 520, overflowY: 'auto' }}>
            {filtered.slice(0, limit).map(item => (
              <button key={item} type="button" className="file-list__item" onClick={() => onOpenCode(item, [])}>
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item}</span>
                <ChevronRight size={15} />
              </button>
            ))}
          </div>
          {filtered.length > limit ? (
            <button
              type="button"
              className="filter-chip"
              style={{ marginTop: 8 }}
              onClick={() => setLimit(prev => prev + 500)}
            >
              Show more ({filtered.length - limit} remaining)
            </button>
          ) : null}
        </>
      )}
    </Panel>
  )

  return (
    <div className="stack">
      <div className="metric-grid">
        <StatCard label="SAST Findings" value={sastFindings.length} helper="Code-level detections from the analyzer." accent="#3B82F6" />
        <StatCard label="High Priority" value={sastFindings.filter(item => ['critical', 'high'].includes(item.severity)).length} helper="Issues worth triaging first." accent="#DC2626" />
        <StatCard label="JADX Files" value={jadxFiles.length} helper="Decompiled Java sources." accent="#00C896" />
        <StatCard label="apktool Files" value={apktoolFiles.length} helper="Smali / decoded resources." accent="#F59E0B" />
      </div>

      {loading ? (
        <EmptyState title="Loading decompiled files" description="Indexing jadx and apktool output…" />
      ) : (jadxFiles.length === 0 && apktoolFiles.length === 0 && extractFiles.length === 0) ? (
        <EmptyState
          title="Decompiled output not available"
          description="jadx and apktool did not produce output for this scan. Only static findings are shown below."
        />
      ) : (
        <div
          className="metric-grid"
          style={{
            gridTemplateColumns: `repeat(${[jadxFiles, apktoolFiles, extractFiles].filter(a => a.length).length || 1}, minmax(0, 1fr))`,
            alignItems: 'start',
          }}
        >
          {jadxFiles.length > 0 && renderColumn(
            'JADX — Java Source',
            'Human-readable decompiled Java. Click any file to open in the viewer.',
            jadxFiles, jadxFiltered, jadxSearch, setJadxSearch, jadxLimit, setJadxLimit, 'jadx'
          )}
          {apktoolFiles.length > 0 && renderColumn(
            'apktool — Smali & Resources',
            'Smali bytecode, AndroidManifest.xml (decoded), res/, assets/.',
            apktoolFiles, apktoolFiltered, apktoolSearch, setApktoolSearch, apktoolLimit, setApktoolLimit, 'apktool'
          )}
          {extractFiles.length > 0 && renderColumn(
            'APK Extract — Raw ZIP',
            'Files directly from the APK archive (including binary strings dumps).',
            extractFiles, extractFiltered, extractSearch, setExtractSearch, extractLimit, setExtractLimit, 'apk_extract'
          )}
        </div>
      )}

      <Panel title="SAST Findings" subtitle="Static-analysis detections produced by the code scanner.">
        <FindingsList
          findings={sastFindings}
          onOpenCode={onOpenCode}
          decompileInfo={results.decompile_info}
          emptyTitle="No code analysis findings"
          emptyDescription="This scan did not return SAST-specific detections."
        />
      </Panel>
    </div>
  )
}

function PermissionsSection({ results }) {
  const [openItems, setOpenItems] = useState({})
  const permissions = results.permissions || {}
  const items = permissions.classified?.length
    ? permissions.classified
    : (permissions.all || []).map(item => ({
      permission: item,
      short_name: item.split('.').pop(),
      status: 'normal',
      description: '',
    }))

  if (!items.length) {
    return <EmptyState title="No permissions data" description="This package did not expose permission metadata." />
  }

  const STATUS_ORDER = { dangerous: 0, unknown: 1, signature: 2, normal: 3 }
  const sorted = [...items].sort((a, b) => (STATUS_ORDER[a.status] ?? 2) - (STATUS_ORDER[b.status] ?? 2))
  const dangerCount = items.filter(i => i.status === 'dangerous').length
  const unknownCount = items.filter(i => i.status === 'unknown').length
  const toggle = key => setOpenItems(prev => ({ ...prev, [key]: !prev[key] }))

  return (
    <div className="stack">
      <div className="metric-grid">
        <StatCard label="Total" value={items.length} helper="Declared permissions." accent="#00C896" />
        {dangerCount > 0 && <StatCard label="Dangerous" value={dangerCount} helper="High-risk scope — review first." accent="#DC2626" />}
        {unknownCount > 0 && <StatCard label="Unknown" value={unknownCount} helper="Third-party or unclassified." accent="#F59E0B" />}
        <StatCard label="Normal" value={items.filter(i => i.status === 'normal').length} helper="Standard system permissions." accent="#10B981" />
      </div>
      <Panel title="Permission list" subtitle="Sorted by risk — dangerous permissions appear first. Click to expand details.">
        <div className="perm-list">
          {sorted.map(item => {
            const key = item.permission
            const isOpen = openItems[key]
            const tier = item.status === 'dangerous' ? 'dangerous' : item.status === 'unknown' ? 'unknown' : 'normal'
            return (
              <div key={key} className={`perm-item perm-item--${tier}${isOpen ? ' is-open' : ''}`}>
                <button type="button" className="perm-item__main" onClick={() => toggle(key)}>
                  <div className="perm-item__left">
                    <span className={`perm-item__badge perm-item__badge--${tier}`}>{item.status || 'normal'}</span>
                    <div className="perm-item__names">
                      <span className="perm-item__short">{item.short_name || item.permission.split('.').pop()}</span>
                      <span className="perm-item__full">{item.permission}</span>
                    </div>
                  </div>
                  <ChevronDown size={14} className={`perm-item__chevron${isOpen ? ' is-rotated' : ''}`} />
                </button>
                {isOpen && item.description ? (
                  <div className="perm-item__expand">{item.description}</div>
                ) : null}
              </div>
            )
          })}
        </div>
      </Panel>
    </div>
  )
}

function BrowsableSection({ results }) {
  const surface = results.attack_surface || {}
  const items = (surface.activities || []).filter(item => item.browsable && (item.deeplinks || []).length)
  const [openItems, setOpenItems] = useState({})

  if (!items.length) {
    return <EmptyState title="No browsable activities" description="No deeplinkable exported activity was detected." />
  }

  const toggle = key => setOpenItems(prev => ({ ...prev, [key]: !prev[key] }))
  const customSchemeCount = items.filter(item =>
    (item.schemes || []).some(s => !['http', 'https'].includes(s)),
  ).length

  return (
    <div className="stack">
      <div className="callout callout--warning">Browsable activities can be triggered from outside the app boundary. Verify custom scheme input validation and exported activity intent filters.</div>
      <div className="metric-grid">
        <StatCard label="Browsable" value={items.length} helper="Activities with deep links." accent="#3B82F6" />
        {customSchemeCount > 0 && <StatCard label="Custom Schemes" value={customSchemeCount} helper="Non-HTTP schemes — higher risk." accent="#DC2626" />}
      </div>
      <Panel title="Browsable activities" subtitle="Each activity below is reachable via a URI intent from outside the app.">
        <div className="surface-list">
          {items.map(item => {
            const key = item.name
            const isOpen = openItems[key]
            const hasCustomScheme = (item.schemes || []).some(s => !['http', 'https'].includes(s))
            const risk = item.exported && hasCustomScheme ? 'critical' : item.exported ? 'high' : 'normal'
            return (
              <div key={key} className={`surface-item surface-item--${risk}${isOpen ? ' is-open' : ''}`}>
                <button type="button" className="surface-item__main" onClick={() => toggle(key)}>
                  <div className="surface-item__left">
                    <div className="surface-item__names">
                      <span className="surface-item__short">{item.short_name || item.name.split('.').pop()}</span>
                      <span className="surface-item__full">{item.name}</span>
                    </div>
                    <div className="surface-item__badges">
                      {item.exported && <span className="surface-badge surface-badge--exported">EXPORTED</span>}
                      <span className="surface-badge surface-badge--browsable">BROWSABLE</span>
                      {hasCustomScheme && <span className="surface-badge surface-badge--exported">CUSTOM SCHEME</span>}
                    </div>
                  </div>
                  <ChevronDown size={14} className={`surface-item__chevron${isOpen ? ' is-rotated' : ''}`} />
                </button>
                {isOpen ? (
                  <div className="surface-item__expand">
                    {(item.deeplinks || []).length ? (
                      <div>
                        <span className="surface-item__detail-label">Deep links</span>
                        <div className="tag-row">{item.deeplinks.map(link => <Tag key={link} tone="info">{link}</Tag>)}</div>
                      </div>
                    ) : null}
                    {(item.schemes || []).length ? (
                      <div>
                        <span className="surface-item__detail-label">URI schemes</span>
                        <div className="tag-row">{item.schemes.map(s => <Tag key={s} tone={['http', 'https'].includes(s) ? 'neutral' : 'danger'}>{s}://</Tag>)}</div>
                      </div>
                    ) : null}
                  </div>
                ) : null}
              </div>
            )
          })}
        </div>
      </Panel>
    </div>
  )
}

const TRACKER_ICONS = {
  'Analytics': BarChart2,
  'Crash Reporting': AlertTriangle,
  'Advertising': Megaphone,
  'Identity': UserCheck,
  'Performance': Zap,
  'Network': Network,
  'Social': Users,
  'Location': Globe,
  'Security': Shield,
}

function TrackersSection({ results }) {
  const trackers = results.trackers || []
  if (!trackers.length) {
    return <EmptyState title="No trackers detected" description="The tracker signature set did not match this package." />
  }

  const grouped = trackers.reduce((acc, tracker) => {
    const key = tracker.category || 'Other'
    acc[key] = [...(acc[key] || []), tracker]
    return acc
  }, {})

  return (
    <div className="stack">
      <div className="metric-grid">
        <StatCard label="Total Trackers" value={trackers.length} helper="Privacy-impacting SDKs detected." accent="#F59E0B" />
        <StatCard label="Categories" value={Object.keys(grouped).length} helper="Distinct tracker categories." accent="#8B5CF6" />
      </div>
      <Panel title="Tracker breakdown" subtitle="Privacy-impacting SDK signatures detected in the package.">
        <div className="tracker-group-list">
          {Object.entries(grouped).map(([category, items], groupIndex) => {
            const Icon = TRACKER_ICONS[category] || Shield
            return (
              <div key={category} className={`tracker-group${groupIndex > 0 ? ' tracker-group--divided' : ''}`}>
                <div className="tracker-group__header">
                  <div className="tracker-group__icon"><Icon size={13} /></div>
                  <span className="tracker-group__label">{category}</span>
                  <span className="tracker-group__count">{items.length}</span>
                </div>
                <div className="tracker-item-list">
                  {items.map(item => (
                    <div key={`${item.name}-${item.pkg}`} className="tracker-item">
                      <span className="tracker-item__name">{item.name}</span>
                      <span className="tracker-item__pkg">{item.pkg}</span>
                    </div>
                  ))}
                </div>
              </div>
            )
          })}
        </div>
      </Panel>
    </div>
  )
}

function SecretsSection({ results, onOpenCode }) {
  const secrets = results.secrets || []
  if (!secrets.length) {
    return <EmptyState title="No secrets detected" description="The analyzer did not find embedded credentials or tokens." />
  }

  const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
  const sorted = [...secrets].sort((a, b) =>
    SEV_ORDER.indexOf(a.severity || 'info') - SEV_ORDER.indexOf(b.severity || 'info'),
  )
  const highCount = secrets.filter(s => ['critical', 'high'].includes(s.severity)).length
  const liveCount = secrets.filter(s => s.validated === true).length

  return (
    <div className="stack">
      {liveCount > 0 && (
        <div className="callout callout--danger">
          {liveCount} credential{liveCount !== 1 ? 's were' : ' was'} <strong>confirmed live</strong> by probing the issuer API. These require immediate rotation.
        </div>
      )}
      <div className="metric-grid">
        <StatCard label="Total Secrets" value={secrets.length} helper="Embedded credentials and keys found." accent="#DC2626" />
        {highCount > 0 && <StatCard label="High / Critical" value={highCount} helper="Immediate rotation required." accent="#7F1D1D" />}
        {liveCount > 0 && <StatCard label="Confirmed Live" value={liveCount} helper="Validated active against issuer API." accent="#dc2626" />}
        <StatCard label="Categories" value={[...new Set(secrets.map(s => s.category).filter(Boolean))].length || '—'} helper="Distinct secret types." accent="#F59E0B" />
      </div>
      <Panel>
        <div className="sec-list">
          {sorted.map((item, index) => (
            <div key={`${item.name}-${index}`} className={`sec-list-item sec-list-item--${item.severity || 'info'}${item.validated ? ' sec-list-item--live' : ''}`}>
              <div className="sec-list-item__header">
                <div className="sec-list-item__header-left">
                  <SeverityBadge severity={item.severity} compact />
                  {item.validated && <span className="secret-live-badge">LIVE</span>}
                  <span className="sec-list-item__name">{item.name}</span>
                  {item.category ? <Tag>{item.category}</Tag> : null}
                  {item.severity_bumped && <Tag tone="danger">Severity Escalated</Tag>}
                </div>
                <CopyValueButton value={item.value} label="Copy" />
              </div>
              <div className="code-pill sec-list-item__value">{item.value}</div>
              {item.description ? <div className="sec-list-item__desc">{item.description}</div> : null}
              {item.validated && (
                <div className="secret-live-notice">
                  Confirmed active — this credential was accepted by the issuer API during the scan.
                </div>
              )}
              {item.recommendation ? (
                <div className="sec-list-item__desc" style={{ marginTop: '4px', color: 'var(--text-muted)', fontStyle: 'italic', fontSize: '0.8rem' }}>
                  💡 {item.recommendation}
                </div>
              ) : null}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '6px' }}>
                {item.cwe  ? <Tag tone="neutral" title="Common Weakness Enumeration">{item.cwe}</Tag>  : null}
                {item.masvs ? <Tag tone="neutral" title="OWASP MASVS">{item.masvs}</Tag> : null}
                {item.owasp ? <Tag tone="neutral" title="OWASP Mobile Top 10">OWASP {item.owasp}</Tag> : null}
              </div>
              {(item.full_path || item.source) ? (
                <div className="sec-list-item__footer">
                  <span className="muted-code">{item.full_path || item.source}{item.line ? `:${item.line}` : ''}</span>
                  {item.full_path ? <FileLinkButton path={item.full_path} lines={item.line ? [item.line] : []} onOpenCode={onOpenCode} /> : null}
                </div>
              ) : null}
              {item.snippet ? (
                <div className="code-snippet" style={{ marginTop: '8px' }}>
                  <div className="code-snippet__header">
                    <span>Source snippet</span>
                    <CopyValueButton value={item.snippet} label="Copy" />
                  </div>
                  <pre>{item.snippet}</pre>
                </div>
              ) : null}
            </div>
          ))}
        </div>
      </Panel>
    </div>
  )
}

function _decodeJwtPayload(token) {
  try {
    const parts = token.split('.')
    if (parts.length < 2) return null
    // Pad base64url to standard base64
    const pad = s => s + '='.repeat((4 - s.length % 4) % 4)
    const payload = JSON.parse(atob(pad(parts[1].replace(/-/g, '+').replace(/_/g, '/'))))
    return payload
  } catch {
    return null
  }
}

function JwtSection({ results, onOpenCode }) {
  const jwts = results.jwts || []
  if (!jwts.length) {
    return <EmptyState title="No JWTs found" description="The scan did not identify embedded JWT tokens." />
  }

  return (
    <div className="stack">
      <div className="callout callout--danger">
        Any embedded JWT should be treated as <strong>exposed authentication material</strong> until proven expired or revoked.
        Check the payload for subject (sub), audience (aud), and expiry (exp) claims.
      </div>
      <div className="metric-grid">
        <StatCard label="JWTs Found" value={jwts.length} helper="Hardcoded JSON Web Tokens." accent="#DC2626" />
        <StatCard label="CWE" value="CWE-798" helper="Use of Hard-coded Credentials." accent="#7F1D1D" />
        <StatCard label="OWASP" value="M1" helper="Improper Credential Usage." accent="#B45309" />
      </div>
      <Panel title={`JWT tokens (${jwts.length})`} subtitle="JSON Web Tokens found embedded in the package.">
        <div className="sec-list">
          {jwts.map((item, index) => {
            const decoded = _decodeJwtPayload(item.value)
            const isExpired = decoded?.exp && decoded.exp * 1000 < Date.now()
            const expDate = decoded?.exp ? new Date(decoded.exp * 1000).toLocaleString() : null
            return (
            <div key={`${item.file_path}-${index}`} className={`sec-list-item sec-list-item--high${isExpired ? ' sec-list-item--info' : ''}`}>
              <div className="sec-list-item__header">
                <div className="sec-list-item__header-left">
                  <SeverityBadge severity={isExpired ? 'info' : 'high'} compact />
                  {isExpired && <span style={{ fontSize: '0.7rem', padding: '2px 6px', borderRadius: '4px', background: 'rgba(100,116,139,0.15)', color: 'var(--text-muted)' }}>EXPIRED</span>}
                  <span className="sec-list-item__name">JWT #{index + 1}{decoded?.sub ? ` — sub: ${decoded.sub}` : ''}</span>
                </div>
                <div className="sec-list-item__header-left" style={{ gap: '8px' }}>
                  <CopyValueButton value={item.value} label="Copy" />
                  <a className="button button--secondary button--small" href={`https://jwt.io/#debugger-io?token=${item.value}`} target="_blank" rel="noopener noreferrer">
                    <ArrowUpRight size={13} />
                    Decode
                  </a>
                </div>
              </div>
              <div className="code-pill sec-list-item__value" style={{ wordBreak: 'break-all', fontSize: '0.75rem' }}>{item.value}</div>
              {decoded && (
                <div style={{ marginTop: '8px', padding: '10px 12px', background: 'rgba(0,0,0,0.2)', borderRadius: '8px', fontSize: '0.78rem', fontFamily: 'monospace', border: '1px solid rgba(255,255,255,0.05)' }}>
                  <div style={{ color: 'var(--text-muted)', marginBottom: '6px', fontFamily: 'inherit', fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Decoded payload</div>
                  {decoded.sub  && <div><span style={{ color: 'var(--accent)' }}>sub:</span> {String(decoded.sub)}</div>}
                  {decoded.iss  && <div><span style={{ color: 'var(--accent)' }}>iss:</span> {String(decoded.iss)}</div>}
                  {decoded.aud  && <div><span style={{ color: 'var(--accent)' }}>aud:</span> {JSON.stringify(decoded.aud)}</div>}
                  {expDate      && <div><span style={{ color: isExpired ? '#94a3b8' : '#ef4444' }}>exp:</span> {expDate}{isExpired ? ' (expired)' : ' ⚠ still valid'}</div>}
                  {decoded.role && <div><span style={{ color: '#f59e0b' }}>role:</span> {String(decoded.role)}</div>}
                </div>
              )}
              {item.file_path ? (
                <div className="sec-list-item__footer">
                  <span className="muted-code">{item.file_path}{item.line ? `:${item.line}` : ''}</span>
                  <FileLinkButton path={item.file_path} lines={item.line ? [item.line] : []} onOpenCode={onOpenCode} />
                </div>
              ) : null}
              {item.snippet ? (
                <div className="code-snippet" style={{ marginTop: '8px' }}>
                  <div className="code-snippet__header">
                    <span>Source snippet</span>
                    <CopyValueButton value={item.snippet} label="Copy snippet" />
                  </div>
                  <pre>{item.snippet}</pre>
                </div>
              ) : null}
            </div>
          )
          })}
        </div>
      </Panel>
    </div>
  )
}

function IpsSection({ results, onOpenCode }) {
  const ips = results.ips || []
  if (!ips.length) {
    return <EmptyState title="No hardcoded IPs found" description="No infrastructure IP addresses were extracted from the package." />
  }

  const publicCount = ips.filter(i => i.type === 'public').length

  return (
    <div className="stack">
      <div className="metric-grid">
        <StatCard label="Total IPs" value={ips.length} helper="Hardcoded IP addresses." accent="#F59E0B" />
        {publicCount > 0 && <StatCard label="Public" value={publicCount} helper="Externally routable — review exposure." accent="#DC2626" />}
      </div>
      <Panel title="IP addresses" subtitle="Hardcoded infrastructure references found in the package.">
        <div className="sec-list">
          {ips.map((item, index) => (
            <div key={`${item.ip}-${index}`} className={`sec-list-item sec-list-item--${item.type === 'public' ? 'high' : 'info'}`}>
              <div className="sec-list-item__header">
                <div className="sec-list-item__header-left">
                  <span className="sec-list-item__name">{item.ip}</span>
                  <Tag tone={item.type === 'public' ? 'danger' : 'neutral'}>{item.type || 'unknown'}</Tag>
                </div>
                <CopyValueButton value={item.ip} label="Copy" />
              </div>
              {item.file_path ? (
                <div className="sec-list-item__footer">
                  <span className="muted-code">{item.file_path}{item.line ? `:${item.line}` : ''}</span>
                  <FileLinkButton path={item.file_path} lines={item.line ? [item.line] : []} onOpenCode={onOpenCode} />
                </div>
              ) : null}
            </div>
          ))}
        </div>
      </Panel>
    </div>
  )
}

function StringsSection({ results, onOpenCode }) {
  const entries = Object.entries(results.string_analysis || {})
  if (!entries.length) {
    return <EmptyState title="No sensitive strings found" description="The analyzer did not classify any string buckets for this scan." />
  }

  return (
    <div className="stack">
      {entries.map(([category, info]) => (
        <Panel key={category}>
          <div className="split-row">
            <div>
              <div className="panel__title">{category}</div>
              <div className="panel__subtitle">{info.description}</div>
            </div>
            <SeverityBadge severity={info.severity} compact />
          </div>
          <div className="stack stack--tight">
            {(info.matches || []).slice(0, 12).map((match, index) => {
              const isObject = typeof match === 'object' && match !== null
              const value = isObject ? match.value : match
              const files = isObject ? match.files || [] : []

              return (
                <div key={`${category}-${index}`} className="evidence-row">
                  <div className="evidence-row__meta">
                    <div className="code-pill">{value}</div>
                    {files[0] ? <div className="muted-code">{files[0]}</div> : null}
                  </div>
                  {files[0] ? <FileLinkButton path={files[0]} lines={[]} onOpenCode={onOpenCode} /> : null}
                </div>
              )
            })}
          </div>
        </Panel>
      ))}
    </div>
  )
}

function SurfaceSection({ results }) {
  const surface = results.attack_surface || {}
  const isIos = results.platform === 'ios'

  // Always call hooks unconditionally (React rules of hooks)
  const [activeType, setActiveType] = useState('activities')
  const [openItems, setOpenItems] = useState({})

  // ── iOS attack surface ────────────────────────────────────────────────────
  if (isIos) {
    const urlSchemes       = surface.url_schemes       || []
    const universalLinks   = surface.universal_links   || []
    const exportedHandlers = surface.exported_handlers || []
    const hasAny = urlSchemes.length || universalLinks.length || exportedHandlers.length

    if (!hasAny) {
      return <EmptyState title="No attack surface detected" description="No URL schemes, universal links, or exported handlers found in the IPA." />
    }
    return (
      <div className="stack">
        <div className="metric-grid">
          {urlSchemes.length > 0 && <StatCard label="URL Schemes" value={urlSchemes.length} helper="Custom URI schemes — callable from any app or web page." accent="#DC2626" />}
          {universalLinks.length > 0 && <StatCard label="Universal Links" value={universalLinks.length} helper="HTTPS deep links associated with this app." accent="#3B82F6" />}
          {exportedHandlers.length > 0 && <StatCard label="Exported Handlers" value={exportedHandlers.length} helper="Extension points accessible to other processes." accent="#F59E0B" />}
        </div>
        {urlSchemes.length > 0 && (
          <Panel title={`URL Schemes (${urlSchemes.length})`} subtitle="These custom schemes allow any app or website to open your app with a crafted URI. Validate all parameters passed via URL scheme handlers.">
            <div className="sec-list">
              {urlSchemes.map((scheme, i) => (
                <div key={`${scheme}-${i}`} className="sec-list-item sec-list-item--high">
                  <div className="sec-list-item__header">
                    <div className="sec-list-item__header-left">
                      <span className="surface-badge surface-badge--exported">URL SCHEME</span>
                      <span className="sec-list-item__name">{scheme}://</span>
                    </div>
                    <CopyValueButton value={`${scheme}://`} label="Copy" />
                  </div>
                  <div className="sec-list-item__desc" style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    Any app can invoke <code>{scheme}://path?param=value</code>. Ensure parameter validation prevents open-redirect, XSS, or path traversal via URL scheme inputs.
                  </div>
                </div>
              ))}
            </div>
          </Panel>
        )}
        {universalLinks.length > 0 && (
          <Panel title={`Universal Links (${universalLinks.length})`} subtitle="HTTPS links claimed by this app via Apple App Site Association (AASA). Verify your AASA file is scoped to minimum required paths.">
            <div className="sec-list">
              {universalLinks.map((link, i) => (
                <div key={`${link}-${i}`} className="sec-list-item sec-list-item--medium">
                  <div className="sec-list-item__header">
                    <div className="sec-list-item__header-left">
                      <span className="surface-badge surface-badge--browsable">UNIVERSAL LINK</span>
                      <span className="sec-list-item__name" style={{ fontSize: '0.82rem', wordBreak: 'break-all' }}>{link}</span>
                    </div>
                    <CopyValueButton value={link} label="Copy" />
                  </div>
                </div>
              ))}
            </div>
          </Panel>
        )}
        {exportedHandlers.length > 0 && (
          <Panel title={`Exported Handlers (${exportedHandlers.length})`} subtitle="Extension points and XPC services exposed outside the app process boundary.">
            <div className="sec-list">
              {exportedHandlers.map((handler, i) => (
                <div key={`${handler}-${i}`} className="sec-list-item sec-list-item--medium">
                  <div className="sec-list-item__header">
                    <div className="sec-list-item__header-left">
                      <span className="surface-badge surface-badge--exported">HANDLER</span>
                      <span className="sec-list-item__name">{handler}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </Panel>
        )}
      </div>
    )
  }

  // ── Android attack surface ────────────────────────────────────────────────
  const types = ['activities', 'services', 'receivers', 'providers']
  const items = surface[activeType] || []
  const appId = results.app_info?.package || ''

  const sorted = [...items].sort((a, b) => {
    const score = item => (item.exported ? 2 : 0) + (item.browsable ? 1 : 0)
    return score(b) - score(a)
  })

  const toggle = key => setOpenItems(prev => ({ ...prev, [key]: !prev[key] }))
  const exportedCount = items.filter(i => i.exported).length
  const browsableCount = items.filter(i => i.browsable).length
  // Permissionless = exported with no guarding permission — the highest-risk subset.
  const permissionlessCount = items.filter(i => i.exported && !i.permission).length

  return (
    <div className="stack">
      <div className="chip-row">
        {types.map(type => (
          <button
            key={type}
            type="button"
            className={`filter-chip${activeType === type ? ' is-active' : ''}`}
            onClick={() => { setActiveType(type); setOpenItems({}) }}
          >
            {type[0].toUpperCase() + type.slice(1)} ({(surface[type] || []).length})
          </button>
        ))}
      </div>

      {items.length ? (
        <>
          <div className="metric-grid">
            {exportedCount > 0 && <StatCard label="Exported" value={exportedCount} helper="Reachable from outside the app." accent="#DC2626" />}
            {permissionlessCount > 0 && <StatCard label="Permissionless" value={permissionlessCount} helper="Exported with no guarding permission — highest risk." accent="#7F1D1D" />}
            {browsableCount > 0 && <StatCard label="Browsable" value={browsableCount} helper="Can be triggered via deep link." accent="#F59E0B" />}
            <StatCard label="Total" value={items.length} helper={`${activeType} registered in manifest.`} accent="#6e7b8a" />
          </div>
          <Panel title={`${activeType.charAt(0).toUpperCase() + activeType.slice(1)} (${items.length})`} subtitle="Exported + browsable components are sorted first — these are your primary attack surface.">
            <div className="surface-list">
              {sorted.map(item => {
                const key = item.name
                const isOpen = openItems[key]
                const risk = (item.exported && item.browsable) ? 'critical' : item.exported ? 'high' : 'normal'
                const adbCmd = activeType === 'activities'
                  ? `adb shell am start -n ${appId}/${item.name}`
                  : activeType === 'services'
                    ? `adb shell am startservice -n ${appId}/${item.name}`
                    : `adb shell am broadcast -a ${(item.actions || [])[0] || 'ACTION'} -n ${appId}/${item.name}`
                return (
                  <div key={key} className={`surface-item surface-item--${risk}${isOpen ? ' is-open' : ''}`}>
                    <button type="button" className="surface-item__main" onClick={() => toggle(key)}>
                      <div className="surface-item__left">
                        <div className="surface-item__names">
                          <span className="surface-item__short">{item.short_name || item.name.split('.').pop()}</span>
                          <span className="surface-item__full">{item.name}</span>
                        </div>
                        <div className="surface-item__badges">
                          {item.exported && <span className="surface-badge surface-badge--exported">EXPORTED</span>}
                          {item.browsable && <span className="surface-badge surface-badge--browsable">BROWSABLE</span>}
                        </div>
                      </div>
                      <ChevronDown size={14} className={`surface-item__chevron${isOpen ? ' is-rotated' : ''}`} />
                    </button>
                    {isOpen ? (
                      <div className="surface-item__expand">
                        {(item.deeplinks || []).length ? (
                          <div className="surface-item__detail">
                            <span className="surface-item__detail-label">Deep links</span>
                            <div className="tag-row">{item.deeplinks.map(link => <Tag key={link} tone="info">{link}</Tag>)}</div>
                          </div>
                        ) : null}
                        {(item.actions || []).length ? (
                          <div className="surface-item__detail">
                            <span className="surface-item__detail-label">Intent actions</span>
                            <div className="tag-row">{item.actions.map(a => <Tag key={a}>{a}</Tag>)}</div>
                          </div>
                        ) : null}
                        {item.exported && appId ? (
                          <div className="surface-item__detail">
                            <span className="surface-item__detail-label">ADB command</span>
                            <div className="code-snippet"><pre>{adbCmd}</pre></div>
                          </div>
                        ) : null}
                      </div>
                    ) : null}
                  </div>
                )
              })}
            </div>
          </Panel>
        </>
      ) : (
        <EmptyState title={`No ${activeType} found`} description="This component class is empty for the current scan." />
      )}
    </div>
  )
}

function CertSection({ results }) {
  const cert = results.certificate || {}
  const overview = cert.security_overview || {}
  const overviewItems = [
    ['Overall', overview.overall],
    ['Signature scheme', (cert.scheme || []).join(', ')],
    ['Debug certificate', cert.debug_cert ? 'Yes' : 'No'],
    ['Expired', cert.expired ? 'Yes' : 'No'],
  ]

  return (
    <div className="stack">
      <div className="metric-grid">
        {overviewItems.filter(([, value]) => value).map(([label, value]) => (
          <StatCard key={label} label={label} value={value} helper="" accent={label === 'Overall' && overview.overall === 'Vulnerable' ? '#DC2626' : '#00C896'} />
        ))}
      </div>

      {cert.available ? (
        <Panel title="Signing certificate" subtitle="X.509 and release-signing details extracted from the package.">
          <DefinitionRows
            items={[
              ['Subject', Object.entries(cert.subject || {}).map(([key, value]) => `${key}=${value}`).join(', ')],
              ['Issuer', Object.entries(cert.issuer || {}).map(([key, value]) => `${key}=${value}`).join(', ')],
              ['Algorithm', cert.signature_algo],
              ['Key type', cert.key_type ? `${cert.key_type} ${cert.key_size}-bit` : ''],
              ['Valid from', cert.valid_from],
              ['Valid to', cert.valid_to],
              ['SHA-1', cert.sha1_fingerprint],
              ['SHA-256', cert.sha256_fingerprint],
            ]}
          />
        </Panel>
      ) : (
        <div className="callout callout--warning">{cert.unavailable_reason || 'Certificate extraction is limited for this signing setup.'}</div>
      )}
    </div>
  )
}

function EndpointsSection({ results }) {
  const endpoints = results.endpoints || []
  const [search, setSearch] = useState('')
  const filtered = endpoints.filter(item => item.toLowerCase().includes(search.toLowerCase()))

  if (!endpoints.length) {
    return <EmptyState title="No endpoints found" description="The scan did not extract URL or API targets." />
  }

  return (
    <Panel title="Endpoints" subtitle="Use these URLs to map auth boundaries and reachable services.">
      <div className="toolbar">
        <label className="search-field">
          <input value={search} onChange={event => setSearch(event.target.value)} placeholder="Filter endpoints…" />
        </label>
      </div>

      <div className="stack stack--tight">
        {filtered.map(endpoint => (
          <div key={endpoint} className="evidence-row">
            <div className="evidence-row__meta">
              <div className="muted-code">{endpoint}</div>
            </div>
            <a className="button button--ghost button--small" href={endpoint} target="_blank" rel="noopener noreferrer">
              <ArrowUpRight size={14} />
              Open
            </a>
          </div>
        ))}
      </div>
    </Panel>
  )
}

function DomainsSection({ results }) {
  const domains = results.domain_intel || []
  if (!domains.length) {
    return <EmptyState title="No domain intelligence" description="No domain enrichment results are available for this scan." />
  }

  const flaggedCount = domains.filter(d => d.ofac || d.malicious).length

  const getDomainTag = item => {
    if (item.is_cdn || item.domain?.includes('cdn') || item.domain?.includes('static')) return { label: 'CDN', tone: 'info' }
    if (item.is_tracker) return { label: 'Tracker', tone: 'warning' }
    if (item.domain?.startsWith('api.') || item.domain?.includes('/api')) return { label: 'API', tone: 'danger' }
    return { label: '3rd-party', tone: 'neutral' }
  }

  return (
    <div className="stack">
      <div className="metric-grid">
        <StatCard label="Domains" value={domains.length} helper="Discovered domains." accent="#3B82F6" />
        {flaggedCount > 0 && <StatCard label="Flagged" value={flaggedCount} helper="OFAC / threat-listed entries." accent="#DC2626" />}
      </div>
      <Panel title="Domain list" subtitle="Use this list to map third-party exposure and data-flow boundaries.">
        <div className="domain-list">
          {domains.map(item => {
            const tag = getDomainTag(item)
            const location = [item.city, item.country].filter(Boolean).join(', ')
            return (
              <div key={item.domain} className={`domain-item${item.ofac || item.malicious ? ' domain-item--flagged' : ''}`}>
                <div className="domain-item__main">
                  <span className="domain-item__name">{item.domain}</span>
                  <div className="domain-item__tags">
                    <Tag tone={tag.tone}>{tag.label}</Tag>
                    {item.ofac && <Tag tone="danger">OFAC</Tag>}
                    <Tag tone={item.status === 'ok' ? 'success' : 'neutral'}>{item.status || 'unknown'}</Tag>
                  </div>
                </div>
                {(item.ip || location) ? (
                  <div className="domain-item__meta">
                    {item.ip ? <span className="muted-code">{item.ip}</span> : null}
                    {location ? <span className="domain-item__location">{location}</span> : null}
                  </div>
                ) : null}
              </div>
            )
          })}
        </div>
      </Panel>
    </div>
  )
}

function BinarySection({ results }) {
  const binaries = results.binaries || []
  if (!binaries.length) {
    return <EmptyState title="No binary analysis" description="Native ELF protection data was not returned for this package." />
  }

  const checks = ['nx', 'pie', 'stack_canary', 'relro', 'fortify', 'stripped']

  return (
    <Panel title="Binary hardening" subtitle="Native library mitigation coverage across packaged shared objects.">
      <div className="table-shell">
        <table className="data-table">
          <thead>
            <tr>
              <th>Library</th>
              {checks.map(check => <th key={check}>{check.replace('_', ' ')}</th>)}
            </tr>
          </thead>
          <tbody>
            {binaries.map(item => (
              <tr key={item.name}>
                <td className="mono">{item.name}</td>
                {checks.map(check => {
                  const value = item[check]
                  const ok = value === true || value === 'full' || value === 'partial'
                  // "stripped" inverts: a stripped binary is the hardened/desirable state.
                  const pass = check === 'stripped' ? ok : ok
                  const note = typeof value === 'string' && !['true', 'false'].includes(value) ? value : ''
                  return (
                    <td key={check}>
                      <span className={`checksec-pill checksec-pill--${pass ? 'pass' : 'fail'}`}>
                        {pass ? 'Yes' : 'No'}
                        {note ? <span className="checksec-pill__note">({note})</span> : null}
                      </span>
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  )
}

function ApiSection({ results, onOpenCode }) {
  const entries = Object.entries(results.android_api || {})
  if (!entries.length) {
    return <EmptyState title="No Android API usage" description="The analyzer did not classify platform API categories for this scan." />
  }

  return (
    <div className="stack">
      {entries.map(([category, files]) => (
        <Panel key={category} title={category} subtitle={`${files.length} file${files.length === 1 ? '' : 's'} reference this API area`}>
          <div className="stack stack--tight">
            {files.map(file => (
              <div key={file} className="evidence-row">
                <div className="evidence-row__meta">
                  <div className="muted-code">{file}</div>
                </div>
                <FileLinkButton path={file} lines={[]} onOpenCode={onOpenCode} />
              </div>
            ))}
          </div>
        </Panel>
      ))}
    </div>
  )
}

function EmailsSection({ results }) {
  const emails = results.emails || []
  if (!emails.length) {
    return <EmptyState title="No email strings found" description="The scan did not surface embedded email addresses." />
  }

  return (
    <Panel title={`Email addresses (${emails.length})`} subtitle="Embedded contact strings discovered in the package.">
      <div className="sec-list">
        {emails.map((item, index) => (
          <div key={`${item.email}-${index}`} className="sec-list-item sec-list-item--info">
            <div className="sec-list-item__header">
              <div className="sec-list-item__header-left">
                <span className="sec-list-item__name">{item.email}</span>
              </div>
              <CopyValueButton value={item.email} label="Copy" />
            </div>
            {(item.files || []).length ? (
              <div className="sec-list-item__files">
                {item.files.map(file => <span key={file} className="muted-code">{file}</span>)}
              </div>
            ) : null}
          </div>
        ))}
      </div>
    </Panel>
  )
}

function SdksSection({ results }) {
  const sdks = results.sdks || []
  if (!sdks.length) {
    return <EmptyState title="No third-party SDKs" description="The analyzer did not classify embedded SDKs in this package." />
  }

  const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
  const sorted = [...sdks].sort((a, b) =>
    SEV_ORDER.indexOf(a.severity || 'info') - SEV_ORDER.indexOf(b.severity || 'info'),
  )
  const highCount = sdks.filter(s => ['critical', 'high'].includes(s.severity)).length

  return (
    <div className="stack">
      <div className="metric-grid">
        <StatCard label="SDKs" value={sdks.length} helper="Third-party packages detected." accent="#8B5CF6" />
        {highCount > 0 && <StatCard label="High Risk" value={highCount} helper="High-severity embedded SDKs." accent="#DC2626" />}
        <StatCard label="Categories" value={[...new Set(sdks.map(s => s.category).filter(Boolean))].length || '—'} helper="Distinct SDK categories." accent="#F59E0B" />
      </div>
      <Panel title="SDK breakdown" subtitle="Embedded third-party frameworks sorted by risk.">
        <div className="sec-list">
          {sorted.map(item => (
            <div key={`${item.package}-${item.name}`} className={`sec-list-item sec-list-item--${item.severity || 'info'}`}>
              <div className="sec-list-item__header">
                <div className="sec-list-item__header-left">
                  <SeverityBadge severity={item.severity} compact />
                  <span className="sec-list-item__name">{item.name}</span>
                  {item.category ? <Tag>{item.category}</Tag> : null}
                </div>
              </div>
              <span className="muted-code">{item.package}</span>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  )
}

function ApkidSection({ results }) {
  const entries = Object.entries(results.apkid || {})
  if (!entries.length) {
    return <EmptyState title="No APKiD data" description="Compiler and anti-analysis fingerprints were not returned." />
  }

  return (
    <div className="stack">
      {entries.map(([dex, findings]) => (
        <Panel key={dex} title={dex} subtitle="Compiler and protection fingerprinting">
          <div className="stack stack--tight">
            {Object.entries(findings).map(([category, values]) => (
              <div key={category} className="split-row">
                <span>{category}</span>
                <div className="tag-row">
                  {values.map(value => <Tag key={value}>{value}</Tag>)}
                </div>
              </div>
            ))}
          </div>
        </Panel>
      ))}
    </div>
  )
}

function MasvsSection({ results }) {
  const findings = results.findings || []
  const categories = [
    { key: 'MASVS-STORAGE', label: 'Storage' },
    { key: 'MASVS-CRYPTO', label: 'Crypto' },
    { key: 'MASVS-AUTH', label: 'Auth' },
    { key: 'MASVS-NETWORK', label: 'Network' },
    { key: 'MASVS-PLATFORM', label: 'Platform' },
    { key: 'MASVS-CODE', label: 'Code' },
    { key: 'MASVS-RESILIENCE', label: 'Resilience' },
  ]

  return (
    <div className="stack">
      {categories.map(category => {
        const matches = findings.filter(item => item.masvs?.startsWith(category.key))
        return (
          <Panel key={category.key} title={category.key} subtitle={category.label}>
            {matches.length ? (
              <div className="stack stack--tight">
                {matches.slice(0, 6).map(item => (
                  <div key={`${category.key}-${item.title}`} className="split-row">
                    <span>{item.title}</span>
                    <SeverityBadge severity={item.severity} compact />
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState title="No mapped findings" description="This standards bucket has no tagged issues in the current results." />
            )}
          </Panel>
        )
      })}
    </div>
  )
}

// ── Taint Flows ───────────────────────────────────────────────────────────────
const SINK_CATEGORY_COLORS = {
  Logging:    '#f59e0b',
  Network:    '#3b82f6',
  SQLite:     '#ef4444',
  FileSystem: '#8b5cf6',
  Crypto:     '#ec4899',
  Execution:  '#dc2626',
  WebView:    '#f97316',
  Intent:     '#6366f1',
  Storage:    '#10b981',
}

function TaintFlowCard({ flow }) {
  const [open, setOpen] = useState(false)
  // Accept both shapes: finding-shape (flow.taint_flow.*) and raw flow-shape (flow.*)
  const tf = flow.taint_flow || {}
  const chain = tf.chain || flow.call_chain || flow.chain || []
  const sinkCat = tf.sink_cat || flow.sink_cat || flow.category || 'Unknown'
  const sourceName = tf.source || flow.source || ''
  const sinkName = tf.sink || flow.sink || ''
  const title = flow.title || (sourceName && sinkName
    ? `Taint Flow: ${sourceName} → ${sinkName}`
    : 'Taint Flow')
  const color = SINK_CATEGORY_COLORS[sinkCat] || '#6b7280'
  const sev = flow.severity || flow.sink_sev || 'medium'

  return (
    <div
      className="taint-flow-card"
      style={{ '--taint-color': color }}
      onClick={() => setOpen(o => !o)}
      role="button"
      tabIndex={0}
      onKeyDown={e => e.key === 'Enter' && setOpen(o => !o)}
    >
      <div className="taint-flow-card__top">
        <div className="taint-flow-card__badges">
          <span className="taint-flow-card__sev-badge" data-sev={sev}>{sev}</span>
          <span className="taint-flow-card__cat-badge">{sinkCat}</span>
        </div>
        <div className="taint-flow-card__title">{title}</div>
        <ChevronDown size={14} className={`taint-flow-card__chevron ${open ? 'is-open' : ''}`} />
      </div>

      {open && (
        <div className="taint-flow-card__body">
          {chain.length > 0 && (
            <div className="taint-flow-card__chain">
              <div className="taint-flow-card__chain-label">Call chain</div>
              <ol className="taint-flow-card__chain-list">
                {chain.map((step, i) => (
                  <li key={i} className="taint-flow-card__chain-step">
                    <span className="taint-flow-card__chain-num">{i + 1}</span>
                    <code className="taint-flow-card__chain-code">{step}</code>
                  </li>
                ))}
              </ol>
            </div>
          )}
          <div className="taint-flow-card__meta-row">
            {flow.cwe && <span className="code-pill">{flow.cwe}</span>}
            {flow.masvs && <span className="code-pill">{flow.masvs}</span>}
            {flow.owasp && <span className="code-pill">OWASP {flow.owasp}</span>}
          </div>
          {flow.recommendation && (
            <div className="taint-flow-card__rec">{flow.recommendation}</div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── VirusTotal Section ───────────────────────────────────────────────────────

const VT_VERDICT_META = {
  clean:      { label: 'Clean',      color: '#10B981', bg: 'rgba(16,185,129,0.12)' },
  suspicious: { label: 'Suspicious', color: '#F59E0B', bg: 'rgba(245,158,11,0.12)' },
  malicious:  { label: 'Malicious',  color: '#DC2626', bg: 'rgba(220,38,38,0.12)'  },
  unknown:    { label: 'Not Found',  color: '#6B7280', bg: 'rgba(107,114,128,0.1)' },
  error:      { label: 'Error',      color: '#F97316', bg: 'rgba(249,115,22,0.12)' },
}

function VtFileCard({ report, label }) {
  if (!report) return null
  const verdict = report.verdict || 'unknown'
  const meta = VT_VERDICT_META[verdict] || VT_VERDICT_META.unknown
  const engines = report.engines || []

  return (
    <div className="vt-file-card">
      <div className="vt-file-header">
        <div className="vt-file-meta">
          <span className="vt-file-label">{label}</span>
          <span className="vt-file-name">{report.filename || report.hash?.slice(0, 12) + '…'}</span>
        </div>
        <div className="vt-verdict-pill" style={{ color: meta.color, background: meta.bg }}>
          {meta.label}
        </div>
      </div>

      <div className="vt-stats-row">
        <div className="vt-stat vt-stat--mal">
          <span className="vt-stat-value">{report.malicious ?? '—'}</span>
          <span className="vt-stat-lbl">Malicious</span>
        </div>
        <div className="vt-stat vt-stat--sus">
          <span className="vt-stat-value">{report.suspicious ?? '—'}</span>
          <span className="vt-stat-lbl">Suspicious</span>
        </div>
        <div className="vt-stat vt-stat--ok">
          <span className="vt-stat-value">{report.undetected ?? '—'}</span>
          <span className="vt-stat-lbl">Undetected</span>
        </div>
        <div className="vt-stat">
          <span className="vt-stat-value">{report.detection_ratio}</span>
          <span className="vt-stat-lbl">Ratio</span>
        </div>
      </div>

      {(report.threat_label || report.family) && (
        <div className="vt-threat-row">
          {report.threat_label && <span className="vt-tag vt-tag--threat">{report.threat_label}</span>}
          {report.family && <span className="vt-tag vt-tag--family">{report.family}</span>}
        </div>
      )}

      {engines.length > 0 && (
        <div className="vt-engines">
          <div className="vt-engines-title">Detections ({engines.length})</div>
          <table className="vt-engine-table">
            <thead>
              <tr>
                <th>Engine</th>
                <th>Result</th>
                <th>Category</th>
              </tr>
            </thead>
            <tbody>
              {engines.map((e, i) => (
                <tr key={i} className={`vt-engine-row vt-engine-row--${e.category}`}>
                  <td>{e.engine}</td>
                  <td>{e.result || '—'}</td>
                  <td>
                    <span className={`vt-cat-badge vt-cat-badge--${e.category}`}>{e.category}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="vt-file-footer">
        {report.last_analysis_date && (
          <span className="vt-meta-text">Last analysed: {report.last_analysis_date}</span>
        )}
        {report.hash && (
          <span className="vt-hash-text">{report.hash}</span>
        )}
        {report.permalink && (
          <a
            className="vt-permalink"
            href={report.permalink}
            target="_blank"
            rel="noopener noreferrer"
          >
            View on VirusTotal ↗
          </a>
        )}
      </div>
    </div>
  )
}

function VirusTotalSection({ results }) {
  const vt = results.virustotal || {}

  if (!vt.api_key_set) {
    return (
      <div className="section-empty">
        <Shield size={32} className="section-empty-icon" />
        <div className="section-empty-title">VirusTotal not configured</div>
        <div className="section-empty-body">
          Set the <code>VIRUSTOTAL_API_KEY</code> environment variable to enable hash-based
          reputation checks against 70+ AV engines.
        </div>
      </div>
    )
  }

  if (vt.error && !vt.main) {
    return (
      <div className="section-empty">
        <AlertTriangle size={32} className="section-empty-icon" />
        <div className="section-empty-title">Lookup failed</div>
        <div className="section-empty-body">{vt.error}</div>
      </div>
    )
  }

  const dexFiles = vt.dex_files || []
  const anyMalicious = (vt.main?.malicious ?? 0) > 0 || dexFiles.some(d => d.malicious > 0)

  return (
    <div className="vt-section">
      {anyMalicious && (
        <div className="vt-alert-banner">
          <AlertTriangle size={16} />
          <span>One or more files were flagged as malicious. Do not distribute or execute this application.</span>
        </div>
      )}

      <VtFileCard report={vt.main} label="Main binary" />

      {dexFiles.length > 0 && (
        <div className="vt-dex-group">
          <div className="vt-dex-title">Embedded DEX files ({dexFiles.length})</div>
          {dexFiles.map((d, i) => (
            <VtFileCard key={i} report={d} label={`DEX ${i + 1}`} />
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Taint Section ────────────────────────────────────────────────────────────

function TaintSection({ results }) {
  const flows = (results.taint_flows || [])
  const taintFindings = (results.findings || []).filter(f => f.source === 'TAINT')
  const allFlows = flows.length > 0 ? flows : taintFindings

  // Group by sink category
  const byCat = {}
  for (const flow of allFlows) {
    const cat = flow.taint_flow?.sink_cat || flow.sink_cat || flow.category || 'Unknown'
    if (!byCat[cat]) byCat[cat] = []
    byCat[cat].push(flow)
  }
  const cats = Object.keys(byCat).sort()

  const ran = results.scan_metrics?.taint?.ran
  const err = results.scan_metrics?.taint?.error

  if (allFlows.length === 0) {
    return (
      <div className="section-wrap">
        <Panel
          title="Taint Flows"
          subtitle="Inter-procedural data-flow analysis"
          icon={<Route size={15} />}
        >
          <EmptyState
            title={err ? 'Taint analysis failed' : ran === false ? 'No taint flows detected' : 'Taint analysis not available'}
            description={
              err
                ? err
                : ran === false
                ? 'No source→sink data-flow paths were found in this APK.'
                : 'Taint analysis requires androguard with full DEX support. Install androguard and re-scan.'
            }
          />
        </Panel>
      </div>
    )
  }

  return (
    <div className="section-wrap">
      <Panel
        title="Taint Flows"
        subtitle={`${allFlows.length} source→sink path${allFlows.length !== 1 ? 's' : ''} detected`}
        icon={<Route size={15} />}
        badge={allFlows.length}
      >
        <div className="taint-flow-list">
          {cats.map(cat => (
            <div key={cat} className="taint-flow-group">
              <div className="taint-flow-group__header" style={{ '--taint-color': SINK_CATEGORY_COLORS[cat] || '#6b7280' }}>
                <span className="taint-flow-group__dot" />
                <span className="taint-flow-group__name">{cat}</span>
                <span className="taint-flow-group__count">{byCat[cat].length}</span>
              </div>
              {byCat[cat].map((flow, i) => (
                <TaintFlowCard key={i} flow={flow} />
              ))}
            </div>
          ))}
        </div>
      </Panel>
    </div>
  )
}

// ── Vulnerable Components ─────────────────────────────────────────────────────

function ComponentsSection({ results }) {
  const components = results.components || []
  const cveFindings = (results.findings || []).filter(f => f.source === 'CVE-MAP')
  const stats = results.cve_stats || {}

  const [filterSev, setFilterSev]   = useState('all')
  const [kevOnly, setKevOnly]       = useState(false)
  const [hasFixOnly, setHasFixOnly] = useState(false)
  const [hideInfo, setHideInfo]     = useState(true)

  // Group findings by (product, version).
  const byComponent = {}
  for (const f of cveFindings) {
    const key = f.component
      ? `${f.component.product}@${f.component.version}`
      : (f.rule_id || f.title)
    if (!byComponent[key]) byComponent[key] = []
    byComponent[key].push(f)
  }

  const applyFilters = (cves) => cves.filter(c => {
    if (hideInfo && c.severity === 'info') return false
    if (filterSev !== 'all' && c.severity !== filterSev) return false
    if (kevOnly && !c.kev) return false
    if (hasFixOnly && !c.fix_version) return false
    return true
  })

  const rows = components.map(c => ({
    ...c,
    cves: applyFilters(byComponent[`${c.product}@${c.version}`] || []),
  }))

  // Sort: highest-severity CVEs first, then by CVE count, then by name.
  const sevRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
  rows.sort((a, b) => {
    const maxA = Math.max(0, ...a.cves.map(c => sevRank[c.severity] || 0))
    const maxB = Math.max(0, ...b.cves.map(c => sevRank[c.severity] || 0))
    if (maxA !== maxB) return maxB - maxA
    if (a.cves.length !== b.cves.length) return b.cves.length - a.cves.length
    return a.product.localeCompare(b.product)
  })

  if (components.length === 0 && cveFindings.length === 0) {
    return (
      <div className="section-wrap">
        <Panel
          title="Vulnerable Components"
          subtitle="Bundled OSS library CVE mapping"
          icon={<Boxes size={15} />}
        >
          <EmptyState
            title="No bundled components detected"
            description="Beetle could not identify any known OSS library versions in this app's native binaries. This usually means the app has no native dependencies, or their version strings were stripped."
          />
        </Panel>
      </div>
    )
  }

  const totalCves = cveFindings.length
  const critHigh = cveFindings.filter(f => f.severity === 'critical' || f.severity === 'high').length
  const kevCount = cveFindings.filter(f => f.kev).length

  return (
    <div className="section-wrap">
      <Panel
        title="Vulnerable Components"
        subtitle={`${components.length} component${components.length !== 1 ? 's' : ''} detected · ${totalCves} CVE${totalCves !== 1 ? 's' : ''} matched${critHigh ? ` · ${critHigh} critical/high` : ''}${kevCount ? ` · ${kevCount} KEV` : ''}`}
        icon={<Boxes size={15} />}
        badge={totalCves || components.length}
      >
        <div className="components-filter-bar">
          <div className="components-filter-group">
            <span className="components-filter-label">Severity:</span>
            {['all', 'critical', 'high', 'medium', 'low'].map(sev => (
              <button
                key={sev}
                type="button"
                className={`components-filter-chip ${filterSev === sev ? 'is-active' : ''}`}
                onClick={() => setFilterSev(sev)}
              >
                {sev === 'all' ? 'All' : sev[0].toUpperCase() + sev.slice(1)}
              </button>
            ))}
          </div>
          <label className="components-filter-toggle">
            <input type="checkbox" checked={kevOnly} onChange={e => setKevOnly(e.target.checked)} />
            KEV only
          </label>
          <label className="components-filter-toggle">
            <input type="checkbox" checked={hasFixOnly} onChange={e => setHasFixOnly(e.target.checked)} />
            Has fix available
          </label>
          <label className="components-filter-toggle">
            <input type="checkbox" checked={hideInfo} onChange={e => setHideInfo(e.target.checked)} />
            Hide info-level
          </label>
        </div>

        <div className="components-list">
          {rows.map(row => (
            <ComponentCard key={`${row.product}@${row.version}`} row={row} />
          ))}
        </div>
        {stats.binaries_scanned ? (
          <div className="components-footnote">
            Scanned {stats.binaries_scanned} binaries · {stats.components_detected} versioned components · data from OSV.dev (cached 24h).
          </div>
        ) : null}
      </Panel>
    </div>
  )
}

function ComponentCard({ row }) {
  const [open, setOpen] = useState(false)
  const hasCves = row.cves.length > 0
  const maxSev = hasCves
    ? row.cves.reduce((acc, c) => {
        const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
        return (rank[c.severity] || 0) > (rank[acc] || 0) ? c.severity : acc
      }, 'info')
    : null

  return (
    <div className={`component-card ${hasCves ? 'component-card--vuln' : ''}`}>
      <div
        className="component-card__header"
        onClick={() => hasCves && setOpen(o => !o)}
        role={hasCves ? 'button' : undefined}
        tabIndex={hasCves ? 0 : -1}
      >
        <div className="component-card__ident">
          <div className="component-card__name">{row.product}</div>
          <div className="component-card__version">v{row.version}</div>
          {row.ecosystem ? <div className="component-card__ecosystem">{row.ecosystem}</div> : null}
          {row.binary ? <div className="component-card__binary">{row.binary}</div> : null}
        </div>
        <div className="component-card__badges">
          {hasCves ? (
            <>
              {row.kev_count ? (
                <span className="component-card__kev" title="CISA Known Exploited Vulnerability">
                  {row.kev_count} KEV
                </span>
              ) : null}
              <SeverityBadge severity={maxSev} />
              <span className="component-card__cve-count">{row.cves.length} CVE{row.cves.length !== 1 ? 's' : ''}</span>
              <ChevronDown size={14} className={`component-card__chevron ${open ? 'is-open' : ''}`} />
            </>
          ) : (
            <span className="component-card__ok">No known CVEs</span>
          )}
        </div>
      </div>

      {open && hasCves && (
        <div className="component-card__body">
          {row.cves.map((cve, i) => (
            <div key={i} className="cve-item">
              <div className="cve-item__top">
                <SeverityBadge severity={cve.severity} />
                <code className="cve-item__id">{cve.cve || cve.rule_id}</code>
                {cve.kev ? <span className="cve-item__kev" title="CISA Known Exploited Vulnerability — actively exploited in the wild">KEV</span> : null}
                {cve.cvss ? <span className="cve-item__cvss">CVSS {cve.cvss}</span> : null}
                {cve.fix_version ? <span className="cve-item__fix">Fixed in {cve.fix_version}</span> : null}
              </div>
              {cve.description ? (
                <div className="cve-item__desc">{cve.description}</div>
              ) : null}
              {cve.recommendation ? (
                <div className="cve-item__rec">{cve.recommendation}</div>
              ) : null}
              {cve.cve ? (
                <a
                  className="cve-item__link"
                  href={`https://nvd.nist.gov/vuln/detail/${cve.cve}`}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  View on NVD <ArrowUpRight size={12} />
                </a>
              ) : null}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── iOS Deep Analysis Sections ────────────────────────────────────────────────

const SEVERITY_COLOR = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#16a34a', info: '#6b7280' }

function KeyValueTable({ rows }) {
  return (
    <table className="ios-kv-table">
      <tbody>
        {rows.map(([k, v]) => (
          <tr key={k}>
            <td className="ios-kv-table__key">{k}</td>
            <td className="ios-kv-table__val">{String(v ?? '—')}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function EntitlementsSection({ results }) {
  const ents = results.entitlements || {}
  const keys = Object.keys(ents)
  const info = results.app_info || {}

  return (
    <div className="section-wrap">
      <Panel title="Entitlements" subtitle="Provisioning profile capabilities" icon={<Shield size={15} />}>
        {keys.length === 0 ? (
          <EmptyState title="No entitlements data" description="Entitlements are extracted from embedded.mobileprovision or .xcent files. Not available for this scan." />
        ) : (
          <>
            {(info.provisioning_team || info.provisioning_type) && (
              <KeyValueTable rows={[
                ['Team',    info.provisioning_team || '—'],
                ['Profile', info.provisioning_profile || '—'],
                ['Type',    info.provisioning_type || '—'],
                ['Expiry',  info.provisioning_expiry ? info.provisioning_expiry.slice(0, 10) : '—'],
                ['Debug Build', info.debug_build ? 'Yes (get-task-allow)' : 'No'],
              ]} />
            )}
            <div className="ios-entitlements-list">
              {keys.map(k => (
                <div key={k} className="ios-entitlement-row">
                  <code className="ios-entitlement-row__key">{k}</code>
                  <span className="ios-entitlement-row__val">{JSON.stringify(ents[k])}</span>
                </div>
              ))}
            </div>
          </>
        )}
      </Panel>
    </div>
  )
}

function IosFrameworksSection({ results }) {
  const fws = results.embedded_frameworks || []
  const known   = fws.filter(f => f.known)
  const unknown = fws.filter(f => !f.known)

  return (
    <div className="section-wrap">
      <Panel title="Embedded Frameworks" subtitle={`${fws.length} framework${fws.length !== 1 ? 's' : ''} detected`} icon={<Boxes size={15} />} badge={fws.length}>
        {fws.length === 0 ? (
          <EmptyState title="No frameworks detected" description="No embedded .framework bundles found in the app bundle." />
        ) : (
          <>
            {known.length > 0 && (
              <>
                <div className="ios-fw-header">Known frameworks</div>
                <div className="ios-fw-list">
                  {known.map(f => (
                    <div key={f.name} className="ios-fw-row">
                      <span className="ios-fw-row__name">{f.name}</span>
                      <span className="ios-fw-row__cat">{f.category}</span>
                      <span className="ios-fw-row__sev" style={{ color: SEVERITY_COLOR[f.severity] }}>{f.severity}</span>
                      <span className="ios-fw-row__desc">{f.description}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
            {unknown.length > 0 && (
              <>
                <div className="ios-fw-header">Unknown / custom frameworks</div>
                <div className="ios-fw-list">
                  {unknown.map(f => (
                    <div key={f.name} className="ios-fw-row">
                      <span className="ios-fw-row__name">{f.name}</span>
                      <span className="ios-fw-row__path">{f.path}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </>
        )}
      </Panel>
    </div>
  )
}

function BoolRow({ label, value, goodWhen = true }) {
  const ok = value === goodWhen
  return (
    <div className="ios-bool-row">
      <span className="ios-bool-row__label">{label}</span>
      <span className={`ios-bool-row__badge ${ok ? 'ios-bool-row__badge--ok' : 'ios-bool-row__badge--warn'}`}>
        {value === null || value === undefined ? '—' : (value ? 'Yes' : 'No')}
      </span>
    </div>
  )
}

function IosStorageSection({ results }) {
  const s = results.ios_data_storage || {}
  const inv = results.file_inventory || {}

  return (
    <div className="section-wrap">
      <Panel title="Data Storage" subtitle="Storage mechanism detection and security posture" icon={<HardDrive size={15} />}>
        <div className="ios-bool-grid">
          <BoolRow label="Uses Keychain"         value={s.uses_keychain}     goodWhen={true} />
          <BoolRow label="Uses NSUserDefaults"   value={s.uses_userdefaults} goodWhen={false} />
          <BoolRow label="Uses CoreData"         value={s.uses_coredata}     goodWhen={null} />
          <BoolRow label="Uses Realm"            value={s.uses_realm}        goodWhen={null} />
          <BoolRow label="Uses SQLite"           value={s.uses_sqlite}       goodWhen={null} />
          <BoolRow label="File Protection Used"  value={s.data_protection}   goodWhen={true} />
          <BoolRow label="Backup Excluded"       value={s.backup_excluded}   goodWhen={true} />
        </div>
        {(inv.suspicious || []).length > 0 && (
          <>
            <div className="ios-fw-header" style={{ marginTop: 16 }}>Suspicious files in bundle</div>
            <div className="ios-fw-list">
              {inv.suspicious.slice(0, 20).map((f, i) => (
                <div key={i} className="ios-fw-row">
                  <code className="ios-entitlement-row__key">{f.path}</code>
                  <span className="ios-fw-row__desc">{f.reason}</span>
                </div>
              ))}
            </div>
          </>
        )}
      </Panel>
    </div>
  )
}

function IosCryptoSection({ results }) {
  const c = results.ios_crypto || {}

  return (
    <div className="section-wrap">
      <Panel title="Cryptography" subtitle="iOS crypto API usage and weak algorithm detection" icon={<KeyRound size={15} />}>
        <div className="ios-bool-grid">
          <BoolRow label="Uses CommonCrypto"      value={c.uses_commonCrypto}  goodWhen={null} />
          <BoolRow label="Uses CryptoKit (modern)"value={c.uses_cryptoKit}     goodWhen={true} />
          <BoolRow label="Uses Security Framework"value={c.uses_security_fw}   goodWhen={null} />
          <BoolRow label="Uses OpenSSL"           value={c.uses_openssl}       goodWhen={false} />
        </div>
        {(c.weak_algorithms || []).length > 0 && (
          <div className="ios-weak-algos">
            <div className="ios-fw-header" style={{ color: '#dc2626' }}>Weak algorithms detected</div>
            <div className="tag-row" style={{ marginTop: 6 }}>
              {c.weak_algorithms.map(a => (
                <span key={a} className="tag" style={{ background: 'rgba(220,38,38,0.08)', color: '#dc2626', borderColor: 'rgba(220,38,38,0.2)' }}>{a}</span>
              ))}
            </div>
          </div>
        )}
        {!(c.weak_algorithms || []).length && (
          <EmptyState title="No weak algorithms detected" description="No broken or deprecated cryptographic algorithms were identified in source files." />
        )}
      </Panel>
    </div>
  )
}

function IosWebviewSection({ results }) {
  const w = results.ios_webview || {}

  return (
    <div className="section-wrap">
      <Panel title="WebView / JS Bridges" subtitle="WebView configuration and JavaScript bridge exposure" icon={<Globe size={15} />}>
        <div className="ios-bool-grid">
          <BoolRow label="Uses WKWebView"      value={w.uses_wkwebview}    goodWhen={true} />
          <BoolRow label="Uses UIWebView (deprecated)" value={w.uses_uiwebview} goodWhen={false} />
          <BoolRow label="Loads Local Files"   value={w.loads_local_files} goodWhen={null} />
          <BoolRow label="Loads Remote URLs"   value={w.loads_remote_urls} goodWhen={null} />
        </div>
        {(w.bridge_handlers || []).length > 0 && (
          <div style={{ marginTop: 12 }}>
            <div className="ios-fw-header">JS Bridge Handlers</div>
            <div className="tag-row" style={{ marginTop: 6 }}>
              {w.bridge_handlers.map(h => <Tag key={h}>{h}</Tag>)}
            </div>
          </div>
        )}
        {w.uses_wkwebview === false && w.uses_uiwebview === false && (
          <EmptyState title="No WebView usage detected" description="No WKWebView or UIWebView references found in source files." />
        )}
      </Panel>
    </div>
  )
}

function CompareSection({ scanId }) {
  const [history, setHistory] = useState([])
  const [selected, setSelected] = useState('')
  const [loading, setLoading] = useState(false)
  const [diff, setDiff] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    apiFetch('/api/scans?limit=20')
      .then(response => (response.ok ? response.json() : null))
      .then(payload => setHistory((payload?.scans || []).filter(item => item.scan_id !== scanId)))
      .catch(() => setHistory([]))
  }, [scanId])

  const handleCompare = async () => {
    if (!selected) return
    setLoading(true)
    setError('')
    setDiff(null)

    try {
      const response = await apiFetch(`/api/compare?scan_a=${scanId}&scan_b=${selected}`)
      if (!response.ok) throw new Error(`Compare failed (${response.status})`)
      setDiff(await response.json())
    } catch (compareError) {
      setError(compareError.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="stack">
      <Panel title="Compare scans" subtitle="Validate whether fixes removed issues cleanly instead of shifting them elsewhere.">
        <div className="toolbar">
          <label className="search-field search-field--select">
            <select value={selected} onChange={event => setSelected(event.target.value)}>
              <option value="">Select a previous scan…</option>
              {history.map(item => (
                <option key={item.scan_id} value={item.scan_id}>
                  {item.app_name || item.filename} · {item.grade || '?'} · {formatTimestamp(item.created_at || item.scan_time)}
                </option>
              ))}
            </select>
          </label>
          <button type="button" className="button" onClick={handleCompare} disabled={!selected || loading}>
            {loading ? 'Comparing…' : 'Compare'}
          </button>
        </div>
        {error ? <div className="callout callout--danger">{error}</div> : null}
      </Panel>

      {diff ? (
        <>
          <div className="metric-grid">
            <StatCard label="New" value={diff.summary?.new_count || 0} helper="Issues introduced in the selected scan." accent="#DC2626" />
            <StatCard label="Fixed" value={diff.summary?.fixed_count || 0} helper="Issues removed since the baseline." accent="#10B981" />
            <StatCard label="Unchanged" value={diff.summary?.unchanged || 0} helper="Findings still present in both scans." accent="#475569" />
          </div>

          {(diff.new || []).length ? (
            <Panel title="New issues" subtitle="Findings that appeared in the current scan.">
              <FindingsList findings={diff.new} onOpenCode={null} />
            </Panel>
          ) : null}

          {(diff.fixed || []).length ? (
            <Panel title="Fixed issues" subtitle="Findings present in the baseline but no longer detected now.">
              <div className="stack stack--tight">
                {diff.fixed.map(item => (
                  <div key={`${item.title}-${item.id || item.rule_id}`} className="list-card list-card--success">
                    <div className="list-card__top">
                      <div>
                        <div className="list-card__title-row">
                          <SeverityBadge severity={item.severity} compact />
                        </div>
                        <div className="list-card__title">{item.title}</div>
                      </div>
                      <CheckCircle2 size={18} color="#10B981" />
                    </div>
                  </div>
                ))}
              </div>
            </Panel>
          ) : null}
        </>
      ) : null}
    </div>
  )
}

function InfoSection({ results }) {
  const info = results.app_info || {}
  return (
    <div className="section-grid">
      <Panel title="Package identity" subtitle="Everything needed to identify the uploaded app artifact.">
        <DefinitionRows
          items={[
            ['App name', info.app_name || results.app_name],
            ['Identifier', info.package || info.bundle_id],
            ['Version', info.version_name || info.version],
            ['Filename', results.filename],
            ['Platform', results.platform],
            ['Scan ID', results.scan_id],
            ['Scan time', formatTimestamp(results.scan_time)],
          ]}
        />
      </Panel>

      <Panel title="Hashes and size" subtitle="Useful for artifact verification and traceability.">
        <DefinitionRows
          items={[
            ['Size', formatFileSize(info.size_mb)],
            ['MD5', info.md5],
            ['SHA-256', info.sha256],
          ]}
        />
      </Panel>
    </div>
  )
}

function DependenciesSection({ results }) {
  const deps = results.dependencies || {}
  const allDeps = deps.deps || []
  const vulnerable = deps.vulnerable || []
  const safe = deps.safe || []
  const osvMetrics = results.scan_metrics?.osv || {}

  if (!allDeps.length) {
    return (
      <div className="stack">
        <EmptyState
          title="No dependencies detected"
          description="No build.gradle, pom.xml, package.json, or pubspec.yaml files were found in the decompiled source."
        />
      </div>
    )
  }

  const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']

  return (
    <div className="stack">
      {osvMetrics.error && !vulnerable.length && (
        <div className="callout callout--warning">
          OSV.dev query encountered an issue: {osvMetrics.error}. Results may be incomplete.
        </div>
      )}

      <div className="metric-grid">
        <StatCard label="Total Libraries" value={allDeps.length} helper="Unique dependencies found across all build files." accent="#3b82f6" />
        <StatCard label="Vulnerable" value={vulnerable.length} helper="Libraries with known CVEs from OSV.dev." accent={vulnerable.length ? '#dc2626' : '#10b981'} />
        <StatCard label="Safe" value={safe.filter(d => !d.unqueried).length} helper="Queried — no known CVEs." accent="#10b981" />
        {deps.queried < allDeps.length && (
          <StatCard label="Unqueried" value={allDeps.length - (deps.queried || 0)} helper={`Capped at ${deps.queried} queries per scan.`} accent="#f59e0b" />
        )}
      </div>

      {vulnerable.length > 0 && (
        <Panel title="Vulnerable Libraries" subtitle="Libraries with known CVEs from OSV.dev.">
          <div className="dep-list">
            {vulnerable.map((dep, idx) => (
              <div key={idx} className="dep-item dep-item--vuln">
                <div className="dep-item__header">
                  <span className="dep-item__name">{dep.name || dep.artifact}</span>
                  <span className="dep-item__version">{dep.version}</span>
                  <span className="dep-badge dep-badge--ecosystem">{dep.ecosystem}</span>
                  <span className="dep-badge dep-badge--vuln">{dep.vuln_count} CVE{dep.vuln_count !== 1 ? 's' : ''}</span>
                </div>
                {dep.vulnerabilities?.slice(0, 3).map((v, vi) => (
                  <div key={vi} className="dep-item__cve">
                    <span className="dep-cve-id">{v.id}</span>
                    <span className="dep-cve-summary">{v.summary}</span>
                  </div>
                ))}
                <div className="dep-item__source">Source: {dep.source}</div>
              </div>
            ))}
          </div>
        </Panel>
      )}

      <Panel
        title="All Dependencies"
        subtitle={`${allDeps.length} unique librar${allDeps.length !== 1 ? 'ies' : 'y'} detected across build files.`}
      >
        <div className="dep-list">
          {allDeps.map((dep, idx) => {
            const isVuln = (dep.vuln_count || 0) > 0
            return (
              <div key={idx} className={`dep-item${isVuln ? ' dep-item--vuln' : ''}`}>
                <div className="dep-item__header">
                  <span className="dep-item__name">{dep.name || dep.artifact}</span>
                  <span className="dep-item__version">{dep.version}</span>
                  <span className="dep-badge dep-badge--ecosystem">{dep.ecosystem}</span>
                  {isVuln && <span className="dep-badge dep-badge--vuln">{dep.vuln_count} CVE{dep.vuln_count !== 1 ? 's' : ''}</span>}
                  {dep.unqueried && <span className="dep-badge dep-badge--unqueried">Not queried</span>}
                </div>
                <div className="dep-item__source">Source: {dep.source}</div>
              </div>
            )
          })}
        </div>
      </Panel>
    </div>
  )
}

export default function SectionViews({ sectionId, results, scanId, onNavigateSection, onOpenCode, viewMode }) {
  if (!results) return null

  const sharedProps = { results, scanId, onNavigateSection, onOpenCode, viewMode }

  switch (sectionId) {
    case 'dashboard':
      return <DashboardSection {...sharedProps} />
    case 'findings':
      return <FindingsSection {...sharedProps} />
    case 'manifest':
      return <ManifestSection {...sharedProps} />
    case 'source':
      return <SourceSection scanId={scanId} decompileInfo={results.decompile_info || {}} onOpenCode={onOpenCode} />
    case 'code':
      return <CodeAnalysisSection {...sharedProps} />
    case 'permissions':
      return <PermissionsSection {...sharedProps} />
    case 'browsable':
      return <BrowsableSection {...sharedProps} />
    case 'trackers':
      return <TrackersSection {...sharedProps} />
    case 'secrets':
      return <SecretsSection {...sharedProps} />
    case 'jwts':
      return <JwtSection {...sharedProps} />
    case 'ips':
      return <IpsSection {...sharedProps} />
    case 'strings':
      return <StringsSection {...sharedProps} />
    case 'surface':
      return <SurfaceSection {...sharedProps} />
    case 'cert':
      return <CertSection {...sharedProps} />
    case 'endpoints':
      return <EndpointsSection {...sharedProps} />
    case 'domains':
      return <DomainsSection {...sharedProps} />
    case 'binary':
      return <BinarySection {...sharedProps} />
    case 'api':
      return <ApiSection {...sharedProps} />
    case 'emails':
      return <EmailsSection {...sharedProps} />
    case 'sdks':
      return <SdksSection {...sharedProps} />
    case 'deps':
      return <DependenciesSection {...sharedProps} />
    case 'apkid':
      return <ApkidSection {...sharedProps} />
    case 'masvs':
      return <MasvsSection {...sharedProps} />
    case 'virustotal':
      return <VirusTotalSection {...sharedProps} />
    case 'taint':
      return <TaintSection {...sharedProps} />
    case 'components':
      return <ComponentsSection {...sharedProps} />
    case 'entitlements':
      return <EntitlementsSection {...sharedProps} />
    case 'ios_frameworks':
      return <IosFrameworksSection {...sharedProps} />
    case 'ios_storage':
      return <IosStorageSection {...sharedProps} />
    case 'ios_crypto':
      return <IosCryptoSection {...sharedProps} />
    case 'ios_webview':
      return <IosWebviewSection {...sharedProps} />
    case 'compare':
      return <CompareSection scanId={scanId} />
    case 'info':
      return <InfoSection {...sharedProps} />
    default:
      return <EmptyState title="Section unavailable" description="The requested workspace section is not registered." />
  }
}

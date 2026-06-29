// Phase 13 workspace panels. Presentation only — consumes the existing `results`
// blob (findings, analyst_explanation, secrets_summary, cloud_attack_paths,
// masvs_coverage/masvs_summary, trust_score). No backend calls except onOpenCode.
import { useEffect, useMemo, useState } from 'react'
import {
  ArrowUpRight, FileCode2, KeyRound, ShieldAlert, Boxes, ExternalLink,
  ChevronRight, Layers, Download, FileJson, GitBranch, ShieldCheck,
  ScrollText, Network, Fingerprint, Cpu, Bug, Sparkles, GitCompare,
  Briefcase, Wrench,
} from 'lucide-react'
import { RadarChart, PolarGrid, PolarAngleAxis, Radar, ResponsiveContainer } from 'recharts'
import {
  SEV_ORDER, SEV_RANK, SEV_COLOR, normSev, SeverityTag, SoftTag, EmptyState, Metric,
  severityCounts, ownershipLabel, confidenceLabel, findingPath, findingLines, buildEvidence,
  evidenceUnavailableReason, useEscape,
} from './ui.jsx'
import { FINDING_AI_ACTIONS, fetchAiProviders, runFindingAction } from '../../lib/ai-providers.js'
import {
  findingKey, FINDING_STATES, STATE_META, PRIORITIES, canWrite, renderMarkdown,
} from '../../lib/collab.js'
import {
  getEvidenceView, detectionSources, trustScore, trustBand, confidenceContributions,
  reachabilityLabel, matchesFilters, findingDetectionSourceSet, findingFrameworkSet,
  OWNERSHIP_OPTIONS,
} from './evidence-model.js'
import { useWorkspaceNav } from './workspace-context.jsx'

// Small coloured pill showing a finding's triage state / priority / assignee.
function StateBadge({ meta }) {
  if (!meta) return null
  const sm = STATE_META[meta.state]
  return (
    <>
      {sm && meta.state !== 'open'
        ? <span className="ws-tag" style={{ background: sm.color + '22', color: sm.color, fontWeight: 650 }}>{sm.label}</span>
        : null}
      {meta.priority ? <span className="ws-tag" style={{ background: '#1118', color: '#fff', fontWeight: 650 }}>{meta.priority}</span> : null}
      {meta.assignee ? <SoftTag title="Assignee">@{meta.assignee}</SoftTag> : null}
    </>
  )
}

// ───────────────────────────── Overview ──────────────────────────────────
export function OverviewPanel({ results, onOpenSection, onOpenFinding, onOpenCode }) {
  const info = results.app_info || {}
  const score = results.score || {}
  const trust = results.trust_score || {}
  const res = results.resolution_scores || {}
  const findings = results.findings || []
  const counts = severityCounts(findings)
  const total = findings.length || 1
  const chains = results.cloud_attack_paths || []
  const secretsSum = results.secrets_summary || {}
  const analyst = results.analyst_summary || {}
  const masvs = results.masvs_summary || {}
  const version = info.version_name || info.version || info.bundle_version || '—'

  const topRisks = analyst.top_risks || []
  const allChains = [...chains, ...findings.filter(f => f.is_attack_chain)]
  const topChain = (analyst.most_exploitable_chains || [])[0] || allChains[0]

  return (
    <div>
      <div className="ws-ident">
        <div className="ws-ident__avatar">
          {info.icon_data ? <img src={info.icon_data} alt="" /> : (results.app_name || 'B')[0].toUpperCase()}
        </div>
        <div>
          <h1>{results.app_name || 'Unknown app'}</h1>
          <div className="ws-ident__pkg ws-mono">{info.package || info.bundle_id || results.filename} · v{version}</div>
        </div>
      </div>

      {/* Metric strip */}
      <div className="ws-metrics ws-section">
        {results.ciso_summary?.risk_rating ? <Metric label="Risk Rating" value={results.ciso_summary.risk_rating} sub="business risk" /> : null}
        <Metric label="Trust Score" value={`${trust.score ?? '—'}`} rating={trust.rating} />
        <Metric label="Security Score" value={<>{score.score ?? '—'}<small>/100</small></>} sub={score.grade ? `Grade ${score.grade}` : ''} />
        <Metric label="Source Resolution" value={`${res.source_resolution_pct ?? '—'}%`} sub="findings located" />
        <Metric label="View Code" value={`${res.view_code_coverage_pct ?? '—'}%`} sub="renderable evidence" />
        <Metric label="Attack Chains" value={chains.length} sub="cloud exposure paths" />
        <Metric label="Secrets" value={secretsSum.total_application_secrets ?? (results.secrets || []).length} sub={`${secretsSum.suppressed_sdk_secrets ?? 0} SDK suppressed`} />
      </div>

      {/* Risk summary */}
      <div className="ws-card ws-card--pad ws-section">
        <h2>Risk Summary</h2>
        <div className="ws-sevbar">
          {SEV_ORDER.map(s => counts[s] ? (
            <span key={s} style={{ width: `${(counts[s] / total) * 100}%`, background: SEV_COLOR[s] }} title={`${counts[s]} ${s}`} />
          ) : null)}
        </div>
        <div className="ws-sevlegend">
          {SEV_ORDER.map(s => (
            <span key={s} className="ws-sevlegend__item">
              <span className="ws-dot" style={{ background: SEV_COLOR[s] }} />
              <b>{counts[s]}</b> {s}
            </span>
          ))}
        </div>
      </div>

      {/* Top Risks — full width, directly below Risk Summary (no sticky, no overlap) */}
      <div className="ws-card ws-card--pad ws-section">
        <h2>Top Risks</h2>
        {(topRisks.length ? topRisks : null) ? (
          <div className="ws-list">
            {topRisks.map((r, i) => (
              <button key={i} type="button" className="ws-list__row" style={{ background: 'none', border: 'none', borderTop: i ? '1px solid var(--ws-line)' : 'none', cursor: 'pointer', textAlign: 'left', width: '100%' }}
                onClick={() => { const f = findings.find(x => x.title === r.title); if (f) onOpenFinding(f) }}>
                <SeverityTag severity={r.severity} compact />
                <span className="ws-list__grow">
                  <span className="ws-list__title">{r.title}</span>
                  {r.why ? <span className="ws-list__why">{r.why}</span> : null}
                </span>
                <ChevronRight size={15} className="ws-muted" />
              </button>
            ))}
          </div>
        ) : (
          <div className="ws-list">
            {[...findings].sort((a, b) => SEV_RANK[normSev(a.severity)] - SEV_RANK[normSev(b.severity)]).slice(0, 5).map((f, i) => (
              <button key={i} type="button" className="ws-list__row" style={{ background: 'none', border: 'none', borderTop: i ? '1px solid var(--ws-line)' : 'none', cursor: 'pointer', textAlign: 'left', width: '100%' }} onClick={() => onOpenFinding(f)}>
                <SeverityTag severity={f.severity} compact />
                <span className="ws-list__grow"><span className="ws-list__title">{f.title}</span></span>
                <ChevronRight size={15} className="ws-muted" />
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Two-column: Recent Findings + Attack Chains | Most Exploitable Chain + MASVS Posture.
          Both columns flow with the page — no sticky rail (Phase 11.985 layout fix). */}
      <div className="ws-two ws-section">
        <div className="ws-col">
          {/* Recent findings (stacked cards, Task 8) */}
          <div>
            <div className="ws-section__head"><h2>Recent Findings</h2>
              <button type="button" className="ws-btn ws-btn--sm" onClick={() => onOpenSection('findings')}>All findings <ChevronRight size={14} /></button></div>
            {findings.slice(0, 6).map((f, i) => <FindingRow key={i} f={f} onOpen={() => onOpenFinding(f)} onOpenCode={onOpenCode} />)}
          </div>

          {/* Attack chains summary */}
          {allChains.length ? (
            <div>
              <div className="ws-section__head"><h2>Attack Chains</h2>
                <button type="button" className="ws-btn ws-btn--sm" onClick={() => onOpenSection('chains')}>All chains <ChevronRight size={14} /></button></div>
              <div className="ws-card ws-card--pad">
                {allChains.slice(0, 4).map((c, i) => (
                  <button key={i} type="button" className="ws-list__row" style={{ background: 'none', border: 'none', borderTop: i ? '1px solid var(--ws-line)' : 'none', cursor: 'pointer', textAlign: 'left', width: '100%' }} onClick={() => onOpenSection('chains')}>
                    <SeverityTag severity={c.severity || 'high'} compact />
                    <span className="ws-list__grow">
                      <span className="ws-list__title">{c.title || 'Attack Chain'}</span>
                      {c.summary ? <span className="ws-list__why">{c.summary}</span> : null}
                    </span>
                    <ChevronRight size={15} className="ws-muted" />
                  </button>
                ))}
              </div>
            </div>
          ) : null}
        </div>

        {/* Right column: Most Exploitable Chain + MASVS Posture + Strong Controls (flows with the page) */}
        <aside className="ws-rail">
          <div className="ws-card ws-card--pad">
            <h2>Most Exploitable Chain</h2>
            {topChain ? (
              <button type="button" onClick={() => onOpenSection('chains')} style={{ background: 'none', border: 'none', cursor: 'pointer', textAlign: 'left', width: '100%', padding: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <SeverityTag severity={topChain.severity || 'high'} compact />
                  <b style={{ fontSize: 14 }}>{topChain.title}</b>
                </div>
                <p style={{ marginTop: 8, fontSize: 13 }}>{topChain.summary}</p>
                <span className="ws-tag ws-tag--soft" style={{ marginTop: 10 }}>{topChain.confidence || topChain.chain_confidence || 'MEDIUM'} confidence · view chain <ArrowUpRight size={11} /></span>
              </button>
            ) : <p className="ws-muted">No correlated cloud attack chain. Enable cloud intelligence to probe exposures.</p>}
          </div>

          <div className="ws-card ws-card--pad">
            <h2>MASVS Posture</h2>
            {masvs.weakest_category ? (
              <>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
                  <span style={{ fontSize: 22, fontWeight: 700 }}>{masvs.overall_score}</span>
                  <span className={`ws-maturity ws-maturity--${masvs.overall_maturity}`}>{masvs.overall_maturity}</span>
                </div>
                <p style={{ marginTop: 6, fontSize: 13 }}>Weakest: <b>{masvs.weakest_category}</b> ({masvs.weakest_maturity})</p>
                {(masvs.strong_controls || []).length ? (
                  <div style={{ marginTop: 10 }}>
                    <div className="ws-block__label">Strong Controls</div>
                    {masvs.strong_controls.slice(0, 4).map(c => <div key={c} className="ws-mcontrol"><ShieldCheck size={13} style={{ color: '#067647' }} /> {c}</div>)}
                  </div>
                ) : <p className="ws-muted" style={{ marginTop: 8, fontSize: 12.5 }}>No positive controls detected.</p>}
                <button type="button" className="ws-btn ws-btn--sm" style={{ marginTop: 12 }} onClick={() => onOpenSection('masvs')}>View MASVS coverage</button>
              </>
            ) : <p className="ws-muted">MASVS coverage not available for this scan.</p>}
          </div>
        </aside>
      </div>

      {/* Workspace launcher */}
      <div className="ws-section">
        <h2>Deep Analysis</h2>
        <div className="ws-launcher">
          {[
            ['ciso', 'CISO Summary', Briefcase], ['developer', 'Developer Guide', Wrench],
            ['manifest', 'Manifest', ScrollText], ['network', 'Network', Network],
            ['certificate', 'Certificate', Fingerprint], ['components', 'Components', Boxes],
            ['androidapis', 'Android APIs', Cpu], ['malware', 'Malware', Bug],
            ['ai', 'AI Assistant', Sparkles], ['compare', 'Compare', GitCompare],
          ].map(([id, label, Icon]) => (
            <button key={id} type="button" className="ws-launch" onClick={() => onOpenSection(id)}>
              <Icon size={18} className="ws-muted" />
              <span>{label}</span>
              <ChevronRight size={14} className="ws-muted" style={{ marginLeft: 'auto' }} />
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}

// ───────────────────────────── Findings ──────────────────────────────────
// Stacked finding card (Phase 11.86 Task 8): severity + confidence header,
// title, file:line, and explicit View Code / Open Finding actions.
// Compact labelled <select> for the analyst filter row.
function FilterSelect({ label, value, options, onChange }) {
  if (!options || !options.length) return null
  return (
    <label className="ws-filter">
      <span className="ws-filter__label">{label}</span>
      <select className="ws-input ws-filter__select" value={value} onChange={e => onChange(e.target.value)}>
        <option value="all">All</option>
        {options.map(o => <option key={o} value={o}>{o}</option>)}
      </select>
    </label>
  )
}

function FindingRow({ f, onOpen, onOpenCode, meta }) {
  const s = normSev(f.severity)
  const conf = confidenceLabel(f)
  const own = ownershipLabel(f)
  const evidence = buildEvidence(f)
  const primary = evidence[0]
  const lineTxt = primary
    ? (primary.lineStart && primary.lineEnd && primary.lineEnd > primary.lineStart
        ? `:${primary.lineStart}–${primary.lineEnd}`
        : (primary.line ? `:${primary.line}` : (primary.approximate ? ' ≈' : '')))
    : ''
  return (
    <div className="ws-fcard" role="button" tabIndex={0} onClick={onOpen}
      onKeyDown={e => { if (e.key === 'Enter') onOpen() }}>
      <span className="ws-fcard__sev" style={{ background: SEV_COLOR[s] }} />
      <div className="ws-fcard__body">
        <div className="ws-fcard__meta">
          <SeverityTag severity={s} />
          {conf ? <SoftTag title="Evidence quality / confidence">{conf} confidence</SoftTag> : null}
          {own ? <SoftTag title="Ownership">{own}</SoftTag> : null}
          {f.category ? <SoftTag>{f.category}</SoftTag> : null}
          {detectionSources(f).length > 1 ? <SoftTag title={detectionSources(f).join(', ')}>{detectionSources(f).length} engines</SoftTag> : null}
          {f.suppressed ? <SoftTag title={f.suppression_reason}>suppressed</SoftTag> : null}
          <StateBadge meta={meta} />
        </div>
        <div className="ws-fcard__title">{f.title || f.name || 'Finding'}</div>
        {primary
          ? <div className="ws-fcard__loc ws-mono" title={primary.path}>{primary.path.split('/').pop()}{lineTxt}</div>
          : <div className="ws-fcard__loc ws-fcard__loc--none">No source mapping</div>}
        <div className="ws-fcard__actions" onClick={e => e.stopPropagation()}>
          {primary && onOpenCode ? (
            <button type="button" className="ws-btn ws-btn--sm" onClick={() => openEvidence(primary, evidence, 0, onOpenCode)}>
              <FileCode2 size={13} /> View Code
            </button>
          ) : null}
          <button type="button" className="ws-btn ws-btn--sm" onClick={onOpen}>Open Finding</button>
        </div>
      </div>
    </div>
  )
}

export function FindingsPanel({ results, onOpenFinding, onOpenCode, collab, initialDetectionSource }) {
  const meta = collab?.collab?.meta || {}
  // Suppressed findings live in their own list (moved there at save time); the
  // "Suppressed" chip surfaces them so analysts can review/undo a suppression.
  const suppressedAll = results.suppressed_findings || []
  const active = results.findings || []
  const [q, setQ] = useState('')
  const [sev, setSev] = useState('all')
  const [appOnly, setAppOnly] = useState(false)
  const [stateFilter, setStateFilter] = useState('all')   // all | <state> | suppressed
  // `initialDetectionSource` lets the Semgrep launcher deep-link straight into the
  // findings pre-filtered to Detected By = Semgrep; the analyst can clear it after.
  const [adv, setAdv] = useState({ category: 'all', detectionSource: initialDetectionSource || 'all', ownership: 'all', framework: 'all', minTrust: 0 })
  const [limit, setLimit] = useState(60)

  const showSuppressed = stateFilter === 'suppressed'
  const all = showSuppressed ? suppressedAll : active

  // Option lists for the analyst filters (derived from the actual findings).
  const opts = useMemo(() => ({
    categories: [...new Set(active.map(f => f.category).filter(Boolean))].sort(),
    sources: findingDetectionSourceSet(active),
    ownerships: OWNERSHIP_OPTIONS.filter(o => active.some(f => (f.owner_type || f.ownership) === o)),
    frameworks: findingFrameworkSet(active),
  }), [active])

  const filtered = useMemo(() => {
    const ql = q.trim().toLowerCase()
    return all.filter(f => {
      if (sev !== 'all' && normSev(f.severity) !== sev) return false
      if (appOnly && (f.ownership_label || f.ownership) && (f.ownership_label || f.ownership) !== 'APPLICATION' && (f.ownership_label || f.ownership) !== 'APP') return false
      if (!showSuppressed && stateFilter !== 'all') {
        const st = meta[findingKey(f)]?.state || 'open'
        if (st !== stateFilter) return false
      }
      // Analyst filters (detection source / ownership / framework / category / trust).
      if (!matchesFilters(f, adv)) return false
      if (ql) {
        const blob = `${f.title} ${f.category} ${findingPath(f)} ${f.cwe || ''} ${detectionSources(f).join(' ')}`.toLowerCase()
        if (!blob.includes(ql)) return false
      }
      return true
    }).sort((a, b) => SEV_RANK[normSev(a.severity)] - SEV_RANK[normSev(b.severity)])
  }, [all, q, sev, appOnly, stateFilter, showSuppressed, meta, adv])

  const setAdvKey = (k, v) => { setAdv(a => ({ ...a, [k]: v })); setLimit(60) }

  return (
    <div>
      <div className="ws-section__head"><h1>Findings</h1><span className="ws-muted">{filtered.length} of {all.length}</span></div>
      <div className="ws-toolbar">
        <input className="ws-input" placeholder="Filter findings…" value={q} onChange={e => { setQ(e.target.value); setLimit(60) }} />
        {['all', ...SEV_ORDER].map(s => (
          <button key={s} type="button" className={`ws-chip${sev === s ? ' is-active' : ''}`} onClick={() => setSev(s)}>
            {s === 'all' ? 'All' : s[0].toUpperCase() + s.slice(1)}
          </button>
        ))}
        <button type="button" className={`ws-chip${appOnly ? ' is-active' : ''}`} onClick={() => setAppOnly(v => !v)}>App-owned only</button>
      </div>
      <div className="ws-toolbar">
        <span className="ws-muted" style={{ fontSize: 12 }}>State</span>
        <button type="button" className={`ws-chip${stateFilter === 'all' ? ' is-active' : ''}`} onClick={() => { setStateFilter('all'); setLimit(60) }}>All</button>
        {FINDING_STATES.map(s => (
          <button key={s.id} type="button" className={`ws-chip${stateFilter === s.id ? ' is-active' : ''}`} onClick={() => { setStateFilter(s.id); setLimit(60) }}>{s.label}</button>
        ))}
        {suppressedAll.length ? (
          <button type="button" className={`ws-chip${showSuppressed ? ' is-active' : ''}`} onClick={() => { setStateFilter('suppressed'); setLimit(60) }}>Suppressed ({suppressedAll.length})</button>
        ) : null}
      </div>
      <div className="ws-toolbar ws-toolbar--filters">
        <FilterSelect label="Category" value={adv.category} options={opts.categories} onChange={v => setAdvKey('category', v)} />
        <FilterSelect label="Detected By" value={adv.detectionSource} options={opts.sources} onChange={v => setAdvKey('detectionSource', v)} />
        <FilterSelect label="Ownership" value={adv.ownership} options={opts.ownerships} onChange={v => setAdvKey('ownership', v)} />
        {opts.frameworks.length ? <FilterSelect label="Framework" value={adv.framework} options={opts.frameworks} onChange={v => setAdvKey('framework', v)} /> : null}
        <label className="ws-filter-range" title="Minimum trust score">
          <span className="ws-muted" style={{ fontSize: 12 }}>Trust ≥ {adv.minTrust}</span>
          <input type="range" min="0" max="100" step="5" value={adv.minTrust} onChange={e => setAdvKey('minTrust', Number(e.target.value))} />
        </label>
      </div>
      {filtered.length ? (
        <>
          {filtered.slice(0, limit).map((f, i) => <FindingRow key={i} f={f} meta={meta[findingKey(f)]} onOpen={() => onOpenFinding(f)} onOpenCode={onOpenCode} />)}
          {filtered.length > limit ? (
            <button type="button" className="ws-btn" style={{ marginTop: 12 }} onClick={() => setLimit(l => l + 80)}>
              Show {Math.min(80, filtered.length - limit)} more
            </button>
          ) : null}
        </>
      ) : <EmptyState title="No findings match" body="Adjust the filters above." />}
    </div>
  )
}

// ─── Collaboration block (state · assignment · comments · suppression) ────────
function CollabBlock({ finding, collab }) {
  const key = findingKey(finding)
  const meta = collab.collab.meta[key] || {}
  const comments = collab.collab.comments[key] || []
  const writable = canWrite()
  const [comment, setComment] = useState('')
  const [assignee, setAssignee] = useState(meta.assignee || '')
  const [supReason, setSupReason] = useState('')
  const [supOpen, setSupOpen] = useState(false)
  const [saving, setSaving] = useState(false)

  const submitComment = async () => {
    if (!comment.trim()) return
    setSaving(true)
    const ok = await collab.addComment(finding, comment.trim())
    setSaving(false)
    if (ok) setComment('')
  }

  return (
    <Block label="Collaboration">
      {/* State */}
      <div className="ws-collab-row">
        <span className="ws-collab-row__label">State</span>
        <div className="ws-collab-states">
          {FINDING_STATES.map(s => {
            const on = (meta.state || 'open') === s.id
            return (
              <button key={s.id} type="button" disabled={!writable}
                className={`ws-chip${on ? ' is-active' : ''}`}
                style={on ? { borderColor: s.color, color: s.color } : undefined}
                onClick={() => collab.setState(finding, s.id)}>{s.label}</button>
            )
          })}
        </div>
      </div>

      {/* Assignment + priority */}
      <div className="ws-collab-row">
        <span className="ws-collab-row__label">Assignee</span>
        <input className="ws-input" style={{ flex: 1 }} placeholder="username" value={assignee}
          disabled={!writable}
          onChange={e => setAssignee(e.target.value)}
          onBlur={() => assignee !== (meta.assignee || '') && collab.assign(finding, { assignee, priority: meta.priority || '' })} />
        <select className="ws-input" style={{ width: 'auto' }} value={meta.priority || ''} disabled={!writable}
          onChange={e => collab.assign(finding, { assignee, priority: e.target.value })}>
          <option value="">Priority…</option>
          {PRIORITIES.map(p => <option key={p} value={p}>{p}</option>)}
        </select>
      </div>

      {/* Suppression */}
      {writable ? (
        <div style={{ marginTop: 6 }}>
          {finding.suppressed ? (
            <p className="ws-muted" style={{ fontSize: 12 }}>Suppressed: {finding.suppression_reason || '—'}</p>
          ) : !supOpen ? (
            <button type="button" className="ws-btn ws-btn--sm" onClick={() => setSupOpen(true)}>Suppress this rule…</button>
          ) : (
            <div className="ws-collab-row">
              <input className="ws-input" style={{ flex: 1 }} placeholder="Reason (required)" value={supReason} onChange={e => setSupReason(e.target.value)} />
              <button type="button" className="ws-btn ws-btn--sm ws-btn--primary" disabled={!supReason.trim()}
                onClick={async () => { const ok = await collab.suppress({ rule_id: finding.rule_id || '', file_pattern: finding.rule_id ? '' : findingPath(finding), reason: supReason.trim() }); if (ok) { setSupOpen(false); setSupReason('') } }}>Save</button>
              <button type="button" className="ws-btn ws-btn--sm" onClick={() => setSupOpen(false)}>Cancel</button>
            </div>
          )}
        </div>
      ) : null}

      {/* Comments (markdown) */}
      <div className="ws-collab-comments">
        {comments.map(c => (
          <div key={c.id} className="ws-comment">
            <div className="ws-comment__head"><b>{c.author || 'anon'}</b> <span className="ws-muted">{c.created_at}</span></div>
            <div className="ws-comment__body" dangerouslySetInnerHTML={{ __html: renderMarkdown(c.body) }} />
          </div>
        ))}
        {writable ? (
          <div className="ws-collab-row" style={{ marginTop: 8 }}>
            <textarea className="ws-input" rows={2} style={{ flex: 1, resize: 'vertical' }}
              placeholder="Add a comment… (markdown: **bold**, *italic*, `code`, [link](url))"
              value={comment} onChange={e => setComment(e.target.value)}
              onKeyDown={e => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') submitComment() }} />
            <button type="button" className="ws-btn ws-btn--sm ws-btn--primary" disabled={saving || !comment.trim()} onClick={submitComment}>Comment</button>
          </div>
        ) : <p className="ws-muted" style={{ fontSize: 12 }}>Read-only role — viewing only.</p>}
      </div>
    </Block>
  )
}

// ─── Analyst intelligence components (Phase 1.99) ─────────────────────────────
// All presentation-only; consume the backend evidence_view / detected_by / fusion
// / confidence_breakdown via the pure evidence-model helpers. No backend calls.

function copyToClipboard(text) {
  try { navigator.clipboard?.writeText(String(text || '')) } catch { /* clipboard unavailable */ }
}

// Header metrics strip: every key signal at a glance.
function IntelStrip({ finding }) {
  const f = finding
  const view = getEvidenceView(f)
  const trust = trustScore(f)
  const conf = confidenceLabel(f)
  const reach = reachabilityLabel(f)
  const cells = [
    { label: 'Severity', value: normSev(f.severity).toUpperCase() },
    conf ? { label: 'Confidence', value: conf } : null,
    { label: 'Trust', value: `${trust}`, band: trustBand(trust) },
    view.evidenceScore ? { label: 'Evidence', value: view.evidenceScore } : null,
    Number(f.fusion_score) ? { label: 'Fusion', value: f.fusion_score } : null,
    view.ownership ? { label: 'Ownership', value: ownershipLabel({ ownership: view.ownership }) || view.ownership } : null,
    reach ? { label: 'Reachability', value: reach } : null,
    (view.inAttackChain) ? { label: 'Attack Chain', value: 'In chain' } : null,
  ].filter(Boolean)
  return (
    <div className="ws-intel">
      {cells.map((c, i) => (
        <div key={i} className={`ws-intel__cell${c.band ? ` ws-intel__cell--${c.band}` : ''}`}>
          <div className="ws-intel__label">{c.label}</div>
          <div className="ws-intel__value">{c.value}</div>
        </div>
      ))}
    </div>
  )
}

// Detected-By badges. Future engines appear automatically (data-driven).
function DetectedByBadges({ finding }) {
  const sources = detectionSources(finding)
  if (!sources.length) return null
  return (
    <Block label="Detected By">
      <div className="ws-badges">
        {sources.map((s, i) => <span key={i} className="ws-badge ws-badge--engine">✓ {s}</span>)}
      </div>
    </Block>
  )
}

// Large highlighted primary-evidence card with analyst actions.
function PrimaryEvidenceCard({ view, finding, onOpenCode }) {
  const nav = useWorkspaceNav()
  const p = view.primary
  if (!p || !p.file) return null
  const fileName = p.file.split('/').pop()
  const lines = p.line ? [p.line] : []
  // Jump-to-source/smali flows through the nav seam (re-targetable to the future
  // Source Explorer); falls back to the raw onOpenCode prop when rendered without
  // a workspace context.
  const open = (vw) => {
    const opts = { snippet: p.snippet, view: vw }
    if (nav._onOpenCode) (vw === 'smali' ? nav.openSmali : nav.openSource)(p.file, lines, opts)
    else onOpenCode?.(p.file, lines, opts)
  }
  return (
    <div className="ws-block">
      <div className="ws-block__label">Primary Evidence</div>
      <div className="ws-primary">
        <div className="ws-primary__top">
          <FileCode2 size={16} />
          <span className="ws-primary__file ws-mono" title={p.file}>{fileName}{p.line ? `:${p.line}` : ''}</span>
          {p.language ? <span className="ws-badge">{p.language}</span> : null}
          {p.owner_type ? <span className="ws-badge ws-badge--own">{ownershipLabel({ ownership: p.owner_type }) || p.owner_type}</span> : null}
          {p.source ? <span className="ws-badge ws-badge--engine">{p.source}</span> : null}
        </div>
        {p.snippet ? <pre className="ws-code">{p.snippet}</pre> : null}
        {(p.reasons || []).length ? (
          <ul className="ws-primary__reasons">
            {p.reasons.slice(0, 5).map((r, i) => <li key={i}>✓ {r}</li>)}
          </ul>
        ) : (view.reason ? <div className="ws-primary__reason ws-muted">{view.reason}</div> : null)}
        {view.frameworkOnly ? (
          <div className="ws-primary__note">No application-owned evidence exists for this finding — the proof is framework/library code.</div>
        ) : null}
        <div className="ws-primary__actions">
          {/* Certificate / signing artifacts have no source file — only offer Copy. */}
          {p.artifact ? null : <button type="button" className="ws-btn ws-btn--primary" onClick={() => open('java')}><FileCode2 size={14} /> View Source</button>}
          {p.artifact ? null : <button type="button" className="ws-btn" onClick={() => open('smali')} title="Smali view (Source Explorer — roadmap)"><Layers size={14} /> View Smali</button>}
          <button type="button" className="ws-btn" onClick={() => copyToClipboard(p.file + (p.line ? `:${p.line}` : ''))}>Copy Path</button>
          {p.snippet ? <button type="button" className="ws-btn" onClick={() => copyToClipboard(p.snippet)}>Copy Snippet</button> : null}
        </div>
      </div>
    </div>
  )
}

// Collapsible supporting evidence (app/manifest/config + chain references).
function SupportingEvidence({ view, onOpenCode }) {
  const items = view.supporting || []
  const [open, setOpen] = useState(false)
  if (!items.length) return null
  return (
    <div className="ws-block">
      <button type="button" className="ws-collapse" onClick={() => setOpen(o => !o)}>
        <ChevronRight size={14} className={open ? 'ws-rot90' : ''} /> Supporting Evidence ({items.length})
      </button>
      {open ? items.map((s, i) => (
        <div key={i} className="ws-evid ws-evid--sm">
          <div className="ws-evid__loc ws-mono" title={s.file}>{(s.file || '').split('/').pop()}{s.line ? `:${s.line}` : ''}
            {s.language ? <span className="ws-badge" style={{ marginLeft: 6 }}>{s.language}</span> : null}</div>
          {s.snippet ? <pre className="ws-code">{s.snippet}</pre> : null}
          {onOpenCode && s.file ? <button type="button" className="ws-btn ws-btn--sm" onClick={() => onOpenCode(s.file, s.line ? [s.line] : [])}><FileCode2 size={13} /> View</button> : null}
        </div>
      )) : null}
    </div>
  )
}

// Hidden library evidence — collapsed by default, explains WHY each was hidden,
// capped so we never render thousands of SDK files.
function HiddenLibraryEvidence({ view }) {
  const hidden = view.hidden || { count: 0, items: [], owners: [] }
  const [open, setOpen] = useState(false)
  if (!hidden.count) return null
  const items = (hidden.items || []).slice(0, 50)
  return (
    <div className="ws-block">
      <button type="button" className="ws-collapse ws-collapse--muted" onClick={() => setOpen(o => !o)}>
        <ChevronRight size={14} className={open ? 'ws-rot90' : ''} /> Hidden Library Evidence ({hidden.count})
        {hidden.owners?.length ? <span className="ws-muted" style={{ fontWeight: 400 }}> — {hidden.owners.slice(0, 4).join(', ')}</span> : null}
      </button>
      {open ? (
        <div className="ws-hidden">
          {items.map((it, i) => (
            <div key={i} className="ws-hidden__row">
              <span className="ws-mono ws-muted" title={it.file}>{(it.file || '').split('/').pop()}</span>
              <span className="ws-badge ws-badge--own">{it.owner_name || it.owner_type}</span>
              {(it.reasons || []).length ? <span className="ws-muted" style={{ fontSize: 11.5 }}>✗ {it.reasons[0]}</span> : null}
            </div>
          ))}
          {hidden.count > items.length ? <div className="ws-muted" style={{ fontSize: 11.5, marginTop: 6 }}>+{hidden.count - items.length} more hidden</div> : null}
        </div>
      ) : null}
    </div>
  )
}

// Explainable confidence panel: overall + contributions + why high/low.
function ConfidencePanel({ finding }) {
  const c = confidenceContributions(finding)
  if (!c.overall && !c.reason) return null
  const Bar = ({ label, value }) => (
    <div className="ws-confbar">
      <span className="ws-confbar__label">{label}</span>
      <span className="ws-confbar__track"><span className="ws-confbar__fill" style={{ width: `${Math.max(0, Math.min(100, value))}%` }} /></span>
      <span className="ws-confbar__val">{value}</span>
    </div>
  )
  return (
    <Block label="Confidence">
      <div className="ws-conf-head">
        <span className={`ws-rating ws-rating--${String(c.band).toLowerCase()}`}>{c.band}</span>
        <span className="ws-mono">{c.overall}/100</span>
      </div>
      {c.reason ? <p className="ws-muted" style={{ fontSize: 12.5, margin: '6px 0 10px' }}>{c.reason}</p> : null}
      {c.positives.map((p, i) => <Bar key={`p${i}`} label={`✓ ${p.label}`} value={p.value} />)}
      {c.negatives.map((p, i) => <Bar key={`n${i}`} label={`✗ ${p.label}`} value={p.value} />)}
      <div className="ws-conf-contrib">
        <div><b>Fusion:</b> {c.fusionContribution}</div>
        <div><b>Evidence:</b> {c.evidenceContribution || '—'}</div>
        <div><b>Ownership:</b> {c.ownershipContribution}</div>
      </div>
    </Block>
  )
}

// ───────────────────────── Finding details drawer ────────────────────────
export function FindingDrawer({ finding, onClose, onOpenCode, collab }) {
  useEscape(onClose)
  const [providers, setProviders] = useState([])
  const [provider, setProvider] = useState('')
  const [busy, setBusy] = useState('')
  const [aiResult, setAiResult] = useState(null)
  useEffect(() => {
    let live = true
    fetchAiProviders().then(d => { if (live) setProviders(d.providers || []) })
    return () => { live = false }
  }, [])

  if (!finding) return null
  const f = finding
  const ex = f.analyst_explanation || {}
  const snippet = f.snippet || f.code_context || (f.file_evidence?.[0]?.snippet) || ''
  const rem = ex.remediation || {}
  const view = getEvidenceView(f)

  const runAi = async action => {
    setBusy(action)
    try {
      const res = await runFindingAction({ action, provider: provider || undefined, finding: f })
      setAiResult({ ...res, action })
    } finally {
      setBusy('')
    }
  }

  return (
    <>
      <div className="ws-drawer-backdrop" onClick={onClose} />
      <aside className="ws-drawer" role="dialog" aria-label="Finding details">
        <div className="ws-drawer__head">
          <div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
              <SeverityTag severity={f.severity} />
              {confidenceLabel(f) ? <SoftTag>{confidenceLabel(f)} conf</SoftTag> : null}
              {ownershipLabel(f) ? <SoftTag>{ownershipLabel(f)}</SoftTag> : null}
            </div>
            <h3>{f.title || f.name || 'Finding'}</h3>
          </div>
          <button type="button" className="ws-drawer__close" onClick={onClose}>×</button>
        </div>
        <div className="ws-drawer__body">
          {/* Analyst intelligence strip + detection sources (Phase 1.99). */}
          <IntelStrip finding={f} />
          <DetectedByBadges finding={f} />
          {/* Collaboration — triage state, assignment, comments, suppression. */}
          {collab ? <CollabBlock finding={f} collab={collab} /> : null}

          {/* AI analysis (Phase 11.97) — reasons only about the evidence above */}
          <Block label="AI Analysis">
            <div className="ws-ai-bar">
              <select className="ws-input ws-ai-provider" value={provider} onChange={e => setProvider(e.target.value)} aria-label="AI provider">
                <option value="">Auto / Deterministic</option>
                {providers.map(p => (
                  <option key={p.id} value={p.id} disabled={!p.available}>
                    {p.name}{p.available ? '' : ' (unavailable)'}
                  </option>
                ))}
              </select>
            </div>
            <div className="ws-ai-actions">
              {FINDING_AI_ACTIONS.map(a => (
                <button key={a.id} type="button" className="ws-btn ws-btn--sm" disabled={!!busy} onClick={() => runAi(a.id)}>
                  <Sparkles size={13} /> {busy === a.id ? 'Working…' : a.label}
                </button>
              ))}
            </div>
            {!providers.some(p => p.available) ? (
              <p className="ws-muted" style={{ fontSize: 12, marginTop: 8 }}>
                No LLM provider is configured — actions return a deterministic, evidence-only result.
                Set an API key (ANTHROPIC/OPENAI/GEMINI/DEEPSEEK) or OLLAMA_HOST to enable a model.
              </p>
            ) : null}
          </Block>

          {ex.what_found || snippet ? (
            <Block label="What Found"><pre className="ws-code">{ex.what_found || snippet}</pre></Block>
          ) : null}
          <Block label={ex.why_dangerous ? 'Why Dangerous' : 'Summary'}>
            <p>{ex.why_dangerous || ex.why_it_matters || f.description || 'No description available.'}</p>
          </Block>

          {/* Chain evidence (Task 7) — for attack-chain findings */}
          {f.is_attack_chain && (f.chain_evidence || f.confidence_explanation) ? (
            <ChainEvidenceBlock finding={f} onOpenCode={onOpenCode} />
          ) : null}

          {/* Evidence (Phase 1.99): the selected application-relevant Primary proof,
              collapsible Supporting, and collapsed Hidden Library evidence. Legacy
              findings (no evidence_view) fall back to the structured location list. */}
          {view.primary && !view.fallback ? (
            <>
              <PrimaryEvidenceCard view={view} finding={f} onOpenCode={onOpenCode} />
              <SupportingEvidence view={view} onOpenCode={onOpenCode} />
              <HiddenLibraryEvidence view={view} />
            </>
          ) : (
            <EvidenceLocations finding={f} onOpenCode={onOpenCode} />
          )}

          <ConfidencePanel finding={f} />

          {ex.attack_scenario ? <Block label="Attack Scenario"><p>{ex.attack_scenario}</p></Block> : null}
          {(ex.prerequisites || []).length ? <Block label="Prerequisites"><ul>{ex.prerequisites.map((p, i) => <li key={i}>{p}</li>)}</ul></Block> : null}
          {ex.impact ? <Block label="Impact"><p>{ex.impact}</p></Block> : null}

          <Block label="Remediation / Developer Fix">
            <p>{ex.developer_fix || rem.developer_fix || rem.summary || f.recommendation || 'Review the evidence and apply secure-coding guidance for this weakness class.'}</p>
            <div className="ws-refs" style={{ marginTop: 8 }}>
              {(rem.masvs || f.masvs) ? <SoftTag>{rem.masvs || f.masvs}</SoftTag> : null}
              {(rem.owasp || f.owasp) ? <SoftTag>OWASP {rem.owasp || f.owasp}</SoftTag> : null}
              {f.cwe ? <SoftTag>{f.cwe}</SoftTag> : null}
            </div>
          </Block>

          {ex.code_example ? <Block label="Code Example"><pre className="ws-code">{ex.code_example}</pre></Block> : null}
          {ex.false_positive_notes ? <Block label="False-Positive Notes"><div className="ws-callout ws-callout--fp">{ex.false_positive_notes}</div></Block> : null}
          {ex.confidence_reason ? <Block label="Confidence Reason"><div className="ws-callout">{ex.confidence_reason}</div></Block> : null}
          {(ex.references || []).length ? <Block label="References"><div className="ws-refs">{ex.references.map((r, i) => <SoftTag key={i}>{r}</SoftTag>)}</div></Block> : null}
        </div>
      </aside>
      {aiResult ? <AiResultDrawer data={aiResult} onClose={() => setAiResult(null)} /> : null}
    </>
  )
}

// ─── AI Result Drawer (Phase 11.97 Task 7) — stacked over the finding drawer ──
const AI_ACTION_TITLE = {
  explain: 'AI · Explain Finding', verify: 'AI · Verify Finding',
  worth_testing: 'AI · Worth Testing?', generate_poc: 'AI · Generate PoC',
  generate_fix: 'AI · Generate Fix', summary: 'AI · Executive Summary',
}
const LEVEL_TONE = { high: '#7f1d1d', medium: '#ea8600', low: '#3b82f6' }

function LevelTag({ value, label }) {
  if (!value) return null
  const v = String(value).toLowerCase()
  return <span className="ws-tag" style={{ background: (LEVEL_TONE[v] || '#52525b') + '1a', color: LEVEL_TONE[v] || '#52525b', fontWeight: 650 }}>{label}: {v}</span>
}

function AiResultDrawer({ data, onClose }) {
  useEscape(onClose)
  const r = data.result || {}
  const action = data.action
  const isError = data.mode === 'error' || data.error
  return (
    <>
      <div className="ws-drawer-backdrop ws-drawer-backdrop--stacked" onClick={onClose} />
      <aside className="ws-drawer ws-drawer--stacked" role="dialog" aria-label="AI result">
        <div className="ws-drawer__head">
          <div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8, flexWrap: 'wrap' }}>
              <span className="ws-tag ws-tag--soft"><Sparkles size={12} /> {data.provider || 'deterministic'}</span>
              {data.model ? <span className="ws-tag ws-tag--soft">{data.model}</span> : null}
              <span className={`ws-tag ws-tag--soft`}>{data.mode === 'llm' ? 'model-written' : data.mode === 'error' ? 'error' : 'deterministic'}</span>
              {data.cached ? <span className="ws-tag ws-tag--soft">cached</span> : null}
              {data.confidence ? <LevelTag value={data.confidence} label="confidence" /> : null}
            </div>
            <h3>{AI_ACTION_TITLE[action] || 'AI Result'}</h3>
          </div>
          <button type="button" className="ws-drawer__close" onClick={onClose}>×</button>
        </div>
        <div className="ws-drawer__body">
          {isError ? (
            <Block label="Unavailable"><div className="ws-callout">{data.error || 'The AI action could not be completed.'}</div></Block>
          ) : null}

          {/* Verify */}
          {action === 'verify' ? (
            <Block label="Assessment">
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
                <LevelTag value={r.likelihood} label="likelihood" />
                <span className="ws-tag" style={{ background: r.false_positive ? '#fef3f2' : '#ecfdf3', color: r.false_positive ? '#b42318' : '#067647', fontWeight: 650 }}>
                  false positive: {String(!!r.false_positive)}
                </span>
              </div>
              {r.reasoning ? <p>{r.reasoning}</p> : null}
              <div className="ws-callout" style={{ marginTop: 10 }}>The analyst is the final authority — this assessment never suppresses a finding automatically.</div>
            </Block>
          ) : null}
          {action === 'verify' && (r.manual_steps || []).length ? (
            <Block label="Manual Verification Steps"><ol className="ws-ol">{r.manual_steps.map((s, i) => <li key={i}>{s}</li>)}</ol></Block>
          ) : null}

          {/* Worth testing */}
          {action === 'worth_testing' ? (
            <Block label="Triage">
              <div style={{ marginBottom: 8 }}><LevelTag value={r.priority} label="priority" /></div>
              {r.expected_impact ? <p><b>Expected impact:</b> {r.expected_impact}</p> : null}
            </Block>
          ) : null}
          {action === 'worth_testing' && (r.manual_validation_steps || []).length ? (
            <Block label="Manual Validation Steps"><ol className="ws-ol">{r.manual_validation_steps.map((s, i) => <li key={i}>{s}</li>)}</ol></Block>
          ) : null}
          {action === 'worth_testing' && (r.required_prerequisites || []).length ? (
            <Block label="Prerequisites"><ul>{r.required_prerequisites.map((s, i) => <li key={i}>{s}</li>)}</ul></Block>
          ) : null}

          {/* PoC */}
          {action === 'generate_poc' ? (
            <>
              {r.summary ? <Block label="Summary"><p>{r.summary}</p></Block> : null}
              {(r.steps || []).length ? <Block label="Steps"><ol className="ws-ol">{r.steps.map((s, i) => <li key={i}>{s}</li>)}</ol></Block> : null}
              {(r.commands || []).length ? <Block label="Commands"><pre className="ws-code">{r.commands.join('\n')}</pre></Block> : null}
              {(r.assumptions || []).length ? <Block label="Assumptions / Placeholders"><ul>{r.assumptions.map((s, i) => <li key={i}>{s}</li>)}</ul></Block> : null}
            </>
          ) : null}

          {/* Fix */}
          {action === 'generate_fix' ? (
            <>
              {r.why_vulnerable ? <Block label="Why Vulnerable"><p>{r.why_vulnerable}</p></Block> : null}
              {r.current_code ? <Block label="Current Code"><pre className="ws-code">{r.current_code}</pre></Block> : null}
              {r.patched_code ? <Block label="Patched Code"><pre className="ws-code">{r.patched_code}</pre></Block> : null}
              {r.best_practice ? <Block label="Best Practice"><p>{r.best_practice}</p></Block> : null}
              {(r.masvs || r.owasp) ? <Block label="Standards"><div className="ws-refs">{r.masvs ? <SoftTag>{r.masvs}</SoftTag> : null}{r.owasp ? <SoftTag>OWASP {r.owasp}</SoftTag> : null}</div></Block> : null}
            </>
          ) : null}

          {/* Explain / summary / generic */}
          {(action === 'explain' || action === 'summary') && data.summary ? (
            <Block label="Summary"><p>{data.summary}</p></Block>
          ) : null}
          {(action === 'explain' || action === 'summary') && data.reasoning ? (
            <Block label="Reasoning"><p style={{ whiteSpace: 'pre-wrap' }}>{data.reasoning}</p></Block>
          ) : null}

          {data.limitations ? <Block label="Limitations"><div className="ws-callout ws-callout--fp">{data.limitations}</div></Block> : null}
        </div>
      </aside>
    </>
  )
}

function Block({ label, children }) {
  return <div className="ws-block"><div className="ws-block__label">{label}</div>{children}</div>
}

// Open the code viewer for one evidence entry, passing the full deterministic
// resolution context (snippet/class/title hints) + the sibling list for Prev/Next.
function openEvidence(loc, evidence, i, onOpenCode) {
  onOpenCode(loc.path, loc.lines, {
    snippet: loc.snippet, source: loc.source, approximate: loc.approximate,
    highlightLine: loc.highlightLine, className: loc.className, titleKeywords: loc.titleKeywords,
    evidence, index: i,
  })
}

const SOURCE_LABEL = {
  'analyst evidence': 'Analyst Evidence',
  'code reference': 'Code Reference',
  'finding location': 'Finding Location',
}

// Pretty line label for an evidence card: exact "84" / "82–87", or ≈approx hint.
function evLineLabel(loc) {
  if (loc.lineStart && loc.lineEnd && loc.lineEnd > loc.lineStart) return `${loc.lineStart}–${loc.lineEnd}`
  if (loc.line) return `${loc.line}`
  return loc.snippet ? '≈ resolved from snippet' : '≈ approximate'
}

// Evidence section (Phase 11.86 Tasks 1/5): structured cards with explicit
// source, file:line, snippet, and View Code. When no source mapping exists the
// section shows an honest "Evidence unavailable" state with the backend reason —
// never hidden, never invented.
function EvidenceLocations({ finding, onOpenCode }) {
  const evidence = buildEvidence(finding)

  if (!evidence.length) {
    return (
      <div className="ws-block">
        <div className="ws-block__label">Evidence</div>
        <div className="ws-evid ws-evid--none">
          <div className="ws-evid__title">Evidence unavailable</div>
          <div className="ws-evid__reason"><b>Reason:</b> {evidenceUnavailableReason(finding)}</div>
        </div>
      </div>
    )
  }

  return (
    <div className="ws-block">
      <div className="ws-block__label">Evidence{evidence.length > 1 ? ` · ${evidence.length} locations` : ''}</div>
      {evidence.map((loc, i) => {
        const fileName = loc.path.split('/').pop()
        const exact = !loc.approximate
        return (
          <div key={i} className="ws-evid">
            <div className="ws-evid__head">
              <span className="ws-evid__num">Evidence #{i + 1}</span>
              <span className="ws-evid__src">{SOURCE_LABEL[loc.source] || loc.source}</span>
            </div>
            <div className="ws-evid__loc ws-mono" title={loc.path}>
              {fileName}<span className="ws-evid__line">:{evLineLabel(loc)}</span>
            </div>
            {loc.snippet ? <pre className="ws-code">{loc.snippet}</pre> : null}
            <div className="ws-evid__actions">
              <button type="button" className="ws-btn" onClick={() => openEvidence(loc, evidence, i, onOpenCode)}>
                <FileCode2 size={14} /> View Code
              </button>
              {!exact ? <span className="ws-evid__approx">Approximate line — resolved by search</span> : null}
            </div>
          </div>
        )
      })}
    </div>
  )
}

// Chain evidence (Task 7): per-member contribution + self-explaining confidence.
function ChainEvidenceBlock({ finding, onOpenCode }) {
  const ev = finding.chain_evidence || []
  const cx = finding.confidence_explanation || {}
  return (
    <div className="ws-block">
      <div className="ws-block__label">Chain Evidence</div>
      {ev.map((e, i) => (
        <div key={i} className="ws-chainev">
          <span className="ws-chainev__check">✓</span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontWeight: 560, fontSize: 13.5 }}>{e.title}</div>
            <div className="ws-muted" style={{ fontSize: 12.5 }}>{e.why_it_contributes}</div>
            {e.file ? <div className="ws-mono ws-muted" style={{ fontSize: 11.5, marginTop: 2 }}>{e.file}{e.line ? `:${e.line}` : ''}</div> : null}
          </div>
          {e.confidence ? <SoftTag>{e.confidence}</SoftTag> : null}
          {e.file ? <button type="button" className="ws-btn" onClick={() => onOpenCode(e.file, e.line ? [e.line] : [])}><FileCode2 size={13} /></button> : null}
        </div>
      ))}
      {(cx.checks || []).length ? (
        <div className="ws-card ws-card--pad" style={{ marginTop: 12 }}>
          <div className="ws-block__label">Why confidence is {cx.confidence}</div>
          {cx.checks.map((c, i) => (
            <div key={i} className="ws-check">
              <span className={c.met ? 'ws-check--yes' : 'ws-check--no'}>{c.met ? '✓' : '✗'}</span> {c.label}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  )
}

// ───────────────────────────── Attack Chains ─────────────────────────────
export function ChainsPanel({ results, onOpenCode }) {
  const cloud = results.cloud_attack_paths || []
  const findingChains = (results.findings || []).filter(f => f.is_attack_chain)
  const chains = [...cloud, ...findingChains]
  if (!chains.length) return <EmptyState title="No attack chains" body="No correlated cloud attack paths or multi-step finding chains were synthesized for this scan." />

  return (
    <div>
      <div className="ws-section__head"><h1>Attack Chains</h1><span className="ws-muted">{chains.length} path{chains.length !== 1 ? 's' : ''}</span></div>
      {chains.map((c, i) => {
        const ex = c.analyst_explanation || {}
        const comps = c.components || []
        const steps = comps.length ? comps : (c.call_chain || []).map(s => ({ label: s, kind: 'step' }))
        return (
          <div key={i} className="ws-chain">
            <div className="ws-chain__head">
              <SeverityTag severity={c.severity || 'high'} />
              <span className="ws-chain__title">{c.title || 'Attack Chain'}</span>
              <span style={{ marginLeft: 'auto' }} className="ws-tag ws-tag--soft">{c.confidence || c.chain_confidence || 'MEDIUM'} confidence</span>
            </div>
            <div className="ws-chain__summary">{c.summary || ex.why_it_matters || ''}</div>
            <div className="ws-timeline">
              {steps.map((s, j) => {
                const stepFile = s.file || s.file_path
                const clickable = !!(onOpenCode && stepFile)
                return (
                <div key={j} className="ws-step">
                  <div className="ws-step__rail">
                    <span className={`ws-step__node${s.kind === 'exposure' ? ' ws-step__node--exposure' : ''}`} />
                    <span className="ws-step__line" />
                  </div>
                  <div className={`ws-step__body${clickable ? ' ws-step__body--clickable' : ''}`}
                    role={clickable ? 'button' : undefined} tabIndex={clickable ? 0 : undefined}
                    onClick={clickable ? () => onOpenCode(stepFile, s.line ? [s.line] : []) : undefined}
                    onKeyDown={clickable ? (e => { if (e.key === 'Enter') onOpenCode(stepFile, s.line ? [s.line] : []) }) : undefined}
                    title={clickable ? `Jump to ${stepFile}` : undefined}>
                    {s.kind ? <div className="ws-step__kind">{s.kind}</div> : null}
                    <div className="ws-step__label">{s.label}{clickable ? <FileCode2 size={12} style={{ marginLeft: 6, verticalAlign: '-1px', opacity: 0.6 }} /> : null}</div>
                    {s.masked_value ? <div className="ws-step__val ws-mono">{s.masked_value}</div> : null}
                    {s.state ? <div className="ws-step__val">{s.state}</div> : null}
                  </div>
                </div>
                )
              })}
            </div>
            {ex.impact ? <div className="ws-callout" style={{ marginTop: 14 }}><b>Impact:</b> {ex.impact}</div> : null}

            {/* Chain evidence + self-explaining confidence (Task 7) */}
            {(c.chain_evidence || []).length ? (
              <div style={{ marginTop: 16 }}>
                <div className="ws-block__label">Chain Evidence</div>
                {c.chain_evidence.map((e, k) => (
                  <div key={k} className="ws-chainev">
                    <span className="ws-chainev__check">✓</span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontWeight: 560, fontSize: 13.5 }}>{e.title}</div>
                      <div className="ws-muted" style={{ fontSize: 12.5 }}>{e.why_it_contributes}{e.file ? ` · ${e.file}${e.line ? `:${e.line}` : ''}` : ''}</div>
                    </div>
                    {e.confidence ? <SoftTag>{e.confidence}</SoftTag> : null}
                  </div>
                ))}
              </div>
            ) : null}
            {(c.confidence_explanation?.checks || []).length ? (
              <div className="ws-card ws-card--pad" style={{ marginTop: 12 }}>
                <div className="ws-block__label">Why confidence is {c.confidence_explanation.confidence}</div>
                {c.confidence_explanation.checks.map((ck, k) => (
                  <div key={k} className="ws-check">
                    <span className={ck.met ? 'ws-check--yes' : 'ws-check--no'}>{ck.met ? '✓' : '✗'}</span> {ck.label}
                  </div>
                ))}
              </div>
            ) : null}
          </div>
        )
      })}
    </div>
  )
}

// ───────────────────────────── Secrets ───────────────────────────────────
// Phase 11.96 — every secret exposes type, confidence, file:line, snippet,
// masked value, View Code and Open Finding (no anonymous cards). Reuses the
// canonical secret schema (evidence.{file_path,line,snippet}, provider, type,
// confidence, validation_result, is_pair, members, relationship_type).
const VSTATE_CLASS = s => ['valid', 'invalid', 'eligible', 'skipped'].includes(s) ? s : 'skipped'

function secretType(s) {
  return s.provider || s.type || s.name || s.title || 'Secret'
}

// Build the navigable evidence list for a secret (single → one location;
// pair → one per member). Each entry feeds onOpenCode for exact-line/highlight.
function secretEvidence(s) {
  const out = []
  const seen = new Set()
  const push = (path, line, snippet, label) => {
    if (!path) return
    const key = `${path}#${line || ''}`
    if (seen.has(key)) return
    seen.add(key)
    out.push({ path, line: line || null, lines: line ? [line] : [], snippet: snippet || '', source: label })
  }
  for (const m of (s.members || [])) push(m.file_path, m.line, m.snippet, `${m.provider || m.type || 'member'} location`)
  for (const fe of (s.file_evidence || [])) push(fe.path, (fe.lines || [])[0], fe.snippet, 'credential pair')
  const ev = s.evidence || {}
  push(ev.file_path || s.full_path || s.file_path, ev.line || s.line, ev.snippet || s.snippet, 'secret location')
  return out
}

function openSecretCode(loc, evidence, i, onOpenCode) {
  if (!onOpenCode || !loc?.path) return
  onOpenCode(loc.path, loc.lines, {
    snippet: loc.snippet, source: loc.source || 'secret', highlightLine: loc.line || undefined,
    evidence, index: i,
  })
}

function SecretCard({ s, onOpenCode, onOpen }) {
  const state = VSTATE_CLASS((s.validation_result || 'skipped').toLowerCase())
  const ev = secretEvidence(s)
  const primary = ev[0]
  const conf = s.confidence || confidenceLabel(s)
  const masked = s.masked_value || s.value || '••••••••'
  return (
    <div className="ws-seccard">
      <div className="ws-seccard__head">
        <KeyRound size={15} className="ws-muted" />
        <span className="ws-seccard__type">{secretType(s)}</span>
        {s.is_pair ? <SoftTag>credential pair</SoftTag> : null}
        {conf ? <SoftTag title="Confidence">{String(conf).toUpperCase()} confidence</SoftTag> : null}
        {s.severity ? <SeverityTag severity={s.severity} compact /> : null}
        <span className={`ws-vstate ws-vstate--${state}`} style={{ marginLeft: 'auto' }}>{state}</span>
      </div>
      <div className="ws-seccard__val ws-mono">{masked}</div>
      {primary
        ? <div className="ws-seccard__loc ws-mono" title={primary.path}>{primary.path.split('/').pop()}{primary.line ? `:${primary.line}` : ''}{ev.length > 1 ? `  ·  +${ev.length - 1} more` : ''}</div>
        : <div className="ws-seccard__loc ws-seccard__loc--none">No source location</div>}
      {primary?.snippet ? <pre className="ws-code ws-code--inline">{primary.snippet}</pre> : null}
      <div className="ws-seccard__actions">
        {primary && onOpenCode ? (
          <button type="button" className="ws-btn ws-btn--sm" onClick={() => openSecretCode(primary, ev, 0, onOpenCode)}>
            <FileCode2 size={13} /> View Code
          </button>
        ) : null}
        <button type="button" className="ws-btn ws-btn--sm" onClick={onOpen}>Open Finding</button>
      </div>
    </div>
  )
}

export function SecretsPanel({ results, onOpenCode }) {
  const secrets = results.secrets || []
  const suppressed = results.suppressed_secrets || []
  const exposures = results.cloud_exposures || []
  const sum = results.secrets_summary || {}
  const pairs = secrets.filter(s => s.is_pair)
  const singles = secrets.filter(s => !s.is_pair)
  const [drawer, setDrawer] = useState(null)

  if (!secrets.length && !suppressed.length && !exposures.length) {
    return <EmptyState title="No secrets detected" body="No embedded credentials, keys, or tokens were found in application-owned code." />
  }

  const total = sum.total_application_secrets ?? secrets.length
  // Primary categories partition the visible secrets: every secret has exactly one,
  // so the counts always sum to Total Secrets (Phase 2.5.1). Prefer the backend
  // breakdown; fall back to grouping by each secret's primary_category for older scans.
  const byCategory = (sum.secrets_by_category && sum.secrets_by_category.length)
    ? sum.secrets_by_category
    : Object.entries(secrets.reduce((acc, s) => {
        const c = s.primary_category || (s.is_pair ? 'Credential Pairs' : 'Other Secrets')
        acc[c] = (acc[c] || 0) + 1
        return acc
      }, {})).map(([category, count]) => ({ category, count }))

  return (
    <div>
      <div className="ws-section__head"><h1>Secrets</h1></div>
      {/* Primary categories — these counts always sum to Total Secrets. */}
      <div className="ws-metrics ws-section">
        <Metric label="Total Secrets" value={total} />
        {byCategory.map(c => <Metric key={c.category} label={c.category} value={c.count} />)}
      </div>
      {/* Context facets — these overlap the total and are NOT part of the partition. */}
      <div className="ws-metrics ws-section">
        <Metric label="Validation Candidates" value={sum.validation_candidates ?? 0} />
        <Metric label="SDK Suppressed" value={sum.suppressed_sdk_secrets ?? suppressed.filter(s => s.suppressed_reason === 'third_party_sdk').length} />
        <Metric label="Cloud Exposures" value={sum.public_cloud_exposures ?? exposures.length} />
      </div>

      <Group title="Credential Pairs" hide={!pairs.length}>{pairs.map((s, i) => <SecretCard key={i} s={s} onOpenCode={onOpenCode} onOpen={() => setDrawer(s)} />)}</Group>
      <Group title="Credentials" hide={!singles.length}>{singles.map((s, i) => <SecretCard key={i} s={s} onOpenCode={onOpenCode} onOpen={() => setDrawer(s)} />)}</Group>
      <Group title="Cloud Exposure" hide={!exposures.length}>
        {exposures.map((e, i) => (
          <div key={i} className="ws-seccard">
            <div className="ws-seccard__head">
              <ShieldAlert size={15} style={{ color: SEV_COLOR[normSev(e.severity)] }} />
              <span className="ws-seccard__type">{e.summary || e.exposure_type}</span>
              {e.confidence ? <SoftTag>{String(e.confidence).toUpperCase()} confidence</SoftTag> : null}
              <SeverityTag severity={e.severity} compact />
            </div>
            <div className="ws-seccard__val ws-mono">{e.evidence?.target_masked || e.exposure_type}</div>
            {e.evidence?.detail || e.detail ? <div className="ws-seccard__loc">{e.evidence?.detail || e.detail}</div> : null}
          </div>
        ))}
      </Group>
      <Group title="Suppressed" hide={!suppressed.length} muted>
        {suppressed.map((s, i) => <SecretCard key={i} s={s} onOpenCode={onOpenCode} onOpen={() => setDrawer(s)} />)}
      </Group>

      {drawer ? <SecretDrawer secret={drawer} results={results} onClose={() => setDrawer(null)} onOpenCode={onOpenCode} /> : null}
    </div>
  )
}

// ─── Secret detail drawer (Task 3) — pattern type, entropy, SDK suppression,
// validation result, chain relationships, cloud exposure, credential pairs,
// plus per-location View Code (exact line / highlight / multiple locations). ──
function SecretDrawer({ secret: s, results, onClose, onOpenCode }) {
  useEscape(onClose)
  const ev = secretEvidence(s)
  const conf = s.confidence || confidenceLabel(s)
  const state = (s.validation_result || 'skipped').toLowerCase()
  const partners = [...(s.paired_with || []), ...((s.members || []).map(m => m.provider || m.type))].filter(Boolean)
  // Cross-reference any cloud exposure that names this secret's provider.
  const exposures = (results.cloud_exposures || []).filter(e =>
    s.provider && `${e.summary || ''} ${e.exposure_type || ''} ${e.provider || ''}`.toLowerCase().includes(String(s.provider).toLowerCase()))
  // Secret Intelligence assessment (Phase 1.91): context validation + verdict.
  const si = s.secret_intelligence || {}
  const detectedBy = detectionSources(s)
  const contextScore = s.secret_context_score ?? si.context_score
  const usage = si.usage_referenced
  const validationReason = s.secret_validation_reason || si.validation_reason || si.reasons?.rejected

  return (
    <>
      <div className="ws-drawer-backdrop" onClick={onClose} />
      <aside className="ws-drawer" role="dialog" aria-label="Secret details">
        <div className="ws-drawer__head">
          <div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8, flexWrap: 'wrap' }}>
              {s.severity ? <SeverityTag severity={s.severity} /> : null}
              {conf ? <SoftTag>{String(conf).toUpperCase()} conf</SoftTag> : null}
              <span className={`ws-vstate ws-vstate--${VSTATE_CLASS(state)}`}>{state}</span>
            </div>
            <h3>{secretType(s)}</h3>
          </div>
          <button type="button" className="ws-drawer__close" onClick={onClose}>×</button>
        </div>
        <div className="ws-drawer__body">
          <Block label="Masked Value"><pre className="ws-code">{s.masked_value || s.value || '••••••••'}</pre></Block>

          <Block label="Details">
            <div className="ws-kv">
              {[
                ['Pattern Type', s.type || s.provider || s.name],
                ['Provider', s.provider],
                ['Detected By', detectedBy.join(', ')],
                ['Status', s.secret_status || si.status],
                ['Confidence', conf ? `${String(conf).toUpperCase()}${s.detector_confidence != null ? ` (${s.detector_confidence})` : ''}` : ''],
                ['Context Score', contextScore != null ? `${contextScore}/100` : ''],
                ['Entropy', s.entropy != null ? Number(s.entropy).toFixed(2) : (si.entropy != null ? Number(si.entropy).toFixed(2) : '')],
                ['Ownership', ownershipLabel(s)],
                ['Usage', usage === true ? 'referenced' : (usage === false ? 'unreferenced (inert constant)' : '')],
                ['Validation Result', state],
                ['Validation Reason', validationReason],
                ['SDK Suppression', s.suppressed_reason || (s.suppressed ? 'suppressed' : 'not suppressed')],
                ['Relationship', s.relationship_type],
                ['Value SHA-256', s.value_sha256 ? `${String(s.value_sha256).slice(0, 16)}…` : ''],
              ].filter(([, v]) => v !== undefined && v !== null && v !== '').map(([k, v]) => (
                <div key={k} className="ws-kv__row"><span className="ws-kv__k">{k}</span><span className="ws-kv__v ws-mono">{v}</span></div>
              ))}
            </div>
          </Block>

          {partners.length ? (
            <Block label="Chain Relationships">
              <p style={{ fontSize: 13 }}>{s.is_pair ? 'Credential pair' : 'Linked'} {s.relationship_type ? `(${s.relationship_type})` : ''} with:</p>
              <div className="ws-refs">{partners.map((p, i) => <SoftTag key={i}>{p}</SoftTag>)}</div>
            </Block>
          ) : null}

          {(s.members || []).length ? (
            <Block label="Credential Pair Members">
              {s.members.map((m, i) => (
                <div key={i} className="ws-list__row" style={{ borderTop: i ? '1px solid var(--ws-line)' : 'none' }}>
                  <span className="ws-list__grow">
                    <span className="ws-list__title">{m.provider || m.type}</span>
                    <span className="ws-list__why ws-mono">{m.masked_value || ''} · {m.file_path ? `${String(m.file_path).split('/').pop()}${m.line ? `:${m.line}` : ''}` : 'no location'}</span>
                  </span>
                  {m.file_path && onOpenCode ? <button type="button" className="ws-btn ws-btn--sm" onClick={() => onOpenCode(m.file_path, m.line ? [m.line] : [], { highlightLine: m.line, snippet: m.snippet, source: 'pair member' })}><FileCode2 size={12} /></button> : null}
                </div>
              ))}
            </Block>
          ) : null}

          {exposures.length ? (
            <Block label="Cloud Exposure">
              {exposures.map((e, i) => (
                <div key={i} className="ws-callout" style={{ marginBottom: 8 }}>
                  <b>{e.summary || e.exposure_type}</b>
                  <div className="ws-mono" style={{ marginTop: 4 }}>{e.evidence?.target_masked || e.exposure_type}</div>
                </div>
              ))}
            </Block>
          ) : null}

          {/* Evidence locations with exact-line View Code (Task 4) */}
          <Block label={`Evidence${ev.length > 1 ? ` · ${ev.length} locations` : ''}`}>
            {ev.length ? ev.map((loc, i) => (
              <div key={i} className="ws-evid">
                <div className="ws-evid__head">
                  <span className="ws-evid__num">Evidence #{i + 1}</span>
                  <span className="ws-evid__src">{loc.source}</span>
                </div>
                <div className="ws-evid__loc ws-mono" title={loc.path}>{loc.path.split('/').pop()}{loc.line ? <span className="ws-evid__line">:{loc.line}</span> : null}</div>
                {loc.snippet ? <pre className="ws-code">{loc.snippet}</pre> : null}
                <div className="ws-evid__actions">
                  {onOpenCode ? <button type="button" className="ws-btn" onClick={() => openSecretCode(loc, ev, i, onOpenCode)}><FileCode2 size={14} /> View Code</button> : null}
                </div>
              </div>
            )) : <div className="ws-evid ws-evid--none"><div className="ws-evid__reason">No source location was resolved for this secret.</div></div>}
          </Block>
        </div>
      </aside>
    </>
  )
}

function Group({ title, children, hide, muted }) {
  if (hide) return null
  return (
    <div className="ws-section">
      <h2 style={muted ? { color: 'var(--ws-ink-3)' } : undefined}>{title}</h2>
      {children}
    </div>
  )
}

// ───────────────────────────── MASVS ─────────────────────────────────────
const MATURITY_FILL = { weak: '#dc2626', moderate: '#ea8600', strong: '#067647' }

export function MasvsPanel({ results }) {
  const cov = results.masvs_coverage || []
  const sum = results.masvs_summary || {}
  if (!cov.length) return <EmptyState title="MASVS coverage unavailable" body="This scan predates MASVS coverage intelligence." />

  const radarData = (sum.coverage_radar || cov.map(c => ({ category: c.category, score: c.score })))
    .map(d => ({ category: d.category.replace('MASVS-', ''), score: d.score }))

  return (
    <div>
      <div className="ws-section__head"><h1>MASVS Coverage</h1>
        <span className="ws-muted">Overall {sum.overall_score} · <span className={`ws-maturity ws-maturity--${sum.overall_maturity}`}>{sum.overall_maturity}</span></span></div>

      <div className="ws-two ws-section">
        <div className="ws-card ws-card--pad">
          <h2>Coverage Radar</h2>
          <div style={{ width: '100%', height: 320 }}>
            <ResponsiveContainer>
              <RadarChart data={radarData} outerRadius="72%">
                <PolarGrid stroke="#ececf0" />
                <PolarAngleAxis dataKey="category" tick={{ fontSize: 11, fill: '#52525b' }} />
                <Radar dataKey="score" stroke="#18181b" fill="#18181b" fillOpacity={0.12} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="ws-card ws-card--pad">
          <h2>Weakest Categories</h2>
          <div className="ws-list">
            {(sum.top_weaknesses || []).map((w, i) => (
              <div key={i} className="ws-list__row">
                <span className="ws-list__grow"><b>{w.category}</b></span>
                <span className={`ws-maturity ws-maturity--${w.maturity}`}>{w.maturity}</span>
                <b style={{ width: 34, textAlign: 'right' }}>{w.score}</b>
              </div>
            ))}
          </div>
          {(sum.strong_controls || []).length ? (
            <>
              <h2 style={{ marginTop: 18 }}>Strong Controls</h2>
              {sum.strong_controls.map(c => <div key={c} className="ws-mcontrol"><ShieldCheck size={13} style={{ color: '#067647' }} /> {c}</div>)}
            </>
          ) : null}
        </div>
      </div>

      <h2>All Categories</h2>
      <div className="ws-masvs-grid">
        {[...cov].sort((a, b) => a.score - b.score).map(c => (
          <div key={c.category} className="ws-mcard">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span className="ws-mcard__cat">{c.category}</span>
              <span className={`ws-maturity ws-maturity--${c.maturity}`}>{c.maturity}</span>
            </div>
            <div className="ws-mcard__bar"><span style={{ width: `${c.score}%`, background: MATURITY_FILL[c.maturity] || '#52525b' }} /></div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: 'var(--ws-ink-3)' }}>
              <span>Score {c.score}</span><span>{(c.controls_present || []).length}/{(c.controls_present || []).length + (c.controls_missing || []).length} controls</span>
            </div>
            {(c.controls_present || []).length ? (
              <div style={{ marginTop: 8 }}>{c.controls_present.map(p => <div key={p} className="ws-mcontrol"><ShieldCheck size={12} style={{ color: '#067647' }} /> {p}</div>)}</div>
            ) : null}
          </div>
        ))}
      </div>
    </div>
  )
}

// ───────────────────────────── Files ─────────────────────────────────────
export function FilesPanel({ results, onOpenCode }) {
  const [q, setQ] = useState('')
  const files = useMemo(() => {
    const map = new Map()
    for (const f of results.findings || []) {
      const p = findingPath(f)
      if (p && !map.has(p)) map.set(p, { path: p, lines: findingLines(f) })
    }
    for (const s of results.secrets || []) {
      const p = s.full_path || s.file_path || s.evidence?.file_path
      if (p && !map.has(p)) map.set(p, { path: p, lines: s.line ? [s.line] : [] })
    }
    return [...map.values()].sort((a, b) => a.path.localeCompare(b.path))
  }, [results])

  const filtered = q ? files.filter(f => f.path.toLowerCase().includes(q.toLowerCase())) : files
  if (!files.length) return <EmptyState title="No source files referenced" body="No findings carry a resolvable source path for this scan." />

  return (
    <div>
      <div className="ws-section__head"><h1>Files</h1><span className="ws-muted">{filtered.length} with evidence</span></div>
      <div className="ws-toolbar"><input className="ws-input" placeholder="Filter files…" value={q} onChange={e => setQ(e.target.value)} /></div>
      <div className="ws-card" style={{ overflow: 'hidden' }}>
        {filtered.slice(0, 300).map((f, i) => (
          <div key={i} className="ws-file" onClick={() => onOpenCode(f.path, f.lines)}>
            <FileCode2 size={14} className="ws-muted" />
            <span className="ws-file__path" title={f.path}>{f.path}</span>
            <ExternalLink size={13} className="ws-muted" />
          </div>
        ))}
      </div>
    </div>
  )
}

// ───────────────────────────── Exports ───────────────────────────────────
export function ExportsPanel({ actions, results }) {
  const cards = [
    { icon: Download, title: 'Security Report (PDF)', desc: 'Full technical findings, evidence, and score — with optional compliance scorecards (MASVS, PCI-DSS, OWASP Mobile).', cta: 'Export PDF', on: actions.onExport },
    { icon: Boxes, title: 'CycloneDX SBOM', desc: 'Dependencies, SDKs, trackers, and native libraries with known CVEs. Compatible with Dependency-Track and AWS Inspector.', cta: 'Download SBOM', on: () => actions.onSbom(results) },
    { icon: FileJson, title: 'SARIF 2.1', desc: 'Static-analysis results for GitHub Code Scanning or the VS Code SARIF viewer.', cta: 'Download SARIF', on: () => actions.onSarif(results) },
    { icon: GitBranch, title: 'CI Gate', desc: 'Check this scan against configured pass/fail thresholds and copy CI snippets.', cta: 'Open CI Gate', on: actions.onCiGate },
  ]
  return (
    <div>
      <div className="ws-section__head"><h1>Exports</h1></div>
      <div className="ws-grid" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))' }}>
        {cards.map((c, i) => (
          <div key={i} className="ws-card ws-card--pad" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <c.icon size={22} className="ws-muted" />
            <h3>{c.title}</h3>
            <p style={{ flex: 1, fontSize: 13 }}>{c.desc}</p>
            <button type="button" className="ws-btn ws-btn--primary" onClick={c.on} style={{ alignSelf: 'flex-start' }}>{c.cta}</button>
          </div>
        ))}
      </div>
    </div>
  )
}

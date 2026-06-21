// Phase 13 workspace panels. Presentation only — consumes the existing `results`
// blob (findings, analyst_explanation, secrets_summary, cloud_attack_paths,
// masvs_coverage/masvs_summary, trust_score). No backend calls except onOpenCode.
import { useMemo, useState } from 'react'
import {
  ArrowUpRight, FileCode2, KeyRound, ShieldAlert, Boxes, ExternalLink,
  ChevronRight, Layers, Download, FileJson, GitBranch, ShieldCheck,
  ScrollText, Network, Fingerprint, Cpu, Bug, Sparkles, GitCompare,
} from 'lucide-react'
import { RadarChart, PolarGrid, PolarAngleAxis, Radar, ResponsiveContainer } from 'recharts'
import {
  SEV_ORDER, SEV_RANK, SEV_COLOR, normSev, SeverityTag, SoftTag, EmptyState, Metric,
  severityCounts, ownershipLabel, confidenceLabel, findingPath, findingLines, buildEvidence, useEscape,
} from './ui.jsx'

// ───────────────────────────── Overview ──────────────────────────────────
export function OverviewPanel({ results, onOpenSection, onOpenFinding }) {
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
  const topChain = (analyst.most_exploitable_chains || [])[0] || chains[0]

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
        <Metric label="Trust Score" value={`${trust.score ?? '—'}`} rating={trust.rating} />
        <Metric label="Security Score" value={<>{score.score ?? '—'}<small>/100</small></>} sub={score.grade ? `Grade ${score.grade}` : ''} />
        <Metric label="Source Resolution" value={`${res.source_resolution_pct ?? '—'}%`} sub="findings located" />
        <Metric label="View Code" value={`${res.view_code_coverage_pct ?? '—'}%`} sub="renderable evidence" />
        <Metric label="Attack Chains" value={chains.length} sub="cloud exposure paths" />
        <Metric label="Secrets" value={secretsSum.total_application_secrets ?? (results.secrets || []).length} sub={`${secretsSum.suppressed_sdk_secrets ?? 0} SDK suppressed`} />
      </div>

      {/* Workspace launcher (Task 11) */}
      <div className="ws-section">
        <h2>Deep Analysis</h2>
        <div className="ws-launcher">
          {[
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

      <div className="ws-two ws-section">
        {/* Top risks */}
        <div className="ws-card ws-card--pad">
          <h2>Top Risks</h2>
          {topRisks.length ? (
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

        {/* Right column: chain + MASVS */}
        <div className="ws-grid" style={{ gridTemplateColumns: '1fr' }}>
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
                <button type="button" className="ws-btn" style={{ marginTop: 12 }} onClick={() => onOpenSection('masvs')}>View MASVS coverage</button>
              </>
            ) : <p className="ws-muted">MASVS coverage not available for this scan.</p>}
          </div>
        </div>
      </div>

      {/* Recent findings */}
      <div className="ws-section">
        <div className="ws-section__head"><h2>Recent Findings</h2>
          <button type="button" className="ws-btn" onClick={() => onOpenSection('findings')}>All findings <ChevronRight size={14} /></button></div>
        {findings.slice(0, 6).map((f, i) => <FindingRow key={i} f={f} onClick={() => onOpenFinding(f)} />)}
      </div>
    </div>
  )
}

// ───────────────────────────── Findings ──────────────────────────────────
function FindingRow({ f, onClick }) {
  const s = normSev(f.severity)
  const conf = confidenceLabel(f)
  const own = ownershipLabel(f)
  const path = findingPath(f)
  return (
    <div className="ws-finding" onClick={onClick} role="button" tabIndex={0}
      onKeyDown={e => { if (e.key === 'Enter') onClick() }}>
      <div className="ws-finding__row">
        <span className="ws-finding__sev" style={{ background: SEV_COLOR[s] }} />
        <div className="ws-finding__main">
          <div className="ws-finding__title">{f.title || f.name || 'Finding'}</div>
          <div className="ws-finding__meta">
            <SeverityTag severity={s} />
            {conf ? <SoftTag title="Evidence quality / confidence">{conf} conf</SoftTag> : null}
            {own ? <SoftTag title="Ownership">{own}</SoftTag> : null}
            {f.category ? <SoftTag>{f.category}</SoftTag> : null}
            {path ? <span className="ws-finding__path ws-mono">{path.split('/').slice(-2).join('/')}{f.line ? `:${f.line}` : ''}</span> : null}
          </div>
        </div>
        <ChevronRight size={16} className="ws-muted" />
      </div>
    </div>
  )
}

export function FindingsPanel({ results, onOpenFinding }) {
  const all = results.findings || []
  const [q, setQ] = useState('')
  const [sev, setSev] = useState('all')
  const [appOnly, setAppOnly] = useState(false)
  const [limit, setLimit] = useState(60)

  const filtered = useMemo(() => {
    const ql = q.trim().toLowerCase()
    return all.filter(f => {
      if (sev !== 'all' && normSev(f.severity) !== sev) return false
      if (appOnly && (f.ownership_label || f.ownership) && (f.ownership_label || f.ownership) !== 'APPLICATION' && (f.ownership_label || f.ownership) !== 'APP') return false
      if (ql) {
        const blob = `${f.title} ${f.category} ${findingPath(f)} ${f.cwe || ''}`.toLowerCase()
        if (!blob.includes(ql)) return false
      }
      return true
    }).sort((a, b) => SEV_RANK[normSev(a.severity)] - SEV_RANK[normSev(b.severity)])
  }, [all, q, sev, appOnly])

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
      {filtered.length ? (
        <>
          {filtered.slice(0, limit).map((f, i) => <FindingRow key={i} f={f} onClick={() => onOpenFinding(f)} />)}
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

// ───────────────────────── Finding details drawer ────────────────────────
export function FindingDrawer({ finding, onClose, onOpenCode }) {
  useEscape(onClose)
  if (!finding) return null
  const f = finding
  const ex = f.analyst_explanation || {}
  const snippet = f.snippet || f.code_context || (f.file_evidence?.[0]?.snippet) || ''
  const rem = ex.remediation || {}

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

          <EvidenceLocations ex={ex} finding={f} primarySnippet={snippet} onOpenCode={onOpenCode} />

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
    </>
  )
}

function Block({ label, children }) {
  return <div className="ws-block"><div className="ws-block__label">{label}</div>{children}</div>
}

// Evidence locations (Tasks 5/6/7): unified, ordered evidence list. Each entry
// opens the viewer scrolled to + highlighting the exact line; when the line is
// not declared it is resolved from the snippet (≈ approximate). The whole list
// is handed to the viewer so it can offer Prev/Next evidence navigation.
function EvidenceLocations({ ex, finding, primarySnippet, onOpenCode }) {
  const evidence = buildEvidence(finding)
  if (!evidence.length) {
    return primarySnippet
      ? <div className="ws-block"><div className="ws-block__label">Evidence</div><pre className="ws-code">{primarySnippet}</pre></div>
      : null
  }
  return (
    <div className="ws-block">
      <div className="ws-block__label">Evidence{evidence.length > 1 ? ` · ${evidence.length} locations` : ''}</div>
      {evidence.map((loc, i) => {
        const lineLabel = loc.line ? `${loc.line}` : (loc.snippet ? '≈ resolved' : '≈ approx')
        return (
          <div key={i} style={{ marginBottom: i < evidence.length - 1 ? 14 : 0 }}>
            <div className="ws-mono ws-muted" style={{ marginBottom: 6 }}>
              Evidence #{i + 1} · {loc.path}{loc.line ? `:${loc.line}` : ''} · {loc.source}
            </div>
            {loc.snippet ? <pre className="ws-code">{loc.snippet}</pre> : null}
            <button type="button" className="ws-btn" style={{ marginTop: 8 }}
              onClick={() => onOpenCode(loc.path, loc.lines, { snippet: loc.snippet, source: loc.source, approximate: loc.approximate || !loc.line, evidence, index: i })}>
              <FileCode2 size={14} /> View at line {lineLabel}
            </button>
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
export function ChainsPanel({ results }) {
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
              {steps.map((s, j) => (
                <div key={j} className="ws-step">
                  <div className="ws-step__rail">
                    <span className={`ws-step__node${s.kind === 'exposure' ? ' ws-step__node--exposure' : ''}`} />
                    <span className="ws-step__line" />
                  </div>
                  <div className="ws-step__body">
                    {s.kind ? <div className="ws-step__kind">{s.kind}</div> : null}
                    <div className="ws-step__label">{s.label}</div>
                    {s.masked_value ? <div className="ws-step__val ws-mono">{s.masked_value}</div> : null}
                    {s.state ? <div className="ws-step__val">{s.state}</div> : null}
                  </div>
                </div>
              ))}
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
function SecretRow({ s }) {
  const state = (s.validation_result || 'skipped').toLowerCase()
  return (
    <div className="ws-secret">
      <KeyRound size={16} className="ws-muted" />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div className="ws-secret__name">{s.name || s.type || s.provider}</div>
        <div className="ws-secret__val">{s.masked_value || s.value || '••••'}</div>
      </div>
      {s.severity ? <SeverityTag severity={s.severity} compact /> : null}
      <span className={`ws-vstate ws-vstate--${['valid', 'invalid', 'eligible', 'skipped'].includes(state) ? state : 'skipped'}`}>{state}</span>
    </div>
  )
}

export function SecretsPanel({ results }) {
  const secrets = results.secrets || []
  const suppressed = results.suppressed_secrets || []
  const exposures = results.cloud_exposures || []
  const sum = results.secrets_summary || {}
  const pairs = secrets.filter(s => s.is_pair)
  const singles = secrets.filter(s => !s.is_pair)

  if (!secrets.length && !suppressed.length && !exposures.length) {
    return <EmptyState title="No secrets detected" body="No embedded credentials, keys, or tokens were found in application-owned code." />
  }

  return (
    <div>
      <div className="ws-section__head"><h1>Secrets</h1></div>
      <div className="ws-metrics ws-section">
        <Metric label="Application Secrets" value={sum.total_application_secrets ?? singles.length} />
        <Metric label="Credential Pairs" value={sum.paired_credentials ?? pairs.length} />
        <Metric label="Validation Candidates" value={sum.validation_candidates ?? 0} />
        <Metric label="SDK Suppressed" value={sum.suppressed_sdk_secrets ?? suppressed.filter(s => s.suppressed_reason === 'third_party_sdk').length} />
        <Metric label="Cloud Exposures" value={sum.public_cloud_exposures ?? exposures.length} />
      </div>

      <Group title="Credential Pairs" hide={!pairs.length}>{pairs.map((s, i) => <SecretRow key={i} s={s} />)}</Group>
      <Group title="Credentials" hide={!singles.length}>{singles.map((s, i) => <SecretRow key={i} s={s} />)}</Group>
      <Group title="Cloud Exposure" hide={!exposures.length}>
        {exposures.map((e, i) => (
          <div key={i} className="ws-secret">
            <ShieldAlert size={16} style={{ color: SEV_COLOR[normSev(e.severity)] }} />
            <div style={{ flex: 1 }}>
              <div className="ws-secret__name">{e.summary || e.exposure_type}</div>
              <div className="ws-secret__val">{e.evidence?.target_masked || e.exposure_type}</div>
            </div>
            <SeverityTag severity={e.severity} compact />
          </div>
        ))}
      </Group>
      <Group title="Suppressed" hide={!suppressed.length} muted>
        {suppressed.map((s, i) => <SecretRow key={i} s={s} />)}
      </Group>
    </div>
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

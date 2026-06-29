// Phase 11.75 — deep-analysis workspace pages. Exposes EXISTING backend
// intelligence (certificate, network, manifest, components, android_api, apkid/
// behavior, compare history, AI analyst, source files). Presentation only.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ShieldCheck, ShieldAlert, Network, FileCode2, Boxes, Cpu, Bug, GitCompare,
  Sparkles, Folder, FileText, Search, ChevronRight, ArrowUpRight, Copy, Minus,
  MessageSquare, Plus, Trash2, Pencil, Send, ChevronDown,
} from 'lucide-react'
import { SEV_COLOR, normSev, SeverityTag, SoftTag, EmptyState, Metric } from './ui.jsx'
import { fetchAiProviders, runFindingAction } from '../../lib/ai-providers.js'
import { apiFetch } from '../../lib/auth.js'
import { loadLocalHistory, getStoredScan } from '../../lib/scan-data.js'

// ── Verdict badge (GOOD / WARNING / HIGH RISK) ─────────────────────────────
function Verdict({ level, children }) {
  const cls = level === 'risk' ? 'risk' : level === 'warn' ? 'warn' : 'good'
  const label = level === 'risk' ? 'HIGH RISK' : level === 'warn' ? 'WARNING' : 'GOOD'
  return <span className={`ws-verdict ws-verdict--${cls}`}>{children || label}</span>
}

function Rows({ items }) {
  return (
    <div className="ws-kv">
      {items.filter(([, v]) => v !== undefined && v !== null && v !== '').map(([k, v]) => (
        <div key={k} className="ws-kv__row"><span className="ws-kv__k">{k}</span><span className="ws-kv__v ws-mono">{v}</span></div>
      ))}
    </div>
  )
}

// ── Shared deep-analysis UI helpers (Phase 11.9) ────────────────────────────
const RISK_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4, none: 5, normal: 5, dangerous: 1, signature: 3 }

// "Show N more" pager — keeps long lists bounded but fully reachable.
function Pager({ count, limit, setLimit, step = 50 }) {
  if (count <= limit) return null
  return (
    <button type="button" className="ws-btn ws-btn--sm" style={{ marginTop: 12 }} onClick={() => setLimit(l => l + step)}>
      Show {Math.min(step, count - limit)} more · {count - limit} remaining
    </button>
  )
}

// Filter chips that double as a counted segmented control.
function Chips({ value, onChange, options }) {
  return (
    <>
      {options.map(o => {
        const id = typeof o === 'string' ? o : o.id
        const label = typeof o === 'string' ? o : o.label
        const n = typeof o === 'string' ? null : o.count
        return (
          <button key={id} type="button" className={`ws-chip${value === id ? ' is-active' : ''}`} onClick={() => onChange(id)}>
            {label}{n !== null && n !== undefined ? <span className="ws-muted"> {n}</span> : null}
          </button>
        )
      })}
    </>
  )
}

// Reference-grade permission → MASVS category map (deterministic, not a finding).
const PERM_MASVS = [
  [/LOCATION/i, 'MASVS-PRIVACY-1'],
  [/CONTACTS|CALENDAR|SMS|CALL_LOG|READ_PHONE|PHONE_STATE|CALL/i, 'MASVS-PRIVACY-1'],
  [/CAMERA|RECORD_AUDIO|MICROPHONE/i, 'MASVS-PRIVACY-1'],
  [/EXTERNAL_STORAGE|MANAGE_EXTERNAL|MEDIA/i, 'MASVS-STORAGE-2'],
  [/INTERNET|NETWORK_STATE|WIFI/i, 'MASVS-NETWORK-1'],
  [/ACCESSIBILITY|BIND_DEVICE_ADMIN|SYSTEM_ALERT_WINDOW|REQUEST_INSTALL/i, 'MASVS-PLATFORM-1'],
  [/BIOMETRIC|USE_FINGERPRINT/i, 'MASVS-AUTH-2'],
]
function permMasvs(p) { for (const [rx, m] of PERM_MASVS) if (rx.test(p)) return m; return '' }

// Reference-grade Android API category → risk level (deterministic).
const API_RISK = [
  [/runtime|exec|command|process/i, 'high'],
  [/reflection|dexload|dynamic|jar loading/i, 'high'],
  [/webview/i, 'high'],
  [/crypto|keystore|cipher|certificate/i, 'medium'],
  [/ssl|trust/i, 'medium'],
  [/content provider|shared preferences|sqlite/i, 'medium'],
  [/storage|read file|write file/i, 'medium'],
  [/location|gps|cell|contacts|camera|sms|phone|installed app|accessibility|device admin/i, 'medium'],
  [/intent|ipc|broadcast/i, 'low'],
  [/notification|clipboard|base64|http|network|wifi/i, 'low'],
]
function apiRisk(cat) { for (const [rx, r] of API_RISK) if (rx.test(cat)) return r; return 'info' }

// ───────────────────────────── Permissions ───────────────────────────────
const PROT_LABEL = { dangerous: 'Dangerous', signature: 'Signature', normal: 'Normal', unknown: 'Unknown' }
const PROT_RISK = { dangerous: 'high', signature: 'low', normal: 'info', unknown: 'info' }

export function PermissionsPanel({ results, onOpenCode }) {
  // Merge the workspace view (type/desc/usage) with classified severities.
  const classified = (results.permissions || {}).classified || []
  const sevByPerm = {}
  classified.forEach(p => { if (p.permission) sevByPerm[p.permission] = p.severity })
  const base = results.permissions_workspace
    || classified.map(p => ({
      permission: p.permission, short_name: p.short_name || (p.permission || '').split('.').pop(),
      type: p.status || 'normal', description: p.description || '', used_in_files: [], findings: [],
    }))
  const all = base.map(p => ({
    ...p,
    risk: sevByPerm[p.permission] || PROT_RISK[p.type] || 'info',
    masvs: permMasvs(p.permission || ''),
  }))

  const [q, setQ] = useState('')
  const [group, setGroup] = useState('all')
  const [sort, setSort] = useState('risk')
  const [limit, setLimit] = useState(50)

  if (!all.length) return <EmptyState title="No permissions declared" body="This package's manifest requests no permissions, so there is nothing to classify." />

  const counts = all.reduce((m, p) => { m[p.type] = (m[p.type] || 0) + 1; return m }, {})
  let rows = all.filter(p => group === 'all' || p.type === group)
  rows = rows.filter(p => !q || `${p.permission} ${p.description} ${p.masvs}`.toLowerCase().includes(q.toLowerCase()))
  rows = [...rows].sort((a, b) => sort === 'name'
    ? (a.short_name || '').localeCompare(b.short_name || '')
    : (RISK_RANK[a.risk] ?? 4) - (RISK_RANK[b.risk] ?? 4))

  return (
    <div>
      <div className="ws-section__head"><h1>Permissions</h1><span className="ws-muted">{all.length}</span></div>
      <div className="ws-metrics ws-section">
        <Metric label="Total" value={all.length} />
        <Metric label="Dangerous" value={counts.dangerous || 0} />
        <Metric label="Signature" value={counts.signature || 0} />
        <Metric label="Normal" value={counts.normal || 0} />
      </div>
      <div className="ws-toolbar">
        <input className="ws-input" placeholder="Search permissions, MASVS…" value={q} onChange={e => { setQ(e.target.value); setLimit(50) }} style={{ minWidth: 260 }} />
        <Chips value={group} onChange={v => { setGroup(v); setLimit(50) }} options={[
          { id: 'all', label: 'All', count: all.length },
          { id: 'dangerous', label: 'Dangerous', count: counts.dangerous || 0 },
          { id: 'signature', label: 'Signature', count: counts.signature || 0 },
          { id: 'normal', label: 'Normal', count: counts.normal || 0 },
        ]} />
        <span className="ws-muted" style={{ marginLeft: 'auto', fontSize: 12 }}>Sort</span>
        <Chips value={sort} onChange={setSort} options={[{ id: 'risk', label: 'Risk' }, { id: 'name', label: 'Name' }]} />
      </div>

      {rows.length ? rows.slice(0, limit).map((p, i) => (
        <div key={i} className="ws-card ws-card--pad" style={{ marginBottom: 8 }}>
          <div className="ws-permhead">
            <span className={`ws-perm ws-perm--${p.type}`}>{PROT_LABEL[p.type] || p.type}</span>
            <b style={{ fontSize: 14 }}>{p.short_name}</b>
            <SeverityTag severity={p.risk} compact />
            {p.masvs ? <SoftTag title="MASVS category (reference mapping)">{p.masvs}</SoftTag> : null}
            <span className="ws-mono ws-muted ws-permpkg" title={p.permission}>{p.permission}</span>
          </div>
          {p.description ? <p style={{ fontSize: 13, marginTop: 6 }}>{p.description}</p> : null}
          {(p.evidence || []).length ? (
            <div style={{ marginTop: 8 }}>
              <div className="ws-block__label">{p.reference_count || p.evidence.length} reference{(p.reference_count || p.evidence.length) !== 1 ? 's' : ''} in source{p.evidence.length > 1 ? ' · navigable with Prev/Next' : ''}</div>
              {(() => {
                // Build one navigable evidence set so View Code gets Prev/Next
                // across the permission's distinct reference locations.
                const evList = p.evidence.map(e => ({
                  path: e.path, lines: e.line ? [e.line] : [], snippet: e.snippet,
                  source: 'permission reference', highlightLine: e.line || undefined, approximate: !e.line,
                }))
                return p.evidence.slice(0, 8).map((e, j) => (
                  <div key={j} className="ws-file" onClick={() => onOpenCode(e.path, e.line ? [e.line] : [], { snippet: e.snippet, source: 'permission reference', highlightLine: e.line, approximate: !e.line, evidence: evList, index: j })}>
                    <FileCode2 size={12} className="ws-muted" />
                    <span className="ws-file__path" title={e.path}>{e.path}{e.line ? `:${e.line}` : ''}</span>
                    <ChevronRight size={12} className="ws-muted" />
                  </div>
                ))
              })()}
            </div>
          ) : (p.used_in_files || []).length ? (
            <div style={{ marginTop: 8 }}>
              <div className="ws-block__label">Used in {p.used_in_files.length} file(s)</div>
              {p.used_in_files.slice(0, 8).map((f, j) => (
                <div key={j} className="ws-file" onClick={() => onOpenCode(f, [])}><FileCode2 size={12} className="ws-muted" /><span className="ws-file__path" title={f}>{f}</span></div>
              ))}
            </div>
          ) : null}
          {(p.findings || []).length ? (
            <div style={{ marginTop: 8 }}>
              <div className="ws-block__label">Related findings</div>
              {p.findings.map((t, j) => <div key={j} className="ws-mcontrol"><ShieldAlert size={12} style={{ color: SEV_COLOR.medium }} /> {t}</div>)}
            </div>
          ) : null}
        </div>
      )) : <EmptyState title="No matching permissions" body="No permissions match the current search/filter. Clear filters to see all." />}
      <Pager count={rows.length} limit={limit} setLimit={setLimit} />
    </div>
  )
}

// ───────────────────────── Android Security posture ──────────────────────
const POSTURE_LABELS = {
  debuggable: 'Debuggable', allowBackup: 'Allow Backup', minSdk: 'Min SDK', targetSdk: 'Target SDK',
  cleartextTraffic: 'Cleartext Traffic', networkSecurityConfig: 'Network Security Config',
  signatureScheme: 'Signature Scheme', janusRisk: 'Janus Risk', backupRisk: 'Backup Risk',
  legacyAndroidSupport: 'Legacy Android Support', installationOnOldVersions: 'Installs on Old Versions',
  rootDetection: 'Root Detection', fridaDetection: 'Frida Detection',
  screenshotProtection: 'Screenshot Protection', certificatePinning: 'Certificate Pinning',
}
function postureText(v) {
  if (Array.isArray(v)) return v.length ? v.join(', ') : '—'
  if (v === true) return 'Yes'; if (v === false) return 'No'
  return v === null || v === undefined ? '—' : String(v)
}
export function AndroidPosturePanel({ results }) {
  const ap = results.android_posture
  if (!ap || !Object.keys(ap).length) return <EmptyState title="Android posture unavailable" body="This scan predates the Android posture workspace or is not an Android app." />
  const order = Object.keys(POSTURE_LABELS).filter(k => k in ap)
  return (
    <div>
      <div className="ws-section__head"><h1>Android Security</h1></div>
      <div className="ws-masvs-grid">
        {order.map(k => {
          const item = ap[k] || {}
          const risk = item.risk || 'good'
          return (
            <div key={k} className={`ws-mcard ws-posture ws-posture--${risk}`}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span className="ws-mcard__cat">{POSTURE_LABELS[k]}</span>
                {risk === 'risk' ? <ShieldAlert size={15} style={{ color: SEV_COLOR.high }} />
                  : risk === 'warn' ? <ShieldAlert size={15} style={{ color: SEV_COLOR.medium }} />
                    : <ShieldCheck size={15} style={{ color: '#067647' }} />}
              </div>
              <div style={{ fontSize: 18, fontWeight: 700, marginTop: 6 }}>{postureText(item.value)}</div>
              <div className={`ws-maturity ws-maturity--${risk === 'risk' ? 'weak' : risk === 'warn' ? 'moderate' : 'strong'}`} style={{ marginTop: 4 }}>
                {risk === 'risk' ? 'HIGH RISK' : risk === 'warn' ? 'REVIEW' : 'OK'}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ───────────────────────────── Taint Flows ───────────────────────────────
export function TaintFlowPanel({ results, onOpenCode }) {
  // Prefer taint_graph (carries file/line/risk); fall back to taint_flows.
  const graph = results.taint_graph || []
  const flat = (results.taint_flows || []).map(t => ({ ...t, risk: t.sink_sev || t.risk }))
  const flows = graph.length ? graph : flat
  const [q, setQ] = useState('')
  const [risk, setRisk] = useState('all')
  const [limit, setLimit] = useState(25)

  if (!flows.length) return <EmptyState title="No taint flows" body="The DEX call-graph analysis resolved no source→sink data-flow paths for this package (no tainted user input reached a sensitive sink within the traversal budget)." />

  const riskCounts = flows.reduce((m, t) => { const r = normSev(t.risk); m[r] = (m[r] || 0) + 1; return m }, {})
  const ql = q.trim().toLowerCase()
  let rows = flows.filter(t => risk === 'all' || normSev(t.risk) === risk)
  rows = rows.filter(t => !ql || `${t.source} ${t.sink} ${t.source_cat} ${t.sink_cat} ${t.file || ''} ${t.class_name || ''}`.toLowerCase().includes(ql))
  rows = [...rows].sort((a, b) => (RISK_RANK[normSev(a.risk)] ?? 4) - (RISK_RANK[normSev(b.risk)] ?? 4))

  return (
    <div>
      <div className="ws-section__head"><h1>Data Flow Analysis</h1><span className="ws-muted">{flows.length} flow{flows.length !== 1 ? 's' : ''}</span></div>
      <div className="ws-metrics ws-section">
        <Metric label="Total flows" value={flows.length} />
        <Metric label="High" value={(riskCounts.high || 0) + (riskCounts.critical || 0)} />
        <Metric label="Medium" value={riskCounts.medium || 0} />
        <Metric label="Low / Info" value={(riskCounts.low || 0) + (riskCounts.info || 0)} />
      </div>
      <div className="ws-toolbar">
        <input className="ws-input" placeholder="Search source, sink, file…" value={q} onChange={e => { setQ(e.target.value); setLimit(25) }} style={{ minWidth: 280 }} />
        <Chips value={risk} onChange={v => { setRisk(v); setLimit(25) }} options={[
          { id: 'all', label: 'All' },
          { id: 'high', label: 'High', count: riskCounts.high || 0 },
          { id: 'medium', label: 'Medium', count: riskCounts.medium || 0 },
          { id: 'low', label: 'Low', count: riskCounts.low || 0 },
        ]} />
      </div>

      {rows.length ? (
        <>
          {rows.slice(0, limit).map((t, i) => {
            const mids = (t.call_chain || []).slice(1, -1)
            // `file` is sometimes a class descriptor (line 0), not a resolvable path.
            const isPath = t.file && (/[/\\]/.test(t.file) || /\.(java|kt|kts|smali|xml)$/i.test(t.file))
            const classLabel = t.class_name || (t.file && !isPath ? t.file : '')
            return (
              <div key={i} className="ws-chain">
                <div className="ws-chain__head">
                  <SeverityTag severity={t.risk} />
                  <span className="ws-chain__title">{t.source_cat || 'Source'} → {t.sink_cat || 'Sink'}</span>
                  {t.confidence ? <SoftTag title="Confidence">{t.confidence}</SoftTag> : null}
                  {isPath ? <button type="button" className="ws-btn ws-btn--sm" style={{ marginLeft: 'auto' }} onClick={() => onOpenCode(t.file, t.line ? [t.line] : [], { source: 'taint sink', highlightLine: t.line, approximate: !t.line })}><FileCode2 size={13} /> {t.file.split('/').pop()}{t.line ? `:${t.line}` : ''}</button> : null}
                </div>
                {classLabel ? <div className="ws-muted ws-mono" style={{ fontSize: 12, marginTop: 4 }}>{String(classLabel).replace(/;$/, '')}{t.method_name ? `.${t.method_name}` : ''}</div> : null}
                <div className="ws-timeline" style={{ marginTop: 12 }}>
                  <Step kind="Source" label={t.source} />
                  {mids.length ? mids.map((c, j) => <Step key={j} kind="Transformation" label={c} />)
                    : <Step kind="Transformation" label="direct flow (no intermediate calls)" />}
                  <Step kind="Sink" label={t.sink} last exposure />
                </div>
                {(t.call_chain || []).length ? (
                  <div style={{ marginTop: 10 }}>
                    <div className="ws-block__label">Call chain</div>
                    <div className="ws-mono ws-muted" style={{ fontSize: 11.5, lineHeight: 1.7, wordBreak: 'break-word' }}>
                      {t.call_chain.join('  →  ')}
                    </div>
                  </div>
                ) : null}
              </div>
            )
          })}
          <Pager count={rows.length} limit={limit} setLimit={setLimit} step={25} />
        </>
      ) : <EmptyState title="No matching flows" body="No taint flows match the current search/filter." />}
    </div>
  )
}
function Step({ kind, label, last, exposure }) {
  return (
    <div className="ws-step">
      <div className="ws-step__rail">
        <span className={`ws-step__node${exposure ? ' ws-step__node--exposure' : ''}`} />
        {!last ? <span className="ws-step__line" /> : null}
      </div>
      <div className="ws-step__body">
        <div className="ws-step__kind">{kind}</div>
        <div className="ws-step__label ws-mono">{label}</div>
      </div>
    </div>
  )
}

// ───────────────────────────── Certificate ───────────────────────────────
export function CertificatePanel({ results }) {
  const c = results.certificate || {}
  const cw = results.certificate_workspace || {}      // Phase 11.75 structure (preferred)
  const hasWs = Object.keys(cw).length > 0
  if (!c.available && !(c.scheme || []).length && !hasWs) {
    return <EmptyState title="No certificate data" body={c.unavailable_reason || 'Signing certificate could not be extracted for this package.'} />
  }
  const schemes = cw.signature_schemes || c.scheme || c.schemes || []
  const has = v => schemes.some(s => String(s).toLowerCase().includes(v))
  const algo = cw.algorithm || c.signature_algo
  const keySize = cw.key_size || c.key_size
  const keyType = cw.key_type || c.key_type || ''
  const keyAlgo = /rsa/i.test(keyType) ? 'RSA' : /ec|ecdsa|elliptic/i.test(keyType) ? 'ECC' : /dsa/i.test(keyType) ? 'DSA' : (keyType || '')
  const md5 = cw.md5 || c.md5 || c.md5_fingerprint
  const debugCert = hasWs ? cw.debug_cert : c.debug_cert
  const expired = hasWs ? cw.expired : c.expired
  const selfSigned = hasWs ? cw.self_signed : (c.subject && c.issuer && JSON.stringify(c.subject) === JSON.stringify(c.issuer))
  const sha1Used = /sha1/i.test(algo || '')
  const md5Used = /md5/i.test(algo || '')
  const weakAlgo = sha1Used || md5Used
  const smallKey = keySize && Number(keySize) < 2048
  const rsa1024 = keyAlgo === 'RSA' && keySize && Number(keySize) <= 1024
  const janusRisk = (hasWs && cw.janus_possible !== undefined) ? cw.janus_possible
    : (c.janus_risk !== undefined ? c.janus_risk : (has('v1') && !has('v2') && !has('v3')))
  const overallVuln = (c.security_overview?.overall || '').toLowerCase() === 'vulnerable'

  let level = 'good'
  if (debugCert || overallVuln || janusRisk || md5Used || rsa1024) level = 'risk'
  else if (expired || weakAlgo || smallKey || selfSigned) level = 'warn'

  // Workspace subject/issuer are pre-joined strings; raw cert is an object.
  const subj = hasWs ? cw.subject : Object.entries(c.subject || {}).map(([k, v]) => `${k}=${v}`).join(', ')
  const iss = hasWs ? cw.issuer : Object.entries(c.issuer || {}).map(([k, v]) => `${k}=${v}`).join(', ')
  const certFindings = cw.findings || []

  // Concrete risk summary (severity-ranked).
  const risks = [
    debugCert && ['high', 'Signed with a debug certificate — not production-safe and publicly known key'],
    md5Used && ['high', 'MD5 signature algorithm — cryptographically broken'],
    rsa1024 && ['high', `RSA-${keySize} signing key — below the 2048-bit minimum`],
    janusRisk && ['high', 'Janus risk — v1-only signing allows DEX injection on older Android'],
    sha1Used && !md5Used && ['medium', 'SHA-1 signature algorithm — collision-prone, deprecated'],
    smallKey && !rsa1024 && ['medium', `Small signing key (${keySize}-bit)`],
    selfSigned && ['low', 'Self-signed certificate — issuer equals subject (expected for app signing)'],
    expired && ['medium', 'Certificate outside its validity window'],
  ].filter(Boolean).sort((a, b) => RISK_RANK[a[0]] - RISK_RANK[b[0]])

  return (
    <div>
      <div className="ws-section__head"><h1>Certificates</h1><Verdict level={level} /></div>

      <div className="ws-card ws-card--pad ws-section">
        <h2>Signature Schemes</h2>
        <div style={{ display: 'flex', gap: 8 }}>
          {['v1', 'v2', 'v3', 'v4'].map(v => (
            <span key={v} className={`ws-scheme ${has(v) ? 'is-on' : ''}`}>APK Signature {v.toUpperCase()}</span>
          ))}
        </div>
      </div>

      <div className="ws-two ws-section">
        <div className="ws-card ws-card--pad">
          <h2>Identity</h2>
          <Rows items={[
            ['Subject', subj], ['Issuer', iss], ['Serial', cw.serial || c.serial],
            ['Signature algorithm', algo],
            ['Key algorithm', keyAlgo], ['Key size', keySize ? `${keySize}-bit` : ''],
            ['Self-signed', selfSigned === undefined ? '' : (selfSigned ? 'Yes' : 'No')],
            ['Valid from', cw.valid_from || c.valid_from], ['Valid to', cw.valid_to || c.valid_to],
          ]} />
        </div>
        <div className="ws-card ws-card--pad">
          <h2>Fingerprints</h2>
          <Rows items={[
            ['MD5', md5],
            ['SHA-1', cw.sha1 || c.sha1_fingerprint || c.sha1],
            ['SHA-256', cw.sha256 || c.sha256_fingerprint || c.sha256],
            ['SHA-512', cw.sha512 || c.sha512_fingerprint || c.sha512],
          ]} />
          {!md5 ? <p className="ws-muted" style={{ fontSize: 11.5, marginTop: 8 }}>MD5 not emitted by the extractor for this certificate.</p> : null}
        </div>
      </div>

      <div className="ws-card ws-card--pad ws-section">
        <h2>Security Checks</h2>
        <div className="ws-assess">
          <AssessRow ok={!debugCert} good="Production certificate" bad="Debug certificate detected" />
          <AssessRow ok={!expired} good="Within validity period" bad="Certificate expired" />
          <AssessRow ok={!janusRisk} good="Janus-resistant (v2+/v3 signed)" bad="Janus risk — v1-only signing" />
          <AssessRow ok={!sha1Used} good="No SHA-1 in signature" bad="SHA-1 used in signature algorithm" />
          <AssessRow ok={!md5Used} good="No MD5 in signature" bad="MD5 used in signature algorithm" />
          <AssessRow ok={!rsa1024} good="RSA key ≥ 2048-bit" bad={`RSA-1024 weak signing key`} />
          <AssessRow ok={!smallKey} good="Adequate key size" bad={`Small key size (${keySize}-bit)`} />
          <AssessRow ok={!selfSigned} good="CA-issued certificate" bad="Self-signed certificate" />
        </div>
      </div>

      <div className="ws-card ws-card--pad ws-section">
        <h2>Risk Summary</h2>
        {risks.length ? risks.map(([sev, text], i) => (
          <div key={i} className="ws-mcontrol"><SeverityTag severity={sev} compact /> <span style={{ marginLeft: 6 }}>{text}</span></div>
        )) : <div className="ws-assess"><AssessRow ok good="No certificate risks detected — production-grade signing" /></div>}
      </div>

      {(cw.issues || []).length ? (
        <div className="ws-card ws-card--pad ws-section">
          <h2>Issue Intelligence <span className="ws-muted" style={{ fontSize: 13 }}>{cw.issues.length}</span></h2>
          {[...cw.issues].sort((a, b) => (RISK_RANK[a.severity] ?? 4) - (RISK_RANK[b.severity] ?? 4)).map((iss, i) => (
            <CertIssueCard key={iss.id || i} iss={iss} />
          ))}
        </div>
      ) : null}

      {certFindings.length ? (
        <div className="ws-card ws-card--pad">
          <h2>Certificate Findings</h2>
          {certFindings.map((t, i) => <div key={i} className="ws-mcontrol"><ShieldAlert size={13} style={{ color: SEV_COLOR.medium }} /> {t}</div>)}
        </div>
      ) : null}
    </div>
  )
}

function CertIssueCard({ iss }) {
  const [open, setOpen] = useState(false)
  const row = (label, val) => val ? (
    <div className="ws-kv__row"><span className="ws-kv__k">{label}</span><span className="ws-kv__v">{val}</span></div>
  ) : null
  return (
    <div className="ws-card ws-card--pad" style={{ marginBottom: 8 }}>
      <div className="ws-permhead" style={{ cursor: 'pointer' }} onClick={() => setOpen(o => !o)}>
        <SeverityTag severity={iss.severity} compact />
        <b style={{ fontSize: 13.5 }}>{iss.title}</b>
        {iss.masvs ? <SoftTag>{iss.masvs}</SoftTag> : null}
        {iss.owasp ? <SoftTag title="OWASP Mobile Top 10">{String(iss.owasp).split(':')[0]}</SoftTag> : null}
        <ChevronRight size={14} className="ws-muted" style={{ marginLeft: 'auto', transform: open ? 'rotate(90deg)' : 'none' }} />
      </div>
      {iss.attack_scenario ? <p style={{ fontSize: 13, marginTop: 8 }}>{iss.attack_scenario}</p> : null}
      {open ? (
        <div style={{ marginTop: 8 }}>
          {(iss.prerequisites || []).length ? (
            <div style={{ marginBottom: 8 }}>
              <div className="ws-block__label">Prerequisites</div>
              <ul style={{ margin: '4px 0 0 18px', fontSize: 13 }}>{iss.prerequisites.map((p, j) => <li key={j}>{p}</li>)}</ul>
            </div>
          ) : null}
          <div className="ws-kv">
            {row('Affected versions', iss.affected_versions)}
            {row('Business impact', iss.business_impact)}
            {row('Technical impact', iss.technical_impact)}
            {row('OWASP', iss.owasp)}
            {row('MASVS', iss.masvs)}
            {row('Remediation', iss.remediation)}
            {row('Developer fix', iss.developer_fix)}
          </div>
        </div>
      ) : null}
    </div>
  )
}

function AssessRow({ ok, good, bad }) {
  return (
    <div className="ws-assess__row">
      {ok ? <ShieldCheck size={15} style={{ color: '#067647' }} /> : <ShieldAlert size={15} style={{ color: SEV_COLOR.high }} />}
      <span style={{ color: ok ? 'var(--ws-ink-2)' : 'var(--sev-high)' }}>{ok ? good : bad}</span>
    </div>
  )
}

// ───────────────────────────── Network ───────────────────────────────────
const NET_GROUPS = [
  { key: 'ssl_bypass', label: 'SSL Bypass', rx: /ssl|trustmanager|hostnameverifier|trust all|x509/i },
  { key: 'webview_ssl', label: 'WebView SSL', rx: /webview.*ssl|onreceivedsslerror|proceed\(/i },
  { key: 'cleartext', label: 'Cleartext Traffic', rx: /cleartext|http:\/\/|usescleartext/i },
  { key: 'pinning', label: 'Missing Pinning', rx: /pinning|certificatepinner|pin-set/i },
]

function urlScheme(u) {
  const m = /^([a-z][a-z0-9+.-]*):\/\//i.exec(String(u))
  return m ? m[1].toLowerCase() : ''
}
function urlHost(u) {
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^/:?#]+)/i.exec(String(u))
  return m ? m[1] : ''
}

export function NetworkPanel({ results }) {
  const nw = results.network_workspace || {}            // Phase 11.75 structure (preferred)
  const nc = results.network_config || {}
  const sum = nc.summary || {}
  const endpoints = nw.endpoints || results.endpoints || []
  const ipsRaw = nw.ips || results.ips || []
  const ips = ipsRaw.map(ip => (ip && typeof ip === 'object') ? ip : { ip })
  const findings = results.findings || []
  const cloudConfig = results.cloud_config || []   // Phase 2.5.5 — Firebase/GCS buckets + endpoints
  const allUrls = [...new Set([...(nw.urls || []), ...(nw.websockets || []), ...endpoints])]
  const domains = nw.domains || []
  const hosts = [...new Set(allUrls.map(urlHost).filter(Boolean))]
  const ta = nw.trust_anchors || {}
  const pinnedDomains = nw.pinned_domains || sum.pinned_domains || []
  const nscPresent = nw.network_security_config ?? nc.present
  const cleartext = nw.cleartext_enabled ?? sum.cleartext_global
  const pinning = nw.pinning_detected ?? sum.has_pinning

  // Group endpoints by scheme.
  const SCHEME_GROUPS = [
    { key: 'http', label: 'HTTP (cleartext)', risky: true, match: s => s === 'http' },
    { key: 'https', label: 'HTTPS', risky: false, match: s => s === 'https' },
    { key: 'ws', label: 'WS (cleartext)', risky: true, match: s => s === 'ws' },
    { key: 'wss', label: 'WSS', risky: false, match: s => s === 'wss' },
  ]
  const grouped = SCHEME_GROUPS.map(g => ({ ...g, items: allUrls.filter(u => g.match(urlScheme(u))) }))
  const other = allUrls.filter(u => !['http', 'https', 'ws', 'wss'].includes(urlScheme(u)))

  const [q, setQ] = useState('')
  const [tab, setTab] = useState('endpoints')
  const [limit, setLimit] = useState(60)
  const [showSuppressedIps, setShowSuppressedIps] = useState(false)
  const ql = q.trim().toLowerCase()

  return (
    <div>
      <div className="ws-section__head"><h1>Network</h1></div>
      <div className="ws-metrics ws-section">
        <Metric label="Network Security Config" value={nscPresent ? 'Present' : 'Default'} />
        <Metric label="Cleartext" value={cleartext ? 'Permitted' : 'Restricted'} />
        <Metric label="Cert Pinning" value={pinning ? 'Detected' : 'None'} />
        <Metric label="Domains" value={domains.length} />
        <Metric label="URLs" value={allUrls.length} />
        <Metric label="Hosts" value={hosts.length} />
        <Metric label="IPs" value={ips.length} />
        <Metric label="Cloud Config" value={cloudConfig.length} />
      </div>

      <div className="ws-two ws-section">
        <div className="ws-card ws-card--pad">
          <h2>Transport Posture</h2>
          <div className="ws-assess">
            <AssessRow ok={!cleartext} good="Cleartext traffic restricted" bad="Cleartext (HTTP) traffic permitted" />
            <AssessRow ok={pinning} good="Certificate pinning detected" bad="No certificate pinning detected" />
            <AssessRow ok={ta.system !== false} good="System CAs trusted (standard)" bad="System CAs not trusted" />
            <AssessRow ok={!ta.user} good="User CAs not trusted" bad="User CAs trusted (MITM risk)" />
            {(ta.custom || []).length ? <div className="ws-mcontrol">Custom anchors: {ta.custom.join(', ')}</div> : null}
          </div>
        </div>
        <div className="ws-card ws-card--pad">
          <h2>Pinned Domains</h2>
          {pinnedDomains.length
            ? pinnedDomains.map((d, i) => <div key={i} className="ws-mono ws-mcontrol"><ShieldCheck size={12} style={{ color: '#067647' }} /> {d}</div>)
            : <p className="ws-muted">No pinned domains declared — connections rely on default trust validation.</p>}
        </div>
      </div>

      {/* Endpoints grouped by scheme */}
      <div className="ws-section">
        <div className="ws-section__head"><h2>Endpoints by Scheme</h2></div>
        <div className="ws-metrics" style={{ marginBottom: 14 }}>
          {grouped.map(g => <Metric key={g.key} label={g.label} value={g.items.length} />)}
        </div>
        <div className="ws-toolbar">
          <input className="ws-input" placeholder="Search URLs, hosts, IPs, domains…" value={q} onChange={e => { setQ(e.target.value); setLimit(60) }} style={{ minWidth: 280 }} />
          <Chips value={tab} onChange={v => { setTab(v); setLimit(60) }} options={[
            { id: 'endpoints', label: 'URLs', count: allUrls.length },
            { id: 'hosts', label: 'Hosts', count: hosts.length },
            { id: 'domains', label: 'Domains', count: domains.length },
            { id: 'ips', label: 'IPs', count: ips.length },
            { id: 'cloud', label: 'Cloud Config', count: cloudConfig.length },
          ]} />
        </div>

        {tab === 'endpoints' ? (() => {
          const rows = allUrls.filter(u => !ql || u.toLowerCase().includes(ql))
          if (!rows.length) return <EmptyState title="No URLs" body={allUrls.length ? 'No URLs match your search.' : 'No URLs or endpoints were extracted from this package.'} />
          return (
            <div className="ws-card" style={{ overflow: 'hidden' }}>
              {rows.slice(0, limit).map((u, i) => {
                const sch = urlScheme(u)
                const cleartextUrl = sch === 'http' || sch === 'ws'
                return (
                  <a key={i} href={u} target="_blank" rel="noopener noreferrer" className="ws-file">
                    <span className={`ws-pill ws-pill--${cleartextUrl ? 'risk' : 'ok'}`}>{sch || '?'}</span>
                    <span className="ws-file__path" title={u}>{u}</span>
                    {cleartextUrl ? <SoftTag title="Cleartext transport">cleartext</SoftTag> : null}
                    <ArrowUpRight size={12} className="ws-muted" />
                  </a>
                )
              })}
              <Pager count={rows.length} limit={limit} setLimit={setLimit} />
            </div>
          )
        })() : null}

        {tab === 'hosts' ? (() => {
          const rows = hosts.filter(h => !ql || h.toLowerCase().includes(ql))
          if (!rows.length) return <EmptyState title="No hosts" body="No hostnames were derived from extracted URLs." />
          return <div className="ws-card" style={{ overflow: 'hidden' }}>{rows.slice(0, limit).map((h, i) => <div key={i} className="ws-file"><Network size={13} className="ws-muted" /><span className="ws-file__path ws-mono" title={h}>{h}</span></div>)}<Pager count={rows.length} limit={limit} setLimit={setLimit} /></div>
        })() : null}

        {tab === 'domains' ? (() => {
          const rows = domains.filter(d => !ql || d.toLowerCase().includes(ql))
          if (!rows.length) return <EmptyState title="No domains" body="No domains were extracted from strings or the network config." />
          return <div className="ws-card" style={{ overflow: 'hidden' }}>{rows.slice(0, limit).map((d, i) => <div key={i} className="ws-file"><span className="ws-file__path ws-mono" title={d}>{d}</span></div>)}<Pager count={rows.length} limit={limit} setLimit={setLimit} /></div>
        })() : null}

        {tab === 'ips' ? (() => {
          const rows = ips.filter(ip => !ql || String(ip.ip || '').toLowerCase().includes(ql))
          if (!rows.length) return <EmptyState title="No IP addresses" body="No literal IP addresses were found in the package." />
          // Noise classes (loopback/link-local/multicast/reserved/broadcast/docs and
          // placeholders) are classified + kept but suppressed-by-default; the rest
          // (public/private + context-promoted) are shown. A toggle reveals the noise.
          const visible = rows.filter(ip => !ip.suppressed)
          const suppressed = rows.filter(ip => ip.suppressed)
          const shown = showSuppressedIps ? rows : (visible.length ? visible : rows)
          const ownerClass = o => /application/i.test(o || '') ? 'ok' : (/framework|sdk|generated/i.test(o || '') ? 'risk' : '')
          const renderIp = (ip, i) => (
            <div key={i} className="ws-file" style={{ flexWrap: 'wrap', alignItems: 'center', gap: 6 }}>
              <span className="ws-mono" style={ip.suppressed ? { opacity: 0.6 } : undefined}>{ip.ip}</span>
              <SoftTag title="Classification">{ip.classification_label || ip.type || 'IP'}</SoftTag>
              {ip.owner ? <span className={`ws-pill ws-pill--${ownerClass(ip.owner) || 'ok'}`} title="Owner (Ownership Engine)">{ip.owner}</span> : null}
              {typeof ip.confidence === 'number' ? <span className="ws-muted" style={{ fontSize: 12 }} title="Proof confidence">{ip.confidence}%</span> : null}
              {ip.file_path ? <span className="ws-muted ws-mono" style={{ fontSize: 12 }} title={ip.file_path}>{String(ip.file_path).split('/').pop()}{ip.line ? `:${ip.line}` : ''}</span> : null}
              {ip.occurrences > 1 ? <span className="ws-muted" style={{ fontSize: 12 }} title="Occurrences">×{ip.occurrences}</span> : null}
              {(ip.intelligence || []).map((t, j) => <SoftTag key={j} title="Intelligence">{t}</SoftTag>)}
              {ip.geo || ip.country ? <span className="ws-muted" style={{ fontSize: 12 }}>{ip.geo || ip.country}</span> : null}
            </div>
          )
          return (
            <div className="ws-card" style={{ overflow: 'hidden' }}>
              {shown.slice(0, limit).map(renderIp)}
              <Pager count={shown.length} limit={limit} setLimit={setLimit} />
              {suppressed.length && !showSuppressedIps ? (
                <button type="button" className="ws-btn ws-btn--sm" style={{ margin: 10 }}
                  onClick={() => setShowSuppressedIps(true)}>
                  Show {suppressed.length} suppressed (loopback / reserved / placeholder noise)
                </button>
              ) : null}
              {showSuppressedIps ? (
                <button type="button" className="ws-btn ws-btn--sm" style={{ margin: 10 }}
                  onClick={() => setShowSuppressedIps(false)}>Hide noise</button>
              ) : null}
            </div>
          )
        })() : null}

        {tab === 'cloud' ? (() => {
          const rows = cloudConfig.filter(c => !ql ||
            `${c.value} ${c.label} ${c.provider} ${c.project_id || ''}`.toLowerCase().includes(ql))
          if (!rows.length) return <EmptyState title="No cloud configuration" body={cloudConfig.length ? 'No cloud config matches your search.' : 'No Firebase / Google Cloud storage buckets or endpoints were found.'} />
          return (
            <div className="ws-card" style={{ overflow: 'hidden' }}>
              {rows.slice(0, limit).map((c, i) => (
                <div key={i} className="ws-file" style={{ flexWrap: 'wrap', alignItems: 'center', gap: 6 }}>
                  <span className={`ws-pill ws-pill--${c.severity === 'low' ? 'risk' : 'ok'}`}>{c.provider}</span>
                  <SoftTag title="Cloud configuration type">{c.label}</SoftTag>
                  <span className="ws-file__path ws-mono" title={c.value}>{c.value}</span>
                  {c.project_id ? <SoftTag title="Project identifier">project: {c.project_id}</SoftTag> : null}
                  {c.owner_type && c.owner_type !== 'Unknown' ? <span className="ws-muted" style={{ fontSize: 12 }} title="Owner">{c.owner_type}</span> : null}
                  {c.file_path ? <span className="ws-muted ws-mono" style={{ fontSize: 12 }} title={c.file_path}>{String(c.file_path).split('/').pop()}{c.line ? `:${c.line}` : ''}</span> : null}
                  {c.occurrences > 1 ? <span className="ws-muted" style={{ fontSize: 12 }} title="Occurrences">×{c.occurrences}</span> : null}
                </div>
              ))}
              <Pager count={rows.length} limit={limit} setLimit={setLimit} />
            </div>
          )
        })() : null}
      </div>

      <div className="ws-section">
        <h2>Network Findings</h2>
        {NET_GROUPS.some(g => findings.some(f => g.rx.test(`${f.title} ${f.category}`))) ? NET_GROUPS.map(g => {
          const hits = findings.filter(f => g.rx.test(`${f.title} ${f.category} ${f.description || ''}`))
          if (!hits.length) return null
          return (
            <div key={g.key} className="ws-card ws-card--pad" style={{ marginBottom: 10 }}>
              <div style={{ fontWeight: 620, marginBottom: 8 }}>{g.label} <span className="ws-muted">· {hits.length}</span></div>
              {hits.slice(0, 8).map((f, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'center', padding: '4px 0' }}>
                  <SeverityTag severity={f.severity} compact /><span style={{ fontSize: 13 }}>{f.title}</span>
                </div>
              ))}
            </div>
          )
        }) : <p className="ws-muted">No network-class findings were raised for this package.</p>}
      </div>
    </div>
  )
}

// ───────────────────────────── Manifest ──────────────────────────────────
export function ManifestPanel({ results }) {
  const info = results.app_info || {}
  const ms = results.manifest_security || {}
  const surface = results.attack_surface || {}
  const perms = (results.permissions || {}).classified || []
  // Android platform defaults for cleartext: targetSdk>=28 → blocked (false),
  // pre-28 → allowed (true). Unknown targetSdk → genuinely unknown.
  const targetSdk = Number(info.target_sdk ?? ms.target_sdk)
  const cleartextDefault = Number.isFinite(targetSdk) ? targetSdk < 28 : null

  const exported = ['activities', 'services', 'receivers', 'providers']
    .map(t => [t, (surface[t] || []).filter(c => c.exported).length])

  const groups = { dangerous: [], signature: [], normal: [] }
  for (const p of perms) {
    const s = p.status === 'dangerous' ? 'dangerous' : p.status === 'signature' ? 'signature' : 'normal'
    groups[s].push(p)
  }

  return (
    <div>
      <div className="ws-section__head"><h1>Manifest</h1></div>
      <div className="ws-metrics ws-section">
        <Metric label="Min SDK" value={info.min_sdk ?? ms.min_sdk ?? '—'} />
        <Metric label="Target SDK" value={info.target_sdk ?? ms.target_sdk ?? '—'} />
        <Metric label="Version" value={info.version_name || info.version || '—'} />
        {exported.map(([t, n]) => <Metric key={t} label={`Exported ${t}`} value={n} />)}
      </div>

      <div className="ws-card ws-card--pad ws-section">
        <h2>App Flags</h2>
        <div className="ws-assess">
          <FlagRow label="debuggable" {...resolveFlag(ms.debuggable ?? info.debuggable, false)} danger />
          <FlagRow label="allowBackup" {...resolveFlag(ms.allow_backup ?? ms.allowBackup, true)} danger />
          <FlagRow label="usesCleartextTraffic" {...resolveFlag(ms.uses_cleartext_traffic ?? ms.usesCleartextTraffic, cleartextDefault)} danger />
          <FlagRow label="networkSecurityConfig" {...resolveFlag((results.network_config || {}).present, false)} danger={false} />
        </div>
        <p className="ws-flag-hint ws-muted">Values marked <em>platform default</em> are inferred from Android behavior when the attribute is absent from the manifest.</p>
      </div>

      <h2>Permissions</h2>
      <div className="ws-two">
        {['dangerous', 'signature', 'normal'].map(tier => (
          <div key={tier} className="ws-card ws-card--pad" style={{ marginBottom: 12 }}>
            <div style={{ fontWeight: 620, textTransform: 'capitalize', marginBottom: 8 }}>{tier} <span className="ws-muted">· {groups[tier].length}</span></div>
            <div className="ws-scroll">
              {groups[tier].map((p, i) => <div key={i} className="ws-mcontrol" title={p.permission}>{p.short_name || (p.permission || '').split('.').pop()}</div>)}
              {!groups[tier].length ? <p className="ws-muted" style={{ fontSize: 12.5 }}>None</p> : null}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// Manifest flags arrive in several shapes: a bool, a string ('true'/'false'/
// 'missing'), or an object {value|state: 'true'|'false'|'missing'}. Coerce to a
// tri-state: true / false / undefined (genuinely unknown or "missing").
function flagValue(v) {
  if (v === undefined || v === null) return undefined
  if (typeof v === 'boolean') return v
  const s = String(typeof v === 'object' ? (v.state ?? v.value ?? '') : v).toLowerCase()
  if (s === 'true') return true
  if (s === 'false') return false
  return undefined
}

// Resolve a manifest flag against an Android platform default.
// Returns { value: bool|null, defaulted } — value is null only when truly unknown.
function resolveFlag(declared, fallback) {
  const v = flagValue(declared)
  if (v === undefined) {
    return { value: fallback === null || fallback === undefined ? null : !!fallback, defaulted: fallback !== null && fallback !== undefined }
  }
  return { value: v, defaulted: false }
}

function FlagRow({ label, value, defaulted, danger }) {
  const unknown = value === null || value === undefined
  const on = value === true
  const bad = danger && on
  return (
    <div className="ws-assess__row">
      {unknown ? <Minus size={15} className="ws-muted" />
        : bad ? <ShieldAlert size={15} style={{ color: SEV_COLOR.high }} />
          : <ShieldCheck size={15} style={{ color: '#067647' }} />}
      <span style={{ color: bad ? 'var(--sev-high)' : 'var(--ws-ink-2)' }}>{label}</span>
      {unknown
        ? <span className="ws-flag ws-flag--unknown">--</span>
        : <span className={`ws-flag ws-flag--${on ? 'true' : 'false'}${bad ? ' ws-flag--bad' : ''}`}>{on ? 'TRUE' : 'FALSE'}</span>}
      {defaulted && !unknown ? <span className="ws-flag-note">platform default</span> : null}
    </div>
  )
}

// ───────────────────────────── Components ────────────────────────────────
const COMP_TYPES = [
  { id: 'activities', label: 'Activities' }, { id: 'services', label: 'Services' },
  { id: 'receivers', label: 'Receivers' }, { id: 'providers', label: 'Providers' },
]
function compActions(c) { return c.actions || c.intent_actions || c.intent_filters || [] }
function compDeeplinks(c) {
  return (c.deeplinks || []).map(d => typeof d === 'string' ? d : `${d.scheme || ''}://${d.host || ''}${d.path || ''}`)
}
function compRisk(c, riskByName) {
  if (riskByName[c.name]) return riskByName[c.name]
  const unprotected = c.exported && !c.permission && (c.permission_protection || 'none') === 'none'
  if (c.exported && (c.deeplinks || []).length) return 'critical'
  if (c.exported && c.browsable) return 'high'
  if (unprotected) return 'high'
  if (c.exported) return 'medium'
  return 'low'
}

// ── Known CVEs in bundled libraries (CVE-MAP / OSV.dev) ───────────────────
// Reuses the data the backend already computes (results.components +
// source==='CVE-MAP' findings + results.cve_stats). No new API calls.
function cveLink(id) {
  if (!id) return null
  return id.startsWith('CVE-')
    ? `https://nvd.nist.gov/vuln/detail/${id}`
    : `https://osv.dev/vulnerability/${id}`
}

function KnownCvesBlock({ results }) {
  const cveFindings = (results.findings || []).filter(f => f.source === 'CVE-MAP')
  const inventory = results.components || []
  const stats = results.cve_stats || {}

  // Nothing detected and nothing scanned → don't clutter the page.
  if (!cveFindings.length && !inventory.length) return null

  // Group CVE findings by their bundled component.
  const byComp = {}
  for (const f of cveFindings) {
    const c = f.component || {}
    const key = c.product ? `${c.product}@${c.version}` : (f.snippet || f.title || 'unknown')
    ;(byComp[key] ||= []).push(f)
  }

  const vulnRows = Object.entries(byComp).map(([key, cves]) => {
    const c = cves[0].component || {}
    const maxSev = cves.reduce((acc, f) => Math.min(acc, RISK_RANK[normSev(f.severity)] ?? 4), 4)
    return {
      key,
      product: c.product || key,
      version: c.version || '',
      ecosystem: c.ecosystem || '',
      binary: c.binary || '',
      cves: [...cves].sort((a, b) => (RISK_RANK[normSev(a.severity)] ?? 4) - (RISK_RANK[normSev(b.severity)] ?? 4)),
      maxSev,
    }
  }).sort((a, b) => a.maxSev - b.maxSev || b.cves.length - a.cves.length)

  const totalCves = cveFindings.length
  const kevCount = cveFindings.filter(f => f.kev).length
  const safeCount = Math.max(0, inventory.length - vulnRows.length)

  return (
    <div style={{ marginTop: 28 }}>
      <div className="ws-section__head">
        <h1>Known CVEs</h1>
        <span className="ws-muted">
          {inventory.length} bundled librar{inventory.length === 1 ? 'y' : 'ies'} · {totalCves} CVE{totalCves !== 1 ? 's' : ''}
          {kevCount ? ` · ${kevCount} KEV` : ''}
        </span>
      </div>

      {vulnRows.length ? vulnRows.map(row => (
        <div key={row.key} className="ws-card ws-card--pad" style={{ marginBottom: 8 }}>
          <div className="ws-permhead">
            <SeverityTag severity={['critical', 'high', 'medium', 'low', 'info'][row.maxSev] || 'info'} compact />
            <span className="ws-mono" style={{ fontWeight: 560 }}>{row.product}{row.version ? ` ${row.version}` : ''}</span>
            {row.ecosystem ? <SoftTag>{row.ecosystem}</SoftTag> : null}
            {row.binary ? <span className="ws-muted ws-mono" style={{ fontSize: 12 }}>{row.binary}</span> : null}
            <span className="ws-pill ws-pill--risk" style={{ marginLeft: 'auto', textTransform: 'none' }}>{row.cves.length} CVE{row.cves.length !== 1 ? 's' : ''}</span>
          </div>
          <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 8 }}>
            {row.cves.map((f, i) => {
              const id = f.cve || f.rule_id
              const href = cveLink(f.cve)
              return (
                <div key={i} style={{ borderTop: i ? '1px solid var(--ws-line)' : 'none', paddingTop: i ? 8 : 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    <SeverityTag severity={f.severity} compact />
                    <code className="ws-mono" style={{ fontWeight: 600 }}>{id}</code>
                    {f.kev ? <span className="ws-pill ws-pill--risk" style={{ textTransform: 'none' }} title="CISA Known Exploited Vulnerability — actively exploited in the wild">KEV</span> : null}
                    {f.cvss != null ? <SoftTag>CVSS {f.cvss}</SoftTag> : null}
                    {f.fix_version ? <SoftTag>Fixed in {f.fix_version}</SoftTag> : null}
                    {href ? <a style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--ws-focus)', textDecoration: 'none', fontWeight: 600 }} href={href} target="_blank" rel="noopener noreferrer">View on {f.cve && f.cve.startsWith('CVE-') ? 'NVD' : 'OSV'} ↗</a> : null}
                  </div>
                  {f.description ? <div className="ws-muted" style={{ fontSize: 12.5, marginTop: 4, whiteSpace: 'pre-wrap' }}>{f.description}</div> : null}
                </div>
              )
            })}
          </div>
        </div>
      )) : (
        <EmptyState title="No known CVEs" body={inventory.length ? 'Bundled libraries were scanned against OSV.dev — none matched a known vulnerability.' : 'No bundled native libraries or packages were detected to scan.'} />
      )}

      <div className="ws-muted" style={{ fontSize: 12, marginTop: 10 }}>
        {stats.binaries_scanned != null ? `${stats.binaries_scanned} binaries scanned · ` : ''}
        {inventory.length} versioned component{inventory.length !== 1 ? 's' : ''}
        {safeCount ? ` · ${safeCount} with no known CVEs` : ''} · data from OSV.dev (cached 24h).
      </div>
    </div>
  )
}

export function ComponentsPanel({ results }) {
  const surface = results.attack_surface || {}
  const inv = results.exported_component_inventory || {}
  const riskByName = {}
  ;(inv.components || []).forEach(c => { if (c.name) riskByName[c.name] = c.risk })
  const [type, setType] = useState('activities')
  const [q, setQ] = useState('')
  const [sort, setSort] = useState('risk')
  const [filter, setFilter] = useState('all')   // all | exported | unprotected
  const [limit, setLimit] = useState(50)

  const ql = q.trim().toLowerCase()
  let items = (surface[type] || []).map(c => ({ ...c, _risk: compRisk(c, riskByName) }))
  if (filter === 'exported') items = items.filter(c => c.exported)
  if (filter === 'unprotected') items = items.filter(c => c.exported && !c.permission && (c.permission_protection || 'none') === 'none')
  items = items.filter(c => !ql || `${c.name} ${compActions(c).join(' ')} ${(c.authorities || '')}`.toLowerCase().includes(ql))
  items = [...items].sort((a, b) => sort === 'name'
    ? (a.name || '').localeCompare(b.name || '')
    : (RISK_RANK[a._risk] ?? 4) - (RISK_RANK[b._risk] ?? 4))

  return (
    <div>
      <div className="ws-section__head"><h1>Application Components</h1><span className="ws-muted">{inv.exported_total ?? '—'} exported of {inv.total ?? '—'}</span></div>
      <div className="ws-toolbar">
        <Chips value={type} onChange={t => { setType(t); setLimit(50) }} options={COMP_TYPES.map(t => ({ ...t, count: (surface[t.id] || []).length }))} />
      </div>
      <div className="ws-toolbar">
        <input className="ws-input" placeholder="Filter by name, action, authority…" value={q} onChange={e => { setQ(e.target.value); setLimit(50) }} />
        <Chips value={filter} onChange={v => { setFilter(v); setLimit(50) }} options={[
          { id: 'all', label: 'All' }, { id: 'exported', label: 'Exported' }, { id: 'unprotected', label: 'Unprotected' },
        ]} />
        <span className="ws-muted" style={{ marginLeft: 'auto', fontSize: 12 }}>Sort</span>
        <Chips value={sort} onChange={setSort} options={[{ id: 'risk', label: 'Risk' }, { id: 'name', label: 'Name' }]} />
      </div>

      {items.length ? (
        <>
          {items.slice(0, limit).map((c, i) => {
            const actions = compActions(c)
            const deeplinks = compDeeplinks(c)
            const unprotected = c.exported && !c.permission && (c.permission_protection || 'none') === 'none'
            return (
              <div key={i} className="ws-card ws-card--pad" style={{ marginBottom: 8 }}>
                <div className="ws-permhead">
                  <SeverityTag severity={c._risk} compact />
                  <span className="ws-mono" style={{ fontWeight: 560, flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis' }} title={c.name}>{c.short_name || c.name}</span>
                  {c.exported ? <span className="ws-pill ws-pill--risk">exported</span> : <span className="ws-pill ws-pill--ok">private</span>}
                  {c.browsable ? <span className="ws-pill ws-pill--warn">browsable</span> : null}
                  {deeplinks.length ? <span className="ws-pill ws-pill--warn">deep link</span> : null}
                  {unprotected ? <span className="ws-pill ws-pill--risk">unprotected</span> : null}
                  {c.permission ? <SoftTag title={c.permission}>permission-protected</SoftTag> : null}
                </div>
                {actions.length ? <div className="ws-muted" style={{ fontSize: 12, marginTop: 7 }}><b>Intent filters:</b> {actions.slice(0, 6).join(', ')}{actions.length > 6 ? ` +${actions.length - 6}` : ''}</div> : null}
                {deeplinks.length ? <div className="ws-muted ws-mono" style={{ fontSize: 12, marginTop: 4 }}>{deeplinks.slice(0, 4).join('  ·  ')}</div> : null}
                {c.authorities ? <div className="ws-muted" style={{ fontSize: 12, marginTop: 4 }}><b>Authorities:</b> {Array.isArray(c.authorities) ? c.authorities.join(', ') : c.authorities}</div> : null}
                {(c.read_permission || c.write_permission) ? <div className="ws-muted" style={{ fontSize: 12, marginTop: 4 }}>R/W perms: {c.read_permission || '—'} / {c.write_permission || '—'}</div> : null}
              </div>
            )
          })}
          <Pager count={items.length} limit={limit} setLimit={setLimit} />
        </>
      ) : <EmptyState title={`No ${type} match`} body={(surface[type] || []).length ? 'No components match the current search/filter.' : `This package declares no ${type}.`} />}

      <KnownCvesBlock results={results} />
    </div>
  )
}

// ───────────────────────────── Android APIs ──────────────────────────────
export function AndroidApiPanel({ results, onOpenCode }) {
  const api = results.android_api || {}
  const evidence = results.android_api_evidence || {}
  const entries = Object.entries(api).map(([cat, files]) => ({ cat, files: files || [], risk: apiRisk(cat) }))
  const [q, setQ] = useState('')
  const [riskFilter, setRiskFilter] = useState('all')
  const [open, setOpen] = useState({})

  if (!entries.length) return <EmptyState title="No Android API usage classified" body="The analyzer did not categorize any platform API usage for this package (no decompiled sources matched the API signature set)." />

  // Evidence carries exact path+line+snippet per category for precise View Code.
  const evMap = {}
  for (const [cat, list] of Object.entries(evidence)) {
    const m = {}
    for (const e of (list || [])) if (e && e.path && m[e.path] === undefined) m[e.path] = e
    evMap[cat] = m
  }

  const riskCounts = entries.reduce((m, e) => { m[e.risk] = (m[e.risk] || 0) + 1; return m }, {})
  const ql = q.trim().toLowerCase()
  let rows = entries.filter(e => riskFilter === 'all' || e.risk === riskFilter)
  rows = rows.filter(e => !ql || e.cat.toLowerCase().includes(ql) || e.files.some(f => String(f).toLowerCase().includes(ql)))
  rows = [...rows].sort((a, b) => (RISK_RANK[a.risk] ?? 4) - (RISK_RANK[b.risk] ?? 4) || b.files.length - a.files.length)

  return (
    <div>
      <div className="ws-section__head"><h1>Android APIs</h1><span className="ws-muted">{entries.length} categories</span></div>
      <div className="ws-metrics ws-section">
        <Metric label="Categories" value={entries.length} />
        <Metric label="High risk" value={riskCounts.high || 0} />
        <Metric label="Medium risk" value={riskCounts.medium || 0} />
        <Metric label="Total references" value={entries.reduce((s, e) => s + e.files.length, 0)} />
      </div>
      <div className="ws-toolbar">
        <input className="ws-input" placeholder="Search categories or files…" value={q} onChange={e => setQ(e.target.value)} style={{ minWidth: 260 }} />
        <Chips value={riskFilter} onChange={setRiskFilter} options={[
          { id: 'all', label: 'All' },
          { id: 'high', label: 'High', count: riskCounts.high || 0 },
          { id: 'medium', label: 'Medium', count: riskCounts.medium || 0 },
          { id: 'low', label: 'Low', count: riskCounts.low || 0 },
        ]} />
      </div>

      {rows.length ? rows.map(({ cat, files, risk }) => {
        const isOpen = open[cat]
        const shown = isOpen ? files : files.slice(0, 6)
        return (
          <div key={cat} className="ws-card ws-card--pad" style={{ marginBottom: 10 }}>
            <div className="ws-permhead">
              <SeverityTag severity={risk} compact />
              <b style={{ fontSize: 14 }}>{cat}</b>
              <span className="ws-muted" style={{ fontSize: 12.5 }}>{files.length} reference{files.length !== 1 ? 's' : ''}</span>
            </div>
            <div className="ws-scroll" style={{ marginTop: 8 }}>
              {shown.map((file, i) => {
                const ev = (evMap[cat] || {})[file]
                return (
                  <div key={i} className="ws-file" onClick={() => onOpenCode(file, ev && ev.line ? [ev.line] : [], ev ? { snippet: ev.snippet, source: 'android api', highlightLine: ev.line, approximate: !ev.line } : {})}>
                    <FileCode2 size={13} className="ws-muted" />
                    <span className="ws-file__path" title={file}>{file}{ev && ev.line ? `:${ev.line}` : ''}</span>
                    <ChevronRight size={13} className="ws-muted" />
                  </div>
                )
              })}
            </div>
            {files.length > 6 ? (
              <button type="button" className="ws-btn ws-btn--sm" style={{ marginTop: 8 }} onClick={() => setOpen(o => ({ ...o, [cat]: !o[cat] }))}>
                {isOpen ? 'Show fewer' : `Show all ${files.length}`}
              </button>
            ) : null}
          </div>
        )
      }) : <EmptyState title="No matching API categories" body="No categories match the current search/filter." />}
    </div>
  )
}

// ───────────────────────────── Malware / RE ──────────────────────────────
export function MalwarePanel({ results }) {
  const apkid = results.apkid || {}
  const behavior = results.behavior_analysis || []
  const findings = results.findings || []
  const native = results.binaries || results.native_libs || []
  const trackers = results.trackers || []
  const vt = results.virustotal || {}
  const mp = (results.malware_perms || {}).malware_permissions || {}
  const suspiciousPerms = mp.matched || []
  const sdks = results.sdks || []
  const hasCtl = rx => findings.some(f => rx.test(`${f.title} ${f.category}`))
  const blob = JSON.stringify(apkid).toLowerCase()
  const [tq, setTq] = useState('')
  const [sq, setSq] = useState('')

  const indicators = [
    ['Obfuscation', /obfuscat|proguard|r8|dexguard/.test(blob) || hasCtl(/obfuscat/i)],
    ['R8 / ProGuard', /proguard|r8/.test(blob)],
    ['Reflection', hasCtl(/reflection/i) || /reflect/.test(blob)],
    ['Dynamic Loading', hasCtl(/dynamic.*load|dexclassloader/i) || /dynamic/.test(blob)],
    ['Native Libraries', (native || []).length > 0],
    ['Root Detection', hasCtl(/root detection|rootbeer/i)],
    ['Emulator Detection', hasCtl(/emulator|qemu|genymotion/i) || /emulator/.test(blob)],
    ['Integrity / Attestation', hasCtl(/integrity|safetynet|play integrity|signature verif/i)],
    ['Anti-Debug / Anti-Analysis', /anti.?debug|anti.?vm|frida|xposed/.test(blob)],
  ]
  const obfCount = indicators.filter(([, p]) => p).length

  // Trackers grouped by category.
  const trackerRows = trackers.filter(t => !tq || `${t.name} ${t.category} ${t.pkg}`.toLowerCase().includes(tq.toLowerCase()))
  const trackerCats = {}
  trackers.forEach(t => { const c = t.category || 'Other'; trackerCats[c] = (trackerCats[c] || 0) + 1 })

  const avDetections = vt.available ? (vt.main?.malicious ?? vt.malicious ?? 0) : null

  // SDKs (searchable).
  const sdkRows = sdks.filter(s => !sq || `${s.name} ${s.category} ${s.package}`.toLowerCase().includes(sq.toLowerCase()))

  return (
    <div>
      <div className="ws-section__head"><h1>Malware Analysis</h1></div>

      {/* Risk summary */}
      <div className="ws-metrics ws-section">
        <Metric label="Trackers" value={trackers.length} />
        <Metric label="SDKs" value={sdks.length} />
        <Metric label="Suspicious Perms" value={`${suspiciousPerms.length}${mp.total ? ` / ${mp.total}` : ''}`} />
        <Metric label="Obfuscation Signals" value={obfCount} />
        <Metric label="AV Detections" value={avDetections === null ? 'N/A' : avDetections} />
      </div>

      {/* Trackers */}
      <div className="ws-section">
        <div className="ws-section__head"><h2>Third-Party Trackers</h2><span className="ws-muted">{trackers.length}</span></div>
        {trackers.length ? (
          <>
            <div className="ws-toolbar"><input className="ws-input" placeholder="Search trackers…" value={tq} onChange={e => setTq(e.target.value)} style={{ minWidth: 240 }} />
              {Object.entries(trackerCats).map(([c, n]) => <SoftTag key={c}>{c} · {n}</SoftTag>)}</div>
            <div className="ws-card" style={{ overflow: 'hidden' }}>
              {trackerRows.map((t, i) => (
                <div key={i} className="ws-file">
                  <Bug size={13} style={{ color: SEV_COLOR.medium }} />
                  <span style={{ fontWeight: 560, fontSize: 13 }}>{t.name}</span>
                  {t.category ? <SoftTag>{t.category}</SoftTag> : null}
                  <span className="ws-file__path ws-mono ws-muted" title={t.pkg}>{t.pkg}</span>
                </div>
              ))}
              {!trackerRows.length ? <p className="ws-muted" style={{ padding: 14 }}>No trackers match your search.</p> : null}
            </div>
          </>
        ) : <EmptyState title="No trackers detected" body="No known third-party tracking/analytics SDK signatures matched this package." />}
      </div>

      {/* SDKs */}
      <div className="ws-section">
        <div className="ws-section__head"><h2>Bundled SDKs</h2><span className="ws-muted">{sdks.length}</span></div>
        {sdks.length ? (
          <>
            <div className="ws-toolbar"><input className="ws-input" placeholder="Search SDKs…" value={sq} onChange={e => setSq(e.target.value)} style={{ minWidth: 240 }} /></div>
            <div className="ws-card" style={{ overflow: 'hidden' }}>
              {sdkRows.map((s, i) => (
                <div key={i} className="ws-file">
                  <Boxes size={13} className="ws-muted" />
                  <span style={{ fontWeight: 560, fontSize: 13 }}>{s.name}</span>
                  {s.category ? <SoftTag>{s.category}</SoftTag> : null}
                  {s.severity && s.severity !== 'info' ? <SeverityTag severity={s.severity} compact /> : null}
                  <span className="ws-file__path ws-mono ws-muted" title={s.package}>{s.package}</span>
                </div>
              ))}
              {!sdkRows.length ? <p className="ws-muted" style={{ padding: 14 }}>No SDKs match your search.</p> : null}
            </div>
          </>
        ) : <EmptyState title="No SDKs identified" body="No known third-party SDK package signatures were detected in this app's code." />}
      </div>

      {/* AV detections */}
      <div className="ws-section">
        <h2>AV Detections (VirusTotal)</h2>
        <div className="ws-card ws-card--pad">
          {vt.available
            ? <div className="ws-assess"><AssessRow ok={!avDetections} good="No AV engines flagged this hash" bad={`${avDetections} AV engine(s) flagged this hash`} /></div>
            : <p className="ws-muted">{vt.error || 'VirusTotal lookups are not configured (set VIRUSTOTAL_API_KEY to enable hash reputation).'}</p>}
        </div>
      </div>

      {/* Suspicious permissions */}
      <div className="ws-section">
        <div className="ws-section__head"><h2>Suspicious Permissions</h2><span className="ws-muted">{suspiciousPerms.length}</span></div>
        {suspiciousPerms.length ? (
          <div className="ws-card ws-card--pad">
            {suspiciousPerms.map((p, i) => <div key={i} className="ws-mcontrol"><ShieldAlert size={12} style={{ color: SEV_COLOR.medium }} /> <span className="ws-mono" style={{ fontSize: 12.5 }}>{p}</span></div>)}
            <p className="ws-muted" style={{ fontSize: 12, marginTop: 8 }}>Permissions frequently abused by malware ({suspiciousPerms.length} of {mp.total || '?'} known). Presence is not malicious on its own.</p>
          </div>
        ) : <EmptyState title="No high-risk permissions" body="None of this app's permissions appear on the malware-abuse watchlist." />}
      </div>

      {/* Obfuscation indicators */}
      <div className="ws-section">
        <h2>Obfuscation &amp; Evasion Indicators</h2>
        <div className="ws-masvs-grid">
          {indicators.map(([label, present]) => (
            <div key={label} className="ws-mcard" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              {present ? <Bug size={16} style={{ color: SEV_COLOR.medium }} /> : <ShieldCheck size={16} className="ws-muted" />}
              <div><div style={{ fontWeight: 600, fontSize: 13 }}>{label}</div><div className="ws-muted" style={{ fontSize: 12 }}>{present ? 'Detected' : 'Not detected'}</div></div>
            </div>
          ))}
        </div>
      </div>

      {Object.keys(apkid).length ? (
        <div className="ws-section">
          <h2>APKiD / YARA Fingerprints</h2>
          {Object.entries(apkid).map(([dex, cats]) => (
            <div key={dex} className="ws-card ws-card--pad" style={{ marginBottom: 8 }}>
              <div className="ws-mono" style={{ fontWeight: 560, marginBottom: 6 }}>{dex}</div>
              {Object.entries(cats || {}).map(([cat, vals]) => (
                <div key={cat} style={{ display: 'flex', gap: 8, padding: '3px 0', flexWrap: 'wrap' }}>
                  <span className="ws-muted" style={{ fontSize: 12.5, minWidth: 110 }}>{cat}</span>
                  {(vals || []).map(v => <SoftTag key={v}>{v}</SoftTag>)}
                </div>
              ))}
            </div>
          ))}
        </div>
      ) : null}

      {behavior.length ? (
        <div className="ws-section">
          <h2>Behavior Analysis</h2>
          {behavior.slice(0, 30).map((b, i) => (
            <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'center', padding: '6px 0', borderTop: i ? '1px solid var(--ws-line)' : 'none' }}>
              <SeverityTag severity={b.severity || 'info'} compact /><span style={{ fontSize: 13 }}>{b.title}</span>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  )
}

// ───────────────────────────── Compare ───────────────────────────────────
export function ComparePanel({ results }) {
  const history = useMemo(() => loadLocalHistory().filter(h => h.scan_id && h.scan_id !== results.scan_id), [results.scan_id])
  const [otherId, setOtherId] = useState(history[0]?.scan_id || '')
  const other = useMemo(() => otherId ? getStoredScan(otherId) : null, [otherId])

  if (!history.length) return <EmptyState title="No other scans to compare" body="Scan another app (viewed in this browser) to enable side-by-side comparison." />

  const metric = (r) => {
    if (!r) return {}
    const sev = r.severity_summary || {}
    return {
      score: r.score?.score ?? '—', trust: r.trust_score?.score ?? '—',
      masvs: r.masvs_summary?.overall_score ?? '—',
      findings: (r.findings || []).length,
      crit: sev.critical ?? 0, high: sev.high ?? 0,
      secrets: r.secrets_summary?.total_application_secrets ?? (r.secrets || []).length,
      components: ['activities', 'services', 'receivers', 'providers'].reduce((s, t) => s + ((r.attack_surface || {})[t] || []).length, 0),
      perms: (r.permissions?.classified || r.permissions?.all || []).length,
      chains: (r.cloud_attack_paths || []).length,
    }
  }
  const A = metric(results), B = metric(other)
  const ROWS = [['Security Score', 'score'], ['Trust Score', 'trust'], ['MASVS Coverage', 'masvs'], ['Findings', 'findings'], ['Critical', 'crit'], ['High', 'high'], ['Secrets', 'secrets'], ['Components', 'components'], ['Permissions', 'perms'], ['Attack Chains', 'chains']]

  return (
    <div>
      <div className="ws-section__head"><h1>Scan Compare</h1></div>
      <div className="ws-toolbar">
        <span className="ws-muted">Compare against:</span>
        <select className="ws-input" value={otherId} onChange={e => setOtherId(e.target.value)}>
          {history.map(h => <option key={h.scan_id} value={h.scan_id}>{h.app_name} · {(h.scan_id || '').slice(0, 8)}</option>)}
        </select>
      </div>
      {!other ? <EmptyState title="Snapshot unavailable" body="The selected scan's full results are not cached in this browser." /> : (
        <div className="ws-card" style={{ overflow: 'hidden' }}>
          <div className="ws-cmp ws-cmp--head"><div>Metric</div><div>{results.app_name}</div><div>{other.app_name}</div><div>Δ</div></div>
          {ROWS.map(([label, key]) => {
            const a = Number(A[key]), b = Number(B[key])
            const delta = Number.isFinite(a) && Number.isFinite(b) ? a - b : null
            return (
              <div key={key} className="ws-cmp">
                <div className="ws-muted">{label}</div><div><b>{A[key]}</b></div><div><b>{B[key]}</b></div>
                <div style={{ color: delta > 0 ? 'var(--sev-high)' : delta < 0 ? '#067647' : 'var(--ws-ink-3)' }}>{delta === null ? '—' : delta > 0 ? `+${delta}` : delta}</div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ───────────────────────────── AI Assistant ──────────────────────────────
// Phase 11.986: dispatches through the SAME backend path as the Finding drawer
// and Ask-AI chat (/api/ai/action via runFindingAction). The old runAssist seam
// was hardwired off (liveAiEnabled() === false), so this page always rendered
// offline deterministic templates even when DeepSeek was selected. It now lists
// the backend's real providers and reports the true provider/model/mode.
const ASSISTANT_ACTIONS = [
  { id: 'summary', label: 'Executive Summary', needs: 'results' },
  { id: 'explain', label: 'Explain Finding', needs: 'finding' },
  { id: 'verify', label: 'Verify Finding', needs: 'finding' },
  { id: 'worth_testing', label: 'Worth Testing?', needs: 'finding' },
  { id: 'generate_poc', label: 'Generate PoC', needs: 'finding' },
  { id: 'generate_fix', label: 'Generate Fix', needs: 'finding' },
]
const _ASSIST_META_KEYS = new Set(['provider', 'model', 'mode', 'cached', 'note', 'action', 'usage', 'latency_ms', 'confidence', 'limitations', 'summary', 'reasoning', 'answer'])

function AssistantResultFields({ result }) {
  // Generic, action-agnostic render of the structured envelope result so every
  // backend action shows meaningfully without per-action code.
  return (
    <>
      {Object.entries(result).map(([k, v]) => {
        if (_ASSIST_META_KEYS.has(k) || v == null || v === '' || (Array.isArray(v) && !v.length)) return null
        const label = k.replace(/_/g, ' ')
        if (Array.isArray(v)) {
          return <div key={k} className="ws-block"><div className="ws-block__label" style={{ textTransform: 'capitalize' }}>{label}</div><ul>{v.map((x, i) => <li key={i}>{typeof x === 'string' ? x : JSON.stringify(x)}</li>)}</ul></div>
        }
        if (typeof v === 'object') return null
        return <div key={k} className="ws-block"><div className="ws-block__label" style={{ textTransform: 'capitalize' }}>{label}</div><p style={{ whiteSpace: 'pre-wrap' }}>{String(v)}</p></div>
      })}
    </>
  )
}

export function AiAssistantPanel({ results }) {
  const [providers, setProviders] = useState([])
  const [provider, setProvider] = useState('')
  const [action, setAction] = useState('summary')
  const [targetId, setTargetId] = useState('')
  const [out, setOut] = useState(null)
  const [busy, setBusy] = useState(false)

  const findings = results.findings || []
  const need = (ASSISTANT_ACTIONS.find(a => a.id === action) || {}).needs

  useEffect(() => { fetchAiProviders().then(d => setProviders(d.providers || [])) }, [])

  const run = async () => {
    setBusy(true)
    try {
      const finding = need === 'finding'
        ? (findings.find(f => (f.title || f.id) === targetId) || findings[0])
        : undefined
      const res = await runFindingAction({ action, provider: provider || undefined, finding, results })
      setOut({ ...res, action })
    } finally { setBusy(false) }
  }

  const meta = out || {}
  const providerFailed = out && meta.mode !== 'llm' && !!meta.note
  const r = meta.result || {}
  const headline = r.answer || r.summary || meta.summary || ''

  return (
    <div>
      <div className="ws-section__head"><h1>AI Actions</h1><SoftTag>provider-agnostic</SoftTag></div>
      <div className="ws-card ws-card--pad ws-section">
        <div className="ws-aiform">
          <label>Provider
            <select className="ws-input" value={provider} onChange={e => { setProvider(e.target.value); setOut(null) }} aria-label="AI provider">
              <option value="">Auto / Deterministic</option>
              {providers.map(p => <option key={p.id} value={p.id} disabled={!p.available}>{p.name}{p.available ? '' : ' (unavailable)'}</option>)}
            </select>
          </label>
          <label>Action
            <select className="ws-input" value={action} onChange={e => { setAction(e.target.value); setOut(null) }}>
              {ASSISTANT_ACTIONS.map(a => <option key={a.id} value={a.id}>{a.label}</option>)}
            </select>
          </label>
          {need === 'finding' ? (
            <label>Finding
              <select className="ws-input" value={targetId} onChange={e => setTargetId(e.target.value)}>
                {findings.slice(0, 100).map((f, i) => <option key={i} value={f.title || f.id}>{f.title}</option>)}
              </select>
            </label>
          ) : null}
        </div>
        <button type="button" className="ws-btn ws-btn--primary" style={{ marginTop: 12 }} onClick={run} disabled={busy}>
          <Sparkles size={14} /> {busy ? 'Generating…' : 'Run'}
        </button>
      </div>

      {out ? (
        <div className="ws-card ws-card--pad">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
            <h2 style={{ margin: 0 }}>Result</h2>
            <span className="ws-tag ws-tag--soft"><Sparkles size={11} /> Provider: {meta.provider || 'deterministic'}</span>
            {meta.model ? <span className="ws-tag ws-tag--soft">Model: {meta.model}</span> : null}
            <span className="ws-tag ws-tag--soft">Mode: {meta.mode === 'llm' ? 'llm' : meta.mode === 'error' ? 'error' : 'deterministic'}</span>
            <span className="ws-tag ws-tag--soft">Cached: {meta.cached ? 'yes' : 'no'}</span>
            {meta.confidence ? <span className="ws-tag ws-tag--soft">conf: {meta.confidence}</span> : null}
          </div>
          {providerFailed ? (
            <div className="ws-callout ws-callout--fp" style={{ marginBottom: 10 }}>
              <b>Provider failed — showing deterministic answer.</b><br />{meta.note}
            </div>
          ) : null}
          {headline ? <p style={{ whiteSpace: 'pre-wrap', marginTop: 0 }}>{headline}</p> : null}
          <AssistantResultFields result={r} />
          {meta.reasoning || r.reasoning ? <div className="ws-block"><div className="ws-block__label">Reasoning</div><p style={{ whiteSpace: 'pre-wrap' }}>{meta.reasoning || r.reasoning}</p></div> : null}
          {meta.limitations || r.limitations ? <div className="ws-block"><div className="ws-block__label">Limitations</div><div className="ws-callout ws-callout--fp">{meta.limitations || r.limitations}</div></div> : null}
        </div>
      ) : (
        <p className="ws-muted">Pick a provider and action, then Run. With no LLM provider configured this returns Beetle's deterministic, evidence-only analysis; select DeepSeek/Claude/OpenAI/Gemini (or Ollama) to dispatch to a model.</p>
      )}
    </div>
  )
}

// ───────────────────────────── Code Browser ──────────────────────────────
function flattenFiles(files) {
  // Backend may return a nested tree (dict) or a flat list of paths.
  if (Array.isArray(files)) return files
  const out = []
  const walk = (node, prefix) => {
    if (Array.isArray(node)) { node.forEach(n => out.push(prefix ? `${prefix}/${n}` : n)); return }
    if (node && typeof node === 'object') {
      for (const [k, v] of Object.entries(node)) {
        if (v && typeof v === 'object') walk(v, prefix ? `${prefix}/${k}` : k)
        else out.push(prefix ? `${prefix}/${k}` : k)
      }
    }
  }
  walk(files, '')
  return out
}

export function CodeBrowserPanel({ results, scanId, onOpenCode }) {
  const [files, setFiles] = useState(null)
  const [err, setErr] = useState('')
  const [q, setQ] = useState('')

  useEffect(() => {
    let cancelled = false
    apiFetch(`/api/scans/${scanId}/files`)
      .then(r => r.json())
      .then(d => { if (!cancelled) setFiles(flattenFiles(d.files || [])) })
      .catch(() => { if (!cancelled) setErr('File listing unavailable for this scan.') })
    return () => { cancelled = true }
  }, [scanId])

  // Fallback: derive from evidence paths when the listing endpoint is empty.
  const evidenceFiles = useMemo(() => {
    const s = new Set()
    for (const f of results.findings || []) { const p = f.file_path || f.full_path; if (p) s.add(p) }
    return [...s]
  }, [results])

  const list = (files && files.length ? files : evidenceFiles)
  const filtered = q ? list.filter(p => p.toLowerCase().includes(q.toLowerCase())) : list

  return (
    <div>
      <div className="ws-section__head"><h1>Code Browser</h1><span className="ws-muted">{list.length} files</span></div>
      <div className="ws-toolbar"><input className="ws-input" placeholder="Search files…" value={q} onChange={e => setQ(e.target.value)} style={{ minWidth: 320 }} /></div>
      {err && !list.length ? <EmptyState title="Source unavailable" body={err} /> : null}
      <div className="ws-card" style={{ overflow: 'hidden' }}>
        {filtered.slice(0, 500).map((p, i) => (
          <div key={i} className="ws-file" onClick={() => onOpenCode(p, [])}>
            <FileText size={13} className="ws-muted" />
            <span className="ws-file__path" title={p}>{p}</span>
            <ArrowUpRight size={12} className="ws-muted" />
          </div>
        ))}
        {!filtered.length ? <p className="ws-muted" style={{ padding: 16 }}>No files match.</p> : null}
      </div>
      <p className="ws-muted" style={{ marginTop: 10, fontSize: 12.5 }}>Open a file to search within it, jump between matches (Enter / Shift+Enter), and copy snippets. Evidence links from findings auto-scroll to the exact line.</p>
    </div>
  )
}

// ───────────────────────────── CISO Summary ──────────────────────────────
// Phase 11.95 Task 3 — business-level posture from results.ciso_summary
// (deterministic backend rollup; no fabricated content).
const RISK_RATING_COLOR = { Critical: '#7f1d1d', High: '#dc2626', Medium: '#ea8600', Low: '#3b82f6' }
const PRIORITY_COLOR = { P0: '#7f1d1d', P1: '#dc2626', P2: '#ea8600', P3: '#3b82f6' }

export function CisoSummaryPanel({ results, onOpenSection }) {
  const ciso = results.ciso_summary || {}
  const score = results.score || {}
  if (!ciso.overall_posture) {
    return <EmptyState title="CISO summary unavailable" body="This scan predates executive summary generation. Re-run the scan to populate it." />
  }
  const mat = ciso.security_maturity || {}
  const matLevel = mat.label === 'strong' ? 'strong' : mat.label === 'moderate' ? 'moderate' : 'weak'
  const rrColor = RISK_RATING_COLOR[ciso.risk_rating] || '#6b7280'

  return (
    <div>
      <div className="ws-section__head"><h1>CISO Summary</h1>
        <span className="ws-rating" style={{ background: rrColor, color: '#fff' }}>{ciso.risk_rating} risk</span></div>

      <div className="ws-metrics ws-section">
        <Metric label="Risk Rating" value={ciso.risk_rating || '—'} />
        <Metric label="Security Grade" value={<>{ciso.security_grade ?? score.grade ?? '—'}</>} sub={score.score != null ? `${score.score}/100` : ''} />
        <Metric label="Security Maturity" value={mat.label || '—'} sub={mat.score != null ? `${mat.score}/100 MASVS` : ''} />
        {ciso.trust_score != null ? <Metric label="Report Trust" value={`${ciso.trust_score}/100`} sub="evidence quality" /> : null}
      </div>

      <div className="ws-card ws-card--pad ws-section">
        <h2>Overall Posture</h2>
        <p style={{ fontSize: 14, lineHeight: 1.6 }}>{ciso.overall_posture}</p>
        {ciso.most_critical_issue ? (
          <div className="ws-callout" style={{ marginTop: 12, borderLeft: `3px solid ${rrColor}` }}>
            <b>Most Critical Issue:</b> {ciso.most_critical_issue}
          </div>
        ) : null}
      </div>

      <div className="ws-two ws-section">
        <div className="ws-card ws-card--pad">
          <h2>Business Risks</h2>
          {(ciso.business_risks || []).length ? (
            <div className="ws-list">
              {ciso.business_risks.map((b, i) => (
                <div key={i} className="ws-list__row" style={{ alignItems: 'flex-start', flexDirection: 'column', gap: 3, borderTop: i ? '1px solid var(--ws-line)' : 'none' }}>
                  <b style={{ fontSize: 13.5 }}>{b.risk}</b>
                  <span className="ws-muted" style={{ fontSize: 12.5 }}>{b.detail}</span>
                </div>
              ))}
            </div>
          ) : <p className="ws-muted">No material business risks derived from the findings.</p>}
        </div>
        <div className="ws-card ws-card--pad">
          <h2>Attack Surface Concerns</h2>
          {(ciso.attack_surface_concerns || []).length ? (
            <ul style={{ margin: 0, paddingLeft: 18, fontSize: 13, lineHeight: 1.6 }}>
              {ciso.attack_surface_concerns.map((c, i) => <li key={i}>{c}</li>)}
            </ul>
          ) : <p className="ws-muted">No notable externally reachable exposure detected.</p>}
          {(mat.strongest_controls || []).length ? (
            <div style={{ marginTop: 14 }}>
              <div className="ws-block__label">Strongest Controls</div>
              {mat.strongest_controls.map(c => <div key={c} className="ws-mcontrol"><ShieldCheck size={13} style={{ color: '#067647' }} /> {c}</div>)}
            </div>
          ) : null}
        </div>
      </div>

      <div className="ws-section">
        <div className="ws-section__head"><h2>Prioritized Remediation</h2>
          <button type="button" className="ws-btn ws-btn--sm" onClick={() => onOpenSection('findings')}>All findings <ChevronRight size={14} /></button></div>
        <div className="ws-card ws-card--pad">
          {(ciso.prioritized_remediation || []).length ? (
            <div className="ws-list">
              {ciso.prioritized_remediation.map((r, i) => (
                <div key={i} className="ws-list__row" style={{ alignItems: 'flex-start', borderTop: i ? '1px solid var(--ws-line)' : 'none' }}>
                  <span className="ws-rating" style={{ background: PRIORITY_COLOR[r.priority] || '#6b7280', color: '#fff', flex: 'none' }}>{r.priority}</span>
                  <span className="ws-list__grow">
                    <span className="ws-list__title">{r.item}</span>
                    <span className="ws-list__why">{r.action}</span>
                  </span>
                </div>
              ))}
            </div>
          ) : <p className="ws-muted">No critical or high-severity remediation items identified.</p>}
        </div>
      </div>

      <button type="button" className="ws-btn ws-btn--sm" onClick={() => onOpenSection('masvs')}>View MASVS posture <ChevronRight size={14} /></button>
    </div>
  )
}

// ───────────────────────────── Developer Guide ───────────────────────────
// Phase 11.95 Task 4 — findings grouped by engineering area from
// results.developer_summary, each with what/why/fix/code example.
export function DeveloperGuidePanel({ results, onOpenCode }) {
  const dev = results.developer_summary || {}
  const groups = dev.groups || []
  const [open, setOpen] = useState(() => (groups[0] ? { [groups[0].area]: true } : {}))
  if (!groups.length) {
    return <EmptyState title="No developer-actionable groups" body="No findings mapped to engineering areas in this scan." />
  }

  return (
    <div>
      <div className="ws-section__head"><h1>Developer Report</h1>
        <span className="ws-muted">{dev.covered_findings || 0} findings · {groups.length} areas</span></div>
      <p className="ws-muted" style={{ fontSize: 13, marginBottom: 14 }}>
        Findings grouped by engineering area. Each group explains what was found, why it is dangerous, and how to fix it — ordered by priority.
      </p>

      <div className="ws-toolbar" style={{ flexWrap: 'wrap' }}>
        {groups.map(g => (
          <button key={g.area} type="button" className="ws-chip" onClick={() => { setOpen(o => ({ ...o, [g.area]: true })); document.getElementById(`devg-${g.area}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' }) }}>
            {g.area} <span className="ws-muted">{g.count}</span>
          </button>
        ))}
      </div>

      {groups.map(g => {
        const isOpen = !!open[g.area]
        const sev = normSev(g.max_severity)
        return (
          <div key={g.area} id={`devg-${g.area}`} className="ws-card ws-section" style={{ overflow: 'hidden' }}>
            <button type="button" className="ws-fcard" style={{ width: '100%', background: 'none', border: 'none', textAlign: 'left', cursor: 'pointer', borderRadius: 0 }}
              onClick={() => setOpen(o => ({ ...o, [g.area]: !o[g.area] }))}>
              <span className="ws-fcard__sev" style={{ background: SEV_COLOR[sev] }} />
              <div className="ws-fcard__body">
                <div className="ws-fcard__meta">
                  <SeverityTag severity={sev} />
                  <span className="ws-rating" style={{ background: PRIORITY_COLOR[g.priority] || '#6b7280', color: '#fff' }}>{g.priority}</span>
                  <SoftTag>{g.count} issue{g.count !== 1 ? 's' : ''}</SoftTag>
                  {g.masvs ? <SoftTag>{g.masvs}</SoftTag> : null}
                </div>
                <div className="ws-fcard__title">{g.area} — {g.blurb}</div>
              </div>
              <ChevronRight size={16} className="ws-muted" style={{ transform: isOpen ? 'rotate(90deg)' : 'none', transition: 'transform .15s', alignSelf: 'center', marginRight: 12 }} />
            </button>

            {isOpen ? (
              <div style={{ padding: '4px 16px 16px' }}>
                <div className="ws-block">
                  <div className="ws-block__label">What Was Found</div>
                  <div className="ws-list">
                    {(g.what_found || []).map((w, i) => (
                      <div key={i} className="ws-list__row" style={{ borderTop: i ? '1px solid var(--ws-line)' : 'none' }}>
                        <SeverityTag severity={w.severity} compact />
                        <span className="ws-list__grow"><span className="ws-list__title">{w.title}</span></span>
                        {w.file ? (
                          <button type="button" className="ws-btn ws-btn--sm" onClick={() => onOpenCode && onOpenCode(w.file, w.line ? [w.line] : [])} title={w.file}>
                            <FileCode2 size={12} /> {String(w.file).split('/').pop()}{w.line ? `:${w.line}` : ''}
                          </button>
                        ) : null}
                      </div>
                    ))}
                  </div>
                </div>
                {g.why_dangerous ? <div className="ws-block"><div className="ws-block__label">Why It's Dangerous</div><p>{g.why_dangerous}</p></div> : null}
                {g.fix ? <div className="ws-block"><div className="ws-block__label">Recommended Fix</div><p>{g.fix}</p></div> : null}
                {g.code_example ? <div className="ws-block"><div className="ws-block__label">Secure Code Example</div><pre className="ws-code">{g.code_example}</pre></div> : null}
              </div>
            ) : null}
          </div>
        )
      })}
    </div>
  )
}

// ───────────────────────────── Ask AI (Phase 11.98) ───────────────────────────
// Conversational analysis over the analyzer evidence. The backend builds context
// automatically (no pasting), reasons over evidence only, persists conversations
// per scan, and degrades to a deterministic answer when no provider is set.
// "No provider-specific code in components" — the panel only uses /api/ai/chat
// plus the generic provider list.
const ASKAI_SUGGESTIONS = [
  'Is this remotely exploitable?',
  'Could this become RCE?',
  'Is this worth reporting?',
  'What manual steps should I perform?',
  'Could this be a false positive?',
  'Generate adb commands.',
  'Compare with MASVS.',
  'Explain like a pentester.',
  'Business impact?',
  'Prioritized remediation?',
]

function AiMessage({ m }) {
  const [open, setOpen] = useState(false)
  const meta = m.meta || {}
  if (m.role === 'user') {
    return <div className="ws-chat-msg ws-chat-msg--user"><div className="ws-chat-bubble ws-chat-bubble--user">{m.content}</div></div>
  }
  // A provider was requested but it errored and we fell back to deterministic.
  const providerFailed = meta.mode !== 'llm' && !!meta.note
  return (
    <div className="ws-chat-msg ws-chat-msg--ai">
      <div className="ws-chat-bubble ws-chat-bubble--ai">
        {providerFailed ? (
          <div className="ws-callout ws-callout--fp" style={{ marginBottom: 10 }}>
            <b>Provider failed — showing deterministic answer.</b><br />{meta.note}
          </div>
        ) : null}
        <div className="ws-chat-ans">{m.content}</div>
        <div className="ws-chat-meta">
          <span className="ws-tag ws-tag--soft"><Sparkles size={11} /> Provider: {meta.provider || 'deterministic'}</span>
          {meta.model ? <span className="ws-tag ws-tag--soft">Model: {meta.model}</span> : null}
          <span className="ws-tag ws-tag--soft">{meta.mode === 'llm' ? 'model' : meta.mode === 'error' ? 'error' : 'deterministic'}</span>
          {meta.confidence ? <span className="ws-tag ws-tag--soft">conf: {meta.confidence}</span> : null}
          <span className="ws-tag ws-tag--soft">Cached: {meta.cached ? 'yes' : 'no'}</span>
          {meta.tokens != null ? <span className="ws-tag ws-tag--soft">{meta.token_estimate ? '~' : ''}{meta.tokens} tok</span> : null}
          {meta.generation_ms != null ? <span className="ws-tag ws-tag--soft">{meta.generation_ms}ms</span> : null}
          <button type="button" className="ws-chat-detail-toggle" onClick={() => setOpen(o => !o)}>
            <ChevronDown size={12} style={{ transform: open ? 'rotate(180deg)' : 'none' }} /> details
          </button>
        </div>
        {open ? (
          <div className="ws-chat-detail">
            {meta.reasoning ? <div className="ws-block"><div className="ws-block__label">Reasoning</div><p style={{ whiteSpace: 'pre-wrap' }}>{meta.reasoning}</p></div> : null}
            {(meta.evidence_used || []).length ? (
              <div className="ws-block"><div className="ws-block__label">Evidence used</div>
                <div className="ws-refs">{meta.evidence_used.map((e, i) => <SoftTag key={i}>{e}</SoftTag>)}</div></div>
            ) : null}
            {meta.limitations ? <div className="ws-block"><div className="ws-block__label">Limitations</div><div className="ws-callout ws-callout--fp">{meta.limitations}</div></div> : null}
          </div>
        ) : null}
      </div>
    </div>
  )
}

export function AskAiPanel({ results, scanId }) {
  const findings = results.findings || []
  const [providers, setProviders] = useState([])
  const [provider, setProvider] = useState('')
  const [convos, setConvos] = useState([])
  const [chatId, setChatId] = useState(null)
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [selected, setSelected] = useState(() => new Set())
  const [pickerOpen, setPickerOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const threadRef = useRef(null)

  const loadConvos = useCallback(() => {
    apiFetch(`/api/ai/chats?scan_id=${scanId}`).then(r => (r.ok ? r.json() : { conversations: [] }))
      .then(d => setConvos(d.conversations || [])).catch(() => {})
  }, [scanId])

  useEffect(() => { fetchAiProviders().then(d => setProviders(d.providers || [])) }, [])
  useEffect(() => { loadConvos() }, [loadConvos])
  useEffect(() => { threadRef.current?.scrollTo({ top: 9e9 }) }, [messages])

  const fid = f => f.id || f.canonical_id || `${f.title || f.name || ''}|${f.file_path || ''}|${f.line || ''}`

  const openConvo = async cid => {
    const r = await apiFetch(`/api/ai/chats/${cid}`)
    if (!r.ok) return
    const c = await r.json()
    setChatId(cid); setMessages(c.messages || [])
  }
  const newConvo = () => { setChatId(null); setMessages([]) }

  const renameConvo = async (cid, e) => {
    e.stopPropagation()
    const title = window.prompt('Rename conversation')
    if (!title) return
    await apiFetch(`/api/ai/chats/${cid}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title }) })
    loadConvos()
  }
  const deleteConvo = async (cid, e) => {
    e.stopPropagation()
    if (!window.confirm('Delete this conversation?')) return
    await apiFetch(`/api/ai/chats/${cid}`, { method: 'DELETE' })
    if (cid === chatId) newConvo()
    loadConvos()
  }

  const send = async (text) => {
    const q = (text ?? input).trim()
    if (!q || busy) return
    setBusy(true)
    const finding_ids = [...selected]
    setMessages(m => [...m, { role: 'user', content: q, meta: {} }])
    setInput('')
    try {
      const r = await apiFetch('/api/ai/chat', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: scanId, question: q, chat_id: chatId, finding_ids, provider: provider || undefined }),
      })
      const env = r.ok ? await r.json() : { answer: 'AI request failed.', mode: 'error' }
      if (env.chat_id && env.chat_id !== chatId) { setChatId(env.chat_id); loadConvos() }
      setMessages(m => [...m, {
        role: 'assistant', content: env.answer || '(no answer)',
        meta: {
          reasoning: env.reasoning, confidence: env.confidence, limitations: env.limitations,
          provider: env.provider, model: env.model, mode: env.mode, cached: env.cached,
          evidence_used: env.evidence_used, tokens: env.tokens, token_estimate: env.token_estimate,
          generation_ms: env.generation_ms, note: env.note,
        },
      }])
    } finally { setBusy(false) }
  }

  return (
    <div className="ws-askai">
      <aside className="ws-askai__side">
        <button type="button" className="ws-btn ws-btn--primary ws-askai__new" onClick={newConvo}><Plus size={14} /> New conversation</button>
        <div className="ws-askai__convos">
          {convos.length ? convos.map(c => (
            <div key={c.chat_id} className={`ws-askai__convo${c.chat_id === chatId ? ' is-active' : ''}`} onClick={() => openConvo(c.chat_id)}>
              <MessageSquare size={13} className="ws-muted" />
              <span className="ws-askai__convo-title">{c.title}</span>
              <span className="ws-askai__convo-count">{c.message_count}</span>
              <button type="button" className="ws-askai__convo-act" title="Rename" onClick={e => renameConvo(c.chat_id, e)}><Pencil size={12} /></button>
              <button type="button" className="ws-askai__convo-act" title="Delete" onClick={e => deleteConvo(c.chat_id, e)}><Trash2 size={12} /></button>
            </div>
          )) : <p className="ws-muted" style={{ fontSize: 12.5, padding: '8px 4px' }}>No conversations yet.</p>}
        </div>
      </aside>

      <div className="ws-askai__main">
        <div className="ws-askai__bar">
          <select className="ws-input" value={provider} onChange={e => setProvider(e.target.value)} aria-label="AI provider">
            <option value="">Auto / Deterministic</option>
            {providers.map(p => <option key={p.id} value={p.id} disabled={!p.available}>{p.name}{p.available ? '' : ' (unavailable)'}</option>)}
          </select>
          <button type="button" className={`ws-chip${selected.size ? ' is-active' : ''}`} onClick={() => setPickerOpen(o => !o)}>
            {selected.size ? `${selected.size} finding${selected.size !== 1 ? 's' : ''} selected` : 'Select findings'} <ChevronDown size={12} />
          </button>
        </div>

        {pickerOpen ? (
          <div className="ws-askai__picker">
            {findings.slice(0, 60).map((f, i) => {
              const id = fid(f)
              return (
                <label key={i} className="ws-askai__pick">
                  <input type="checkbox" checked={selected.has(id)} onChange={e => setSelected(s => { const n = new Set(s); if (e.target.checked) n.add(id); else n.delete(id); return n })} />
                  <SeverityTag severity={f.severity} compact />
                  <span className="ws-askai__pick-title">{f.title || f.name}</span>
                </label>
              )
            })}
          </div>
        ) : null}

        <div className="ws-askai__thread" ref={threadRef}>
          {messages.length ? messages.map((m, i) => <AiMessage key={i} m={m} />) : (
            <div className="ws-askai__welcome">
              <Sparkles size={26} className="ws-muted" />
              <h3>Ask the AI Assistant about this scan</h3>
              <p>Questions are answered from the analyzer evidence only — never fabricated. Select findings to reason across them.</p>
              <div className="ws-askai__suggest">
                {ASKAI_SUGGESTIONS.map(s => <button key={s} type="button" className="ws-chip" onClick={() => send(s)}>{s}</button>)}
              </div>
            </div>
          )}
          {busy ? <div className="ws-chat-msg ws-chat-msg--ai"><div className="ws-chat-bubble ws-chat-bubble--ai ws-muted">Thinking…</div></div> : null}
        </div>

        <div className="ws-askai__input">
          <textarea className="ws-input" rows={2} placeholder="Ask anything about this scan… (evidence-grounded)" value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }} />
          <button type="button" className="ws-btn ws-btn--primary" disabled={busy || !input.trim()} onClick={() => send()}><Send size={15} /></button>
        </div>
      </div>
    </div>
  )
}

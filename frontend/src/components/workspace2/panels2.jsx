// Phase 11.75 — deep-analysis workspace pages. Exposes EXISTING backend
// intelligence (certificate, network, manifest, components, android_api, apkid/
// behavior, compare history, AI analyst, source files). Presentation only.
import { useEffect, useMemo, useState } from 'react'
import {
  ShieldCheck, ShieldAlert, Network, FileCode2, Boxes, Cpu, Bug, GitCompare,
  Sparkles, Folder, FileText, Search, ChevronRight, ArrowUpRight, Copy,
} from 'lucide-react'
import { SEV_COLOR, normSev, SeverityTag, SoftTag, EmptyState, Metric } from './ui.jsx'
import { AI_PROVIDERS, AI_ACTIONS, runAssist } from '../../lib/ai-providers.js'
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

// ───────────────────────────── Certificate ───────────────────────────────
export function CertificatePanel({ results }) {
  const c = results.certificate || {}
  if (!c.available && !(c.scheme || []).length) {
    return <EmptyState title="No certificate data" body={c.unavailable_reason || 'Signing certificate could not be extracted for this package.'} />
  }
  const schemes = c.scheme || c.schemes || []
  const has = v => schemes.some(s => String(s).toLowerCase().includes(v))
  const weakAlgo = /sha1|md5/i.test(c.signature_algo || '')
  const smallKey = c.key_size && Number(c.key_size) < 2048
  const janusRisk = c.janus_risk !== undefined ? c.janus_risk : (has('v1') && !has('v2') && !has('v3'))
  const overallVuln = (c.security_overview?.overall || '').toLowerCase() === 'vulnerable'

  let level = 'good'
  if (c.debug_cert || overallVuln || janusRisk) level = 'risk'
  else if (c.expired || weakAlgo || smallKey) level = 'warn'

  const subj = Object.entries(c.subject || {}).map(([k, v]) => `${k}=${v}`).join(', ')
  const iss = Object.entries(c.issuer || {}).map(([k, v]) => `${k}=${v}`).join(', ')

  return (
    <div>
      <div className="ws-section__head"><h1>Certificate</h1><Verdict level={level} /></div>

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
            ['Subject', subj], ['Issuer', iss], ['Serial', c.serial],
            ['Algorithm', c.signature_algo], ['Key', c.key_type ? `${c.key_type} ${c.key_size}-bit` : c.key_size],
            ['Valid from', c.valid_from], ['Valid to', c.valid_to],
          ]} />
        </div>
        <div className="ws-card ws-card--pad">
          <h2>Fingerprints</h2>
          <Rows items={[
            ['SHA-1', c.sha1_fingerprint || c.sha1], ['SHA-256', c.sha256_fingerprint || c.sha256], ['SHA-512', c.sha512_fingerprint || c.sha512],
          ]} />
        </div>
      </div>

      <div className="ws-card ws-card--pad">
        <h2>Production Readiness</h2>
        <div className="ws-assess">
          <AssessRow ok={!c.debug_cert} good="Production certificate" bad="Debug certificate detected" />
          <AssessRow ok={!c.expired} good="Within validity period" bad="Certificate expired" />
          <AssessRow ok={!janusRisk} good="Janus-resistant (v2+/v3 signed)" bad="Janus risk — v1-only signing" />
          <AssessRow ok={!weakAlgo} good="Strong signature algorithm" bad={`Weak signature algorithm (${c.signature_algo})`} />
          <AssessRow ok={!smallKey} good="Adequate key size" bad={`Small key size (${c.key_size}-bit)`} />
        </div>
      </div>
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

export function NetworkPanel({ results }) {
  const nc = results.network_config || {}
  const sum = nc.summary || {}
  const endpoints = results.endpoints || []
  const ips = results.ips || []
  const findings = results.findings || []
  const ws = endpoints.filter(u => /^wss?:\/\//i.test(u))
  const urls = endpoints.filter(u => !/^wss?:\/\//i.test(u))

  return (
    <div>
      <div className="ws-section__head"><h1>Network</h1></div>
      <div className="ws-metrics ws-section">
        <Metric label="Network Security Config" value={nc.present ? 'Present' : 'Default'} />
        <Metric label="Cleartext" value={sum.cleartext_global ? 'Permitted' : 'Restricted'} />
        <Metric label="Cert Pinning" value={sum.has_pinning ? `${sum.pinned_domain_count || 0} domain(s)` : 'None'} />
        <Metric label="User CAs" value={sum.user_ca_trusted ? 'Trusted' : 'Not trusted'} />
        <Metric label="Endpoints" value={urls.length} />
        <Metric label="WebSockets" value={ws.length} />
      </div>

      <div className="ws-section">
        <h2>Network Findings</h2>
        {NET_GROUPS.map(g => {
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
        })}
        {!NET_GROUPS.some(g => findings.some(f => g.rx.test(`${f.title} ${f.category}`))) ? <p className="ws-muted">No network-class findings.</p> : null}
      </div>

      <div className="ws-two ws-section">
        <div className="ws-card ws-card--pad">
          <h2>Endpoints &amp; WebSockets</h2>
          <div className="ws-scroll">
            {[...ws, ...urls].slice(0, 120).map((u, i) => (
              <a key={i} href={u} target="_blank" rel="noopener noreferrer" className="ws-file"><Network size={13} className="ws-muted" /><span className="ws-file__path" title={u}>{u}</span><ArrowUpRight size={12} /></a>
            ))}
            {!endpoints.length ? <p className="ws-muted">No endpoints extracted.</p> : null}
          </div>
        </div>
        <div className="ws-card ws-card--pad">
          <h2>IP Addresses</h2>
          <div className="ws-scroll">
            {ips.slice(0, 80).map((ip, i) => (
              <div key={i} className="ws-file"><span className="ws-mono">{ip.ip || ip}</span>{ip.type ? <SoftTag>{ip.type}</SoftTag> : null}</div>
            ))}
            {!ips.length ? <p className="ws-muted">No IP addresses found.</p> : null}
          </div>
        </div>
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
  const flag = (v, dangerWhenTrue = true) => v === undefined ? '—' : (v ? 'true' : 'false')
  const flagLevel = v => v ? 'warn' : 'good'

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
          <FlagRow label="debuggable" value={ms.debuggable ?? info.debuggable} danger />
          <FlagRow label="allowBackup" value={ms.allow_backup ?? ms.allowBackup} danger />
          <FlagRow label="usesCleartextTraffic" value={ms.uses_cleartext_traffic ?? ms.usesCleartextTraffic} danger />
          <FlagRow label="networkSecurityConfig" value={(results.network_config || {}).present} danger={false} />
        </div>
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

function FlagRow({ label, value, danger }) {
  const on = value === true
  const bad = danger && on
  return (
    <div className="ws-assess__row">
      {bad ? <ShieldAlert size={15} style={{ color: SEV_COLOR.high }} /> : <ShieldCheck size={15} style={{ color: '#067647' }} />}
      <span style={{ color: bad ? 'var(--sev-high)' : 'var(--ws-ink-2)' }}>{label} = <b>{value === undefined ? '—' : String(on)}</b></span>
    </div>
  )
}

// ───────────────────────────── Components ────────────────────────────────
export function ComponentsPanel({ results }) {
  const surface = results.attack_surface || {}
  const inv = results.exported_component_inventory || {}
  const riskByName = {}
  ;(inv.components || []).forEach(c => { if (c.name) riskByName[c.name] = c.risk })
  const TYPES = ['activities', 'services', 'receivers', 'providers']
  const [type, setType] = useState('activities')
  const [q, setQ] = useState('')

  const items = (surface[type] || []).filter(c => !q || (c.name || '').toLowerCase().includes(q.toLowerCase()))
  const risk = c => riskByName[c.name] || (c.exported && c.browsable ? 'critical' : c.exported ? 'high' : 'low')
  const RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  items.sort((a, b) => (RANK[risk(a)] ?? 4) - (RANK[risk(b)] ?? 4))

  const deeplinks = (surface.activities || []).filter(a => a.browsable && (a.deeplinks || []).length)

  return (
    <div>
      <div className="ws-section__head"><h1>Components</h1></div>
      <div className="ws-toolbar">
        {TYPES.map(t => (
          <button key={t} type="button" className={`ws-chip${type === t ? ' is-active' : ''}`} onClick={() => setType(t)}>
            {t[0].toUpperCase() + t.slice(1)} <span className="ws-muted">{(surface[t] || []).length}</span>
          </button>
        ))}
        <input className="ws-input" placeholder="Filter components…" value={q} onChange={e => setQ(e.target.value)} />
      </div>

      {items.length ? items.map((c, i) => (
        <div key={i} className="ws-card ws-card--pad" style={{ marginBottom: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <SeverityTag severity={risk(c)} compact />
            <span className="ws-mono" style={{ fontWeight: 560, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis' }}>{c.name}</span>
            {c.exported ? <SoftTag>exported</SoftTag> : null}
            {c.browsable ? <SoftTag>browsable</SoftTag> : null}
            {c.permission ? <SoftTag title="Guarding permission">perm</SoftTag> : null}
          </div>
          {(c.intent_filters || c.intent_actions || []).length ? (
            <div className="ws-muted" style={{ fontSize: 12, marginTop: 6 }}>Actions: {(c.intent_actions || c.intent_filters || []).slice(0, 4).join(', ')}</div>
          ) : null}
          {(c.authorities || []).length ? <div className="ws-muted" style={{ fontSize: 12, marginTop: 4 }}>Authorities: {c.authorities.join(', ')}</div> : null}
        </div>
      )) : <EmptyState title={`No ${type}`} />}

      {deeplinks.length ? (
        <div className="ws-section">
          <h2>Deep Links</h2>
          {deeplinks.map((a, i) => (
            <div key={i} className="ws-card ws-card--pad" style={{ marginBottom: 8 }}>
              <div className="ws-mono" style={{ fontWeight: 560 }}>{a.name}</div>
              {(a.deeplinks || []).map((d, j) => <div key={j} className="ws-mono ws-muted" style={{ fontSize: 12, marginTop: 4 }}>{typeof d === 'string' ? d : `${d.scheme || ''}://${d.host || ''}${d.path || ''}`}</div>)}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  )
}

// ───────────────────────────── Android APIs ──────────────────────────────
const API_CAT_ICON = { default: Cpu }
export function AndroidApiPanel({ results, onOpenCode }) {
  const api = results.android_api || {}
  const entries = Object.entries(api)
  const findings = results.findings || []
  if (!entries.length) return <EmptyState title="No Android API usage classified" body="The analyzer did not categorize platform API usage for this scan." />

  const findingFor = path => findings.find(f => (f.file_path || f.full_path || '') === path)

  return (
    <div>
      <div className="ws-section__head"><h1>Android APIs</h1><span className="ws-muted">{entries.length} categories</span></div>
      {entries.map(([cat, files]) => (
        <div key={cat} className="ws-card ws-card--pad" style={{ marginBottom: 12 }}>
          <div style={{ fontWeight: 620, marginBottom: 8 }}>{cat} <span className="ws-muted">· {files.length} file(s)</span></div>
          <div className="ws-scroll">
            {files.map((file, i) => {
              const f = findingFor(file)
              return (
                <div key={i} className="ws-file" onClick={() => onOpenCode(file, f ? [f.line].filter(Boolean) : [])}>
                  <FileCode2 size={13} className="ws-muted" />
                  <span className="ws-file__path" title={file}>{file}</span>
                  {f ? <SoftTag title="Linked finding">{normSev(f.severity)}</SoftTag> : null}
                  <ChevronRight size={13} className="ws-muted" />
                </div>
              )
            })}
          </div>
        </div>
      ))}
    </div>
  )
}

// ───────────────────────────── Malware / RE ──────────────────────────────
export function MalwarePanel({ results }) {
  const apkid = results.apkid || {}
  const behavior = results.behavior_analysis || []
  const findings = results.findings || []
  const native = results.binaries || results.native_libs || []
  const hasCtl = rx => findings.some(f => rx.test(`${f.title} ${f.category}`))
  const blob = JSON.stringify(apkid).toLowerCase()

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

  return (
    <div>
      <div className="ws-section__head"><h1>Malware Analysis</h1></div>
      <div className="ws-masvs-grid ws-section">
        {indicators.map(([label, present]) => (
          <div key={label} className="ws-mcard" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {present ? <Bug size={16} style={{ color: SEV_COLOR.medium }} /> : <ShieldCheck size={16} className="ws-muted" />}
            <div><div style={{ fontWeight: 600, fontSize: 13 }}>{label}</div><div className="ws-muted" style={{ fontSize: 12 }}>{present ? 'Detected' : 'Not detected'}</div></div>
          </div>
        ))}
      </div>

      {Object.keys(apkid).length ? (
        <div className="ws-section">
          <h2>APKiD Fingerprints</h2>
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
      <div className="ws-section__head"><h1>Compare</h1></div>
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
export function AiAssistantPanel({ results }) {
  const [provider, setProvider] = useState(AI_PROVIDERS[0].id)
  const [model, setModel] = useState(AI_PROVIDERS[0].models[0])
  const [action, setAction] = useState('executive_summary')
  const [targetId, setTargetId] = useState('')
  const [out, setOut] = useState(null)
  const [busy, setBusy] = useState(false)

  const findings = results.findings || []
  const chains = results.cloud_attack_paths || []
  const need = (AI_ACTIONS.find(a => a.id === action) || {}).needs
  const providerObj = AI_PROVIDERS.find(p => p.id === provider) || AI_PROVIDERS[0]

  const run = async () => {
    setBusy(true)
    const context = { results }
    if (need === 'finding') context.finding = findings.find(f => (f.title || f.id) === targetId) || findings[0]
    if (need === 'chain') context.chain = chains.find(c => c.title === targetId) || chains[0]
    const res = await runAssist({ provider, model, action, context })
    setOut(res); setBusy(false)
  }

  return (
    <div>
      <div className="ws-section__head"><h1>AI Assistant</h1><SoftTag>provider-agnostic</SoftTag></div>
      <div className="ws-card ws-card--pad ws-section">
        <div className="ws-aiform">
          <label>Provider
            <select className="ws-input" value={provider} onChange={e => { setProvider(e.target.value); setModel((AI_PROVIDERS.find(p => p.id === e.target.value) || {}).models[0]) }}>
              {AI_PROVIDERS.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          </label>
          <label>Model
            <select className="ws-input" value={model} onChange={e => setModel(e.target.value)}>
              {providerObj.models.map(m => <option key={m} value={m}>{m}</option>)}
            </select>
          </label>
          <label>Action
            <select className="ws-input" value={action} onChange={e => { setAction(e.target.value); setOut(null) }}>
              {AI_ACTIONS.map(a => <option key={a.id} value={a.id}>{a.label}</option>)}
            </select>
          </label>
          {need === 'finding' ? (
            <label>Finding
              <select className="ws-input" value={targetId} onChange={e => setTargetId(e.target.value)}>
                {findings.slice(0, 100).map((f, i) => <option key={i} value={f.title || f.id}>{f.title}</option>)}
              </select>
            </label>
          ) : null}
          {need === 'chain' ? (
            <label>Chain
              <select className="ws-input" value={targetId} onChange={e => setTargetId(e.target.value)}>
                {chains.map((c, i) => <option key={i} value={c.title}>{c.title}</option>)}
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
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <h2 style={{ margin: 0 }}>Result</h2>
            <SoftTag>{out.live ? `live · ${out.provider}` : 'analyst intelligence (offline)'}</SoftTag>
          </div>
          <pre className="ws-code" style={{ whiteSpace: 'pre-wrap' }}>{out.text}</pre>
        </div>
      ) : (
        <p className="ws-muted">Pick a provider, action, and target, then Run. Without a configured LLM gateway this uses Beetle's deterministic analyst intelligence; the provider abstraction is ready to dispatch to Claude, OpenAI, Gemini, DeepSeek, or Ollama.</p>
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

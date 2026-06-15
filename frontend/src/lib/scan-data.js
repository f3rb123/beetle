export const SECTION_GROUPS = [
  {
    title: 'Overview',
    items: [
      { id: 'dashboard', label: 'Dashboard', hint: 'Security posture, scan score, and decision-driving context.' },
      { id: 'findings', label: 'Findings', hint: 'Prioritized vulnerabilities with evidence and remediation context.' },
      { id: 'compare', label: 'Compare', hint: 'Diff this scan against a previous one to validate improvements.' },
      { id: 'info', label: 'App Info', hint: 'Package identity, hashes, platform, and scan metadata.' },
    ],
  },
  {
    title: 'Evidence',
    items: [
      { id: 'source', label: 'Source Files', hint: 'Browse decompiled output and open files in the unified code viewer.' },
      { id: 'code', label: 'Code Analysis', hint: 'SAST-oriented issues grouped for code review.' },
      { id: 'manifest', label: 'Manifest', hint: 'Unified code view for manifest review and exported defaults.' },
      { id: 'strings', label: 'Strings', hint: 'Sensitive strings, hardcoded material, and extracted clues.' },
      { id: 'secrets', label: 'Secrets', hint: 'Embedded keys, credentials, and leak-prone configuration.' },
      { id: 'jwts', label: 'JWTs', hint: 'Auth artifacts that should be treated as active secrets.' },
      { id: 'ips', label: 'IPs', hint: 'Hardcoded infrastructure references and network exposure.' },
    ],
  },
  {
    title: 'Attack Surface',
    items: [
      { id: 'permissions', label: 'Permissions', hint: 'Declared permissions and dangerous capability scope.' },
      { id: 'surface', label: 'Attack Surface', hint: 'Activities, services, receivers, and providers.' },
      { id: 'browsable', label: 'Browsable', hint: 'Deeplinks and externally triggerable entry points.' },
      { id: 'endpoints', label: 'Endpoints', hint: 'Discovered URLs and API targets.' },
      { id: 'domains', label: 'Domains', hint: 'Domain intelligence and ownership signals.' },
      { id: 'api', label: 'Android API', hint: 'Sensitive platform API usage with linked files.' },
    ],
  },
  {
    title: 'Hardening',
    items: [
      { id: 'binary', label: 'Binaries', hint: 'Native library protection flags and hardening posture.' },
      { id: 'cert', label: 'Certificate', hint: 'Signing material, validity, and release hygiene.' },
      { id: 'apkid', label: 'APKiD', hint: 'Compiler, packer, anti-analysis, and protection clues.' },
      { id: 'masvs', label: 'MASVS / OWASP', hint: 'Standards mapping for the issues already detected.' },
      { id: 'components', label: 'Vulnerable Components', hint: 'Bundled OSS libraries with matching CVEs from OSV.dev.' },
    ],
  },
  {
    title: 'Intelligence',
    items: [
      { id: 'trackers', label: 'Trackers', hint: 'Privacy-impacting SDKs and third-party telemetry.' },
      { id: 'sdks', label: 'SDKs', hint: 'Third-party packages and embedded frameworks.' },
      { id: 'emails', label: 'Emails', hint: 'Discovered contact strings or leaked addresses.' },
      { id: 'virustotal', label: 'VirusTotal', hint: 'Hash-based AV reputation check across 70+ engines.' },
    ],
  },
  {
    title: 'Data Flow',
    items: [
      { id: 'taint', label: 'Taint Flows', hint: 'Inter-procedural data-flow paths from user-controlled sources to sensitive sinks.' },
    ],
  },
  {
    title: 'iOS Deep Analysis',
    platform: 'ios',
    items: [
      { id: 'entitlements',  label: 'Entitlements',      hint: 'Provisioning entitlements and dangerous capability flags.', platform: 'ios' },
      { id: 'ios_frameworks',label: 'Frameworks',        hint: 'Embedded third-party frameworks and SDK security signals.', platform: 'ios' },
      { id: 'ios_storage',   label: 'Data Storage',      hint: 'Keychain, UserDefaults, CoreData, Realm and file protection posture.', platform: 'ios' },
      { id: 'ios_crypto',    label: 'Cryptography',      hint: 'iOS cryptographic API usage and weak algorithm detection.', platform: 'ios' },
      { id: 'ios_webview',   label: 'WebView / Bridges', hint: 'WKWebView configuration, JS bridge handlers and UIWebView usage.', platform: 'ios' },
    ],
  },
]

export const QUICK_SECTION_IDS = new Set([
  'dashboard',
  'findings',
  'manifest',
  'surface',
  'cert',
  'info',
  'compare',
])

export const SECTION_MAP = SECTION_GROUPS.flatMap(group => group.items).reduce((acc, item) => {
  acc[item.id] = item
  return acc
}, {})

export const SECTION_IDS = Object.keys(SECTION_MAP)

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

// Centralized normalization — frontend must not assume the backend's case.
export const normalizeSeverity = (sev) => {
  if (sev == null) return 'info'
  const s = String(sev).trim().toLowerCase()
  return SEVERITY_ORDER.includes(s) ? s : 'info'
}

// Recompute a severity summary from a findings list. Safe default when the
// backend summary disagrees with the findings array (older scans, stale blobs).
export const deriveSeveritySummary = (findings = []) => {
  const out = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of findings) out[normalizeSeverity(f?.severity)] += 1
  return out
}

export const SEVERITY_META = {
  critical: { label: 'Critical', text: '#7F1D1D', bg: '#FEE2E2', border: '#FECACA', accent: '#7F1D1D' },
  high: { label: 'High', text: '#DC2626', bg: '#FEE2E2', border: '#FECACA', accent: '#DC2626' },
  medium: { label: 'Medium', text: '#F59E0B', bg: '#FEF3C7', border: '#FDE68A', accent: '#F59E0B' },
  low: { label: 'Low', text: '#10B981', bg: '#DCFCE7', border: '#BBF7D0', accent: '#10B981' },
  info: { label: 'Info', text: '#3B82F6', bg: '#DBEAFE', border: '#BFDBFE', accent: '#3B82F6' },
}

export const GRADE_META = {
  A: { label: 'Excellent', color: '#10B981', bg: 'rgba(16, 185, 129, 0.14)' },
  B: { label: 'Strong', color: '#3B82F6', bg: 'rgba(59, 130, 246, 0.14)' },
  C: { label: 'Watchlist', color: '#F59E0B', bg: 'rgba(245, 158, 11, 0.14)' },
  D: { label: 'Weak', color: '#F97316', bg: 'rgba(249, 115, 22, 0.14)' },
  F: { label: 'Critical', color: '#DC2626', bg: 'rgba(220, 38, 38, 0.14)' },
}

export const SCAN_STAGES = [
  { id: 'queued', label: 'Queued' },
  { id: 'preparing', label: 'Prepare' },
  { id: 'decompiling', label: 'Decompile' },
  { id: 'analyzing', label: 'Analyze' },
  { id: 'finalizing', label: 'Finalize' },
  { id: 'completed', label: 'Complete' },
]

export const DEFAULT_STAGE = SCAN_STAGES[0]

export function getStageMeta(stageId = DEFAULT_STAGE.id) {
  return SCAN_STAGES.find(stage => stage.id === stageId) || DEFAULT_STAGE
}

export function looksLikeResults(payload) {
  return Boolean(payload?.scan_id && (payload?.app_info || payload?.findings || payload?.score))
}

export async function readJsonResponse(response) {
  const text = await response.text()
  try {
    return { data: JSON.parse(text), text }
  } catch {
    return { data: null, text }
  }
}

export function normalizeHistoryEntry(entry = {}) {
  return {
    ...entry,
    app_name: entry.app_name || entry.filename || 'Untitled scan',
    pkg: entry.pkg || entry.package || entry.bundle_id || '',
    grade: entry.grade || entry.score?.grade || '',
    score: entry.score?.score ?? entry.score ?? 0,
    ss: entry.ss || {
      critical: entry.s_critical || 0,
      high: entry.s_high || 0,
      medium: entry.s_medium || 0,
      low: entry.s_low || 0,
      info: entry.s_info || 0,
    },
    icon_data: entry.icon_data || entry.app_info?.icon_data || '',
    platform: entry.platform || 'android',
    timestamp: entry.scan_time || entry.created_at || entry.updated_at || '',
  }
}

export function loadLocalHistory() {
  if (typeof window === 'undefined') return []
  try {
    const raw = JSON.parse(window.localStorage.getItem('ch') || '[]')
    return raw.map(normalizeHistoryEntry)
  } catch {
    return []
  }
}

export function saveScanSnapshot(results) {
  if (typeof window === 'undefined' || !results?.scan_id) return

  try {
    const history = loadLocalHistory()
    const entry = normalizeHistoryEntry({
      scan_id: results.scan_id,
      app_name: results.app_name,
      platform: results.platform,
      grade: results.score?.grade,
      score: results.score?.score,
      ss: results.severity_summary,
      pkg: results.app_info?.package || results.app_info?.bundle_id || '',
      icon_data: results.app_info?.icon_data || '',
      scan_time: results.scan_time,
      created_at: results.scan_time,
      filename: results.filename,
    })

    const nextHistory = [entry, ...history.filter(item => item.scan_id !== entry.scan_id)].slice(0, 10)
    window.localStorage.setItem('ch', JSON.stringify(nextHistory))
    // Tag the snapshot with a client-side save time so re-entries after a long
    // absence don't silently show stale triage / finding state.
    const snapshot = { ...results, __cached_at: Date.now() }
    window.localStorage.setItem(`cs_${results.scan_id}`, JSON.stringify(snapshot))
  } catch {
    // Ignore local persistence failures.
  }
}

// Snapshots older than this are discarded on read. The UI still fetches fresh
// results from the server on every entry — this TTL just prevents rendering an
// ancient cached view first if the fetch is slow.
const SNAPSHOT_TTL_MS = 15 * 60 * 1000

export function getStoredScan(scanId) {
  if (typeof window === 'undefined' || !scanId) return null
  try {
    const raw = window.localStorage.getItem(`cs_${scanId}`)
    if (!raw) return null
    const parsed = JSON.parse(raw)
    const savedAt = parsed?.__cached_at
    if (savedAt && (Date.now() - savedAt) > SNAPSHOT_TTL_MS) {
      // Expired — drop it so the caller falls through to a clean fetch.
      try { window.localStorage.removeItem(`cs_${scanId}`) } catch { /* ignore */ }
      return null
    }
    return parsed
  } catch {
    return null
  }
}

// Section ids that should disappear from the sidebar when they have no data.
// NOTE: `components` (Vulnerable Components / CVE mapping) is intentionally NOT
// gated — we always show the section so users can confirm the scan ran the
// CVE analyzer, even when it found nothing (the section renders a friendly
// "No bundled components detected" empty state in that case).
const DATA_GATED_SECTIONS = {
  taint: results =>
    (results?.taint_flows?.length || 0) > 0 ||
    (results?.findings || []).some(f => f.source === 'TAINT'),
  virustotal: results =>
    !!(results?.virustotal || results?.vt_report),
}

export function getSectionGroups(viewMode = 'detailed', platform = '', results = null) {
  const plat = String(platform || '').toLowerCase()
  let groups = SECTION_GROUPS

  // Filter platform-specific groups
  if (plat) {
    groups = groups.filter(g => !g.platform || g.platform === plat)
    groups = groups.map(g => ({
      ...g,
      items: g.items.filter(item => !item.platform || item.platform === plat),
    })).filter(g => g.items.length > 0)
  } else {
    // Hide iOS-only sections when platform unknown
    groups = groups.filter(g => g.platform !== 'ios')
  }

  // Drop data-gated sections that have no data to show.
  if (results) {
    groups = groups.map(g => ({
      ...g,
      items: g.items.filter(item => {
        const gate = DATA_GATED_SECTIONS[item.id]
        return gate ? gate(results) : true
      }),
    })).filter(g => g.items.length > 0)
  }

  if (viewMode !== 'quick') return groups

  return groups.map(group => ({
    ...group,
    items: group.items.filter(item => QUICK_SECTION_IDS.has(item.id)),
  })).filter(group => group.items.length > 0)
}

export function getInitial(label = '') {
  const cleaned = String(label || '').replace(/[^a-z0-9]/gi, '').trim()
  return (cleaned[0] || 'C').toUpperCase()
}

export function getPlatformCode(platform = '', fallbackName = '') {
  const value = String(platform || '').toLowerCase()
  const filename = String(fallbackName || '').toLowerCase()
  if (value === 'ios' || value.includes('ipa') || filename.endsWith('.ipa')) return 'IPA'
  return 'APK'
}

export function getPlatformLabel(filename = '') {
  return String(filename || '').toLowerCase().endsWith('.ipa') ? 'iOS IPA' : 'Android APK'
}

export function formatDuration(ms) {
  if (!Number.isFinite(ms) || ms <= 0) return '—'
  if (ms >= 1000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.round(ms)}ms`
}

export function formatFileSize(sizeMb) {
  if (!Number.isFinite(Number(sizeMb))) return '—'
  return `${Number(sizeMb).toFixed(1)} MB`
}

export function formatTimestamp(value) {
  if (!value) return 'Unknown time'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'Unknown time'
  return date.toLocaleString([], {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  })
}

export function relativeTimestamp(value) {
  if (!value) return 'Recently'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'Recently'

  const diffMs = date.getTime() - Date.now()
  const diffMinutes = Math.round(diffMs / 60000)

  if (Math.abs(diffMinutes) < 60) {
    const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
    return formatter.format(diffMinutes, 'minute')
  }

  const diffHours = Math.round(diffMinutes / 60)
  if (Math.abs(diffHours) < 24) {
    const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
    return formatter.format(diffHours, 'hour')
  }

  const diffDays = Math.round(diffHours / 24)
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
  return formatter.format(diffDays, 'day')
}

export function isQuickFinding(finding = {}) {
  const title = String(finding.title || '')
  return ['critical', 'high'].includes(finding.severity) ||
    /Debuggable|Signature Scheme|Content Provider|Attack Chain|Session Recording|JWT|Certificate/i.test(title)
}

export function normLines(lines, fallbackLine) {
  const raw = Array.isArray(lines) ? lines : lines != null ? [lines] : fallbackLine ? [fallbackLine] : []
  return [...new Set(raw.map(value => Number(value)).filter(value => Number.isInteger(value) && value > 0))].sort((a, b) => a - b)
}

export function getEvidenceEntries(finding = {}) {
  const entries = []
  const primaryPath = finding.file_path || ''
  const primaryLines = normLines(finding.file_evidence?.[0]?.lines, finding.line)

  ;(finding.file_evidence || []).forEach(entry => {
    if (!entry?.path) return
    entries.push({
      path: entry.path,
      lines: normLines(entry.lines),
      snippet: entry.snippet || '',
    })
  })

  if (entries.length === 0 && Array.isArray(finding.files)) {
    finding.files.forEach(path => {
      if (!path) return
      entries.push({
        path,
        lines: path === primaryPath ? primaryLines : [],
        snippet: path === primaryPath ? finding.snippet || '' : '',
      })
    })
  }

  if (entries.length === 0 && primaryPath) {
    entries.push({
      path: primaryPath,
      lines: primaryLines,
      snippet: finding.snippet || '',
    })
  }

  const seen = new Set()
  return entries.filter(entry => {
    const key = `${entry.path}|${entry.lines.join(',')}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

export function getPrimaryEvidence(finding = {}) {
  const entries = getEvidenceEntries(finding)
  return entries[0] || null
}

export function countLinkedFindings(findings = []) {
  return findings.filter(item => Boolean(getPrimaryEvidence(item)?.path)).length
}

export function getSeveritySummary(results = {}) {
  return results.severity_summary || {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  }
}

export function getGradeMeta(grade) {
  return GRADE_META[grade] || { label: 'Ungraded', color: '#475569', bg: 'rgba(71, 85, 105, 0.14)' }
}

export function getTopFindings(findings = [], limit = 5) {
  return [...findings]
    .sort((a, b) => {
      const severityDiff = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
      if (severityDiff !== 0) return severityDiff
      return (b.exploitability || 0) - (a.exploitability || 0)
    })
    .slice(0, limit)
}

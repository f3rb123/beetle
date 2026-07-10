// Phase 1.99 — Evidence UI data model (pure, no React, unit-testable).
//
// Adapts the backend intelligence pipeline's per-finding output into the shapes the
// analyst workspace renders. It NEVER recomputes intelligence — it reads what the
// backend already produced (evidence_view from the Evidence Selection / Report
// Accuracy engines, detected_by + fusion from Finding Fusion, confidence_breakdown
// from the Confidence Engine) and falls back gracefully to legacy fields so older
// scans still render. Keeping this React-free makes it testable under plain Node.

// ── language detection (for the primary evidence card) ────────────────────────
const EXT_LANG = {
  java: 'Java', kt: 'Kotlin', kts: 'Kotlin', smali: 'Smali', xml: 'XML',
  json: 'JSON', js: 'JavaScript', jsx: 'JavaScript', ts: 'TypeScript', tsx: 'TypeScript',
  swift: 'Swift', m: 'Objective-C', mm: 'Objective-C', h: 'C/Obj-C Header',
  plist: 'Property List', gradle: 'Gradle', properties: 'Properties', dart: 'Dart',
  so: 'Native (ELF)', dylib: 'Native (Mach-O)', yml: 'YAML', yaml: 'YAML',
}

export function languageOf(path) {
  if (!path) return ''
  const base = String(path).split(/[\\/]/).pop()
  if (/^androidmanifest\.xml$/i.test(base)) return 'Android Manifest'
  if (/^info\.plist$/i.test(base)) return 'Info.plist'
  const ext = base.includes('.') ? base.split('.').pop().toLowerCase() : ''
  return EXT_LANG[ext] || (ext ? ext.toUpperCase() : '')
}

const num = (v, d = 0) => { const n = Number(v); return Number.isFinite(n) ? n : d }

// ── detection sources (Detected By badges) ────────────────────────────────────
// Reads Finding Fusion's detected_by; future engines appear automatically. Falls
// back to inferring a single source from legacy producer fields.
export function detectionSources(f) {
  const finding = f || {}
  let list = Array.isArray(finding.detected_by) ? finding.detected_by.filter(Boolean) : []
  if (!list.length) {
    const inferred = finding.source_module || finding.source ||
      (finding.discovery_method ? labelForMethod(finding.discovery_method) : '') || 'Beetle Native'
    list = [inferred]
  }
  // De-dupe, preserve order.
  return [...new Set(list.map(String))]
}

function labelForMethod(m) {
  const map = {
    apkleaks_regex: 'APKLeaks', taint_flow: 'Taint', manifest: 'Manifest',
    regex_match: 'Beetle Native', live_probe: 'Live Probe', secret: 'Secrets',
  }
  return map[String(m)] || ''
}

// ── unified evidence view ─────────────────────────────────────────────────────
// Prefers the backend evidence_view (Report Accuracy engine). Falls back to
// evidence_selection, then to a minimal view assembled from legacy fields so the
// card always renders something honest.
export function getEvidenceView(f) {
  const finding = f || {}
  const v = finding.evidence_view
  if (v && v.primary && v.primary.file) return normalizeView(v, finding)

  const sel = finding.evidence_selection
  if (sel && sel.primary && sel.primary.file_path) {
    return normalizeView({
      primary: viewProof(sel.primary),
      supporting: (sel.supporting || []).map(viewProof),
      additional_references: (sel.additional_references || []).map(viewProof),
      hidden_library_evidence: sel.hidden ? sel.hidden : (sel.rejected ? hiddenFromRejected(sel.rejected) : emptyHidden()),
      evidence_score: sel.primary.score,
      selection_reason: sel.reason,
      evidence_ownership: sel.primary.owner_type,
      evidence_source: sel.primary.source,
      detection_sources: finding.detected_by,
      reachability: finding.reachability,
      in_attack_chain: !!(finding.in_attack_chain || finding.is_attack_chain),
    }, finding)
  }
  return legacyView(finding)
}

function viewProof(p) {
  if (!p) return null
  return {
    file: p.file || p.file_path || '', line: p.line || 0, snippet: p.snippet || '',
    owner_type: p.owner_type || '', owner_name: p.owner_name || '', source: p.source || '',
    score: p.score, reasons: p.selected_because || p.reasons || [],
  }
}

function hiddenFromRejected(rejected) {
  const items = (rejected || []).map(r => ({
    file: r.file_path || r.file || '', owner_type: r.owner_type || '',
    owner_name: r.owner_name || r.owner_type || '', reasons: r.rejected_because || [],
  }))
  return { count: items.length, owners: [...new Set(items.map(i => i.owner_name).filter(Boolean))], items }
}

const emptyHidden = () => ({ count: 0, owners: [], items: [] })

function normalizeView(v, finding) {
  return {
    primary: v.primary ? { file: v.primary.file || '', line: num(v.primary.line), snippet: v.primary.snippet || '',
      owner_type: v.primary.owner_type || '', owner_name: v.primary.owner_name || '',
      source: v.primary.source || '', score: v.primary.score, reasons: v.primary.reasons || [],
      // Prefer a backend-supplied language label (e.g. "Signing Metadata" for a
      // certificate artifact, "Android Manifest" for the manifest); else infer.
      language: v.primary.language || languageOf(v.primary.file),
      artifact: !!v.primary.artifact } : null,
    frameworkOnly: !!v.framework_only,
    artifact: !!v.artifact,
    supporting: (v.supporting || []).filter(Boolean).map(p => ({ ...p, language: languageOf(p.file) })),
    additional: v.additional_references || [],
    hidden: v.hidden_library_evidence || emptyHidden(),
    evidenceScore: num(v.evidence_score),
    reason: v.selection_reason || '',
    ownership: v.evidence_ownership || finding.owner_type || '',
    source: v.evidence_source || '',
    detectionSources: detectionSources({ ...finding, detected_by: v.detection_sources || finding.detected_by }),
    reachability: v.reachability || finding.reachability || '',
    inAttackChain: !!v.in_attack_chain,
    fallback: !!v.fallback,
  }
}

// Build a view from legacy file_evidence / file_path when no selection ran.
function legacyView(finding) {
  const fe = Array.isArray(finding.file_evidence) ? finding.file_evidence : []
  const first = fe[0]
  const primFile = (first && first.path) || finding.file_path || finding.full_path || ''
  const primLine = (first && first.lines && first.lines[0]) || finding.line || finding.line_number || 0
  return {
    primary: primFile ? {
      file: primFile, line: num(primLine), snippet: (first && first.snippet) || finding.snippet || finding.code_context || '',
      owner_type: finding.owner_type || '', owner_name: finding.owner_name || '', source: '',
      score: undefined, reasons: [], language: languageOf(primFile),
    } : null,
    supporting: fe.slice(1, 6).map(e => ({ file: e.path, line: (e.lines || [])[0] || 0, snippet: e.snippet || '',
      owner_type: '', owner_name: '', source: 'file_evidence', language: languageOf(e.path) })),
    additional: [],
    hidden: emptyHidden(),
    evidenceScore: 0,
    reason: 'Legacy evidence (selection engine did not run for this finding).',
    ownership: finding.owner_type || '',
    source: '',
    detectionSources: detectionSources(finding),
    reachability: finding.reachability || '',
    inAttackChain: !!(finding.in_attack_chain || finding.is_attack_chain),
    frameworkOnly: false,
    artifact: false,
    fallback: true,
  }
}

// ── chain evidence normalization ──────────────────────────────────────────────
// Attack-chain (is_attack_chain) findings aggregate evidence differently from
// regular findings: evidence_references[] ({file, line, evidence_id}) and per-step
// steps[].evidence ("path:line" strings), with affected_files[] as a last resort —
// NOT the regular file_path/file_evidence[].line shape. These helpers translate the
// chain shape into the same (file, line) targets the code viewer jumps to, so
// view-code on a chain (and each of its steps) lands on the exact line.

// Parse a step's "path:line" (or bare "path") evidence string into {file, line}.
export function parseStepEvidence(ev) {
  if (typeof ev !== 'string') return null
  const s = ev.trim()
  if (!s) return null
  const m = s.match(/^(.*):(\d+)$/)   // trailing :<line> (greedy path allows drive-less paths)
  if (m) return { file: m[1], line: num(m[2]) }
  return { file: s, line: 0 }
}

// Ordered, de-duplicated (file, line, snippet, source) viewer targets for a chain
// finding. evidence_references first (they carry the corrected file + line), then
// each step's own evidence, then affected_files (no line → graceful "open file").
export function chainEvidenceTargets(finding) {
  const f = finding || {}
  const out = []
  const seen = new Set()
  const add = (file, line, snippet, source) => {
    if (!file) return
    const ln = num(line)
    const key = ln ? `${file}#${ln}` : `${file}#${source}`
    if (seen.has(key)) return
    seen.add(key)
    out.push({ file, line: ln, snippet: snippet || '', source })
  }
  for (const r of (Array.isArray(f.evidence_references) ? f.evidence_references : [])) {
    if (r && r.file) add(r.file, r.line, r.evidence_id, 'chain evidence')
  }
  for (const s of (Array.isArray(f.steps) ? f.steps : [])) {
    const t = parseStepEvidence(s && s.evidence)
    if (t) add(t.file, t.line, (s && (s.title || s.description)) || '', 'chain step')
  }
  if (!out.length) {
    for (const p of (Array.isArray(f.affected_files) ? f.affected_files : [])) {
      if (p) add(p, 0, '', 'chain file')   // no line — viewer opens the file, no jump
    }
  }
  return out
}

// The single primary (file, line) target for a chain finding's "View Code":
// the first reference that carries a real line, else the first target of any kind
// (file-only → open without jumping), else null when the chain has no proof file.
export function chainViewerTarget(finding) {
  const targets = chainEvidenceTargets(finding)
  return targets.find(t => t.line > 0) || targets[0] || null
}

// A drawer/primary-evidence VIEW for a chain finding, built from its normalized
// chain targets (evidence_references[] / steps[].evidence) — so the primary "View
// Code" lands on the same file:line the PDF uses, never evidence[0] from the stale
// generic path (which could be an excluded R-constant class). Returns null when the
// chain has no proof location at all (caller falls back to the generic view).
export function chainEvidenceView(finding) {
  const f = finding || {}
  const primary = chainViewerTarget(f)
  if (!primary || !primary.file) return null
  const proof = (t) => ({
    file: t.file, line: num(t.line), snippet: t.snippet || '',
    owner_type: f.owner_type || '', owner_name: f.owner_name || '',
    source: t.source || 'chain evidence', language: languageOf(t.file), reasons: [],
    artifact: false,
  })
  const supporting = chainEvidenceTargets(f).filter(
    t => !(t.file === primary.file && num(t.line) === num(primary.line)))
  return {
    primary: proof(primary),
    supporting: supporting.map(proof),
    additional: [],
    hidden: { count: 0, owners: [], items: [] },
    evidenceScore: 0,
    reason: '',
    ownership: f.owner_type || f.ownership_label || '',
    source: 'chain evidence',
    detectionSources: detectionSources(f),
    reachability: f.reachability || '',
    inAttackChain: true,
    frameworkOnly: false,
    artifact: false,
    fallback: false,
  }
}

// ── ownership label humanization ──────────────────────────────────────────────
// Ownership arrives as either the Ownership Engine enum (ThirdPartySDK) or the
// finding_model label (THIRD_PARTY_SDK). Both must render as a short, human string
// that fits its stat tile/badge — never the raw CamelCase enum ("Thirdpartysdk").
const OWNERSHIP_DISPLAY = {
  APPLICATION: 'Application',
  THIRDPARTYSDK: 'Third-Party SDK',
  THIRDPARTYLIBRARY: 'Third-Party Lib',
  OPENSOURCELIBRARY: 'Open-Source Lib',
  ANDROIDFRAMEWORK: 'Android Framework',
  APPLEFRAMEWORK: 'Apple Framework',
  GOOGLESDK: 'Google SDK',
  VENDORSDK: 'Vendor SDK',
  GENERATEDCODE: 'Generated',
  FIREBASE: 'Firebase',
  JETPACK: 'Jetpack',
  UNKNOWN: 'Unknown',
}

export function humanizeOwnership(raw) {
  if (!raw) return ''
  const key = String(raw).replace(/[^a-z0-9]/gi, '').toUpperCase()
  if (OWNERSHIP_DISPLAY[key]) return OWNERSHIP_DISPLAY[key]
  // Unknown label: split CamelCase / snake_case and title-case, so a future enum
  // reads "Some New Owner" rather than a jammed "Somenewowner".
  return String(raw)
    .replace(/_/g, ' ')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .replace(/\b\w/g, m => m.toUpperCase())
}

// ── trust score (display-only roll-up) ────────────────────────────────────────
// A single 0-100 "how much should I trust this finding" number from the signals
// the backend already computed: overall confidence (dominant), fusion corroboration
// and evidence strength. Never used for filtering/suppression — purely a glance.
export function trustScore(f) {
  const finding = f || {}
  const conf = num(finding.overall_confidence, num(finding.confidence_score, num(finding.confidence)))
  const fusion = num(finding.fusion_score)
  const evScore = num((finding.evidence_view || {}).evidence_score)
  let score = conf * 0.6
  score += Math.min(fusion, 100) * 0.25
  score += Math.min(Math.max(evScore, 0), 100) * 0.15
  const out = Math.round(Math.max(0, Math.min(100, score)))
  return out
}

export function trustBand(score) {
  return score >= 75 ? 'high' : score >= 50 ? 'medium' : score >= 25 ? 'low' : 'info'
}

// ── confidence contributions (Confidence Panel) ───────────────────────────────
export function confidenceContributions(f) {
  const finding = f || {}
  const overall = num(finding.overall_confidence, num(finding.confidence_score, num(finding.confidence)))
  const bd = finding.confidence_breakdown || {}
  const dims = bd.dimensions || {}
  const dim = (k) => num(dims[k] && (dims[k].score ?? dims[k]))
  const pos = [], neg = []
  const add = (label, v, goodAt = 60) => { if (!v && v !== 0) return; (v >= goodAt ? pos : neg).push({ label, value: v }) }
  add('Detection', dim('detection'))
  add('Ownership', dim('ownership') || num(finding.owner_confidence))
  add('Evidence', dim('evidence') || num((finding.evidence_view || {}).evidence_score))
  add('Context', dim('context'))
  add('Exploitability', dim('exploitability'))
  const detCount = num(finding.detection_count, (finding.detected_by || []).length)
  return {
    overall,
    band: bd.band || (overall >= 75 ? 'High' : overall >= 50 ? 'Medium' : overall >= 25 ? 'Low' : 'Informational'),
    reason: finding.confidence_reason || '',
    positives: pos,
    negatives: neg,
    fusionContribution: detCount >= 2 ? `Corroborated by ${detCount} independent engines` : 'Single engine detection',
    evidenceContribution: num((finding.evidence_view || {}).evidence_score) || num(dim('evidence')),
    ownershipContribution: finding.owner_name || finding.owner_type || 'Unknown',
  }
}

export function reachabilityLabel(f) {
  const r = String((f || {}).reachability || '').toUpperCase()
  return r === 'YES' ? 'Reachable' : r === 'MAYBE' ? 'Possibly reachable' : r === 'NO' ? 'Not reachable' : ''
}

// ── filtering (Search panel) ──────────────────────────────────────────────────
export const OWNERSHIP_OPTIONS = ['Application', 'ThirdPartySDK', 'GoogleSDK', 'AndroidFramework',
  'AppleFramework', 'VendorSDK', 'OpenSourceLibrary', 'GeneratedCode', 'Unknown']

export function findingDetectionSourceSet(findings) {
  const s = new Set()
  for (const f of findings || []) detectionSources(f).forEach(x => s.add(x))
  return [...s].sort()
}

export function findingFrameworkSet(findings) {
  const s = new Set()
  for (const f of findings || []) { const fw = f.framework_name || f.framework; if (fw) s.add(fw) }
  return [...s].sort()
}

// A single predicate the panel composes. All criteria optional; empty = match-all.
export function matchesFilters(f, c) {
  const finding = f || {}, crit = c || {}
  if (crit.severity && crit.severity !== 'all' && String(finding.severity || 'info').toLowerCase() !== crit.severity) return false
  if (crit.category && crit.category !== 'all' && finding.category !== crit.category) return false
  if (crit.detectionSource && crit.detectionSource !== 'all' && !detectionSources(finding).includes(crit.detectionSource)) return false
  if (crit.ownership && crit.ownership !== 'all') {
    const ot = finding.owner_type || finding.ownership || ''
    if (ot !== crit.ownership) return false
  }
  if (crit.framework && crit.framework !== 'all' && (finding.framework_name || finding.framework || '') !== crit.framework) return false
  if (crit.masvs && crit.masvs !== 'all' && !String(arrify(finding.masvs).join(' ')).includes(crit.masvs)) return false
  if (crit.owasp && crit.owasp !== 'all' && !String(arrify(finding.owasp).join(' ')).includes(crit.owasp)) return false
  if (crit.minEvidence && num((finding.evidence_view || {}).evidence_score) < num(crit.minEvidence)) return false
  if (crit.minTrust && trustScore(finding) < num(crit.minTrust)) return false
  return true
}

function arrify(v) { return Array.isArray(v) ? v : (v ? [v] : []) }

/**
 * Source Explorer — pure tree + overlay model (Beetle 2.0, Phase 2.3).
 *
 * Framework-free helpers (unit-testable without React) that turn the existing
 * `/api/scans/{id}/files` manifest + the backend `results.source_explorer` overlay
 * into the data the tree UI renders. No parsing, no extraction — pure projection.
 */

export const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
export const SEV_COLOR = {
  critical: '#7f1d1d', high: '#dc2626', medium: '#ea8600', low: '#3b82f6', info: '#6b7280',
}

// Subdir roots the backend prefixes onto manifest paths; stripped to match the
// finding/secret paths used in the overlay (which are relative to the subdir).
const _PREFIX_RE = /^(?:jadx|apktool|apk_extract|ipa_extract|payload)\//i

export function normalizePath(p) {
  return String(p || '').replace(/\\/g, '/').replace(_PREFIX_RE, '')
}

export function basename(p) {
  const s = String(p || '').replace(/\\/g, '/')
  return s.slice(s.lastIndexOf('/') + 1)
}

export function maxSev(a, b) {
  return (SEV_RANK[a] ?? 0) >= (SEV_RANK[b] ?? 0) ? (a || 'info') : (b || 'info')
}

/**
 * Build a nested tree from a flat list of paths.
 * Node: { name, path, dir, children? }. Dirs first, then files; both alphabetical.
 */
export function buildTree(paths) {
  const root = { name: '', path: '', dir: true, _map: new Map() }
  for (const raw of paths || []) {
    const p = String(raw || '').replace(/\\/g, '/').replace(/^\/+/, '')
    if (!p) continue
    const parts = p.split('/').filter(Boolean)
    let node = root
    let acc = ''
    parts.forEach((part, i) => {
      acc = acc ? `${acc}/${part}` : part
      const isFile = i === parts.length - 1
      let child = node._map.get(part)
      if (!child) {
        child = { name: part, path: acc, dir: !isFile, _map: isFile ? null : new Map() }
        node._map.set(part, child)
      }
      // A path can re-mark an existing node; keep "dir" if it ever has children.
      if (!isFile) child.dir = true
      node = child
    })
  }
  const finalize = (node) => {
    if (!node._map) { delete node._map; return node }
    const children = [...node._map.values()].map(finalize)
    children.sort((a, b) => (a.dir === b.dir
      ? a.name.localeCompare(b.name)
      : (a.dir ? -1 : 1)))
    delete node._map
    node.children = children
    return node
  }
  return finalize(root)
}

/**
 * Build the overlay lookup from the backend file_index:
 *   fileByPath  normalizedPath -> record
 *   fileByBase  basename       -> record (fallback when prefixes differ)
 *   dirSev      normalizedDir  -> { sev, secret, network, certificate, component }
 * Folder severity/flags are propagated up from every annotated file (aggregation).
 */
export function buildOverlay(fileIndex = {}) {
  const fileByPath = new Map()
  const fileByBase = new Map()
  const dirSev = new Map()
  for (const [rawPath, rec] of Object.entries(fileIndex)) {
    const np = normalizePath(rawPath)
    fileByPath.set(np, rec)
    fileByBase.set(basename(np), rec)
    const sev = rec.max_severity || 'info'
    const parts = np.split('/').filter(Boolean)
    let acc = ''
    for (let i = 0; i < parts.length - 1; i++) {
      acc = acc ? `${acc}/${parts[i]}` : parts[i]
      const cur = dirSev.get(acc) || { sev: 'info', secret: false, network: false, certificate: false, component: false }
      cur.sev = maxSev(cur.sev, sev)
      cur.secret = cur.secret || !!rec.secret
      cur.network = cur.network || !!rec.network
      cur.certificate = cur.certificate || !!rec.certificate
      cur.component = cur.component || !!rec.component
      dirSev.set(acc, cur)
    }
  }
  return { fileByPath, fileByBase, dirSev }
}

/** Badge for a node (file or dir), or null when it carries no security signal. */
export function badgeForNode(node, overlay) {
  if (!node || !overlay) return null
  const np = normalizePath(node.path)
  if (node.dir) return overlay.dirSev.get(np) || null
  const rec = overlay.fileByPath.get(np) || overlay.fileByBase.get(node.name)
  if (!rec) return null
  return {
    sev: rec.max_severity || 'info',
    secret: !!rec.secret, network: !!rec.network,
    certificate: !!rec.certificate, component: !!rec.component,
    findings: rec.findings || 0,
  }
}

/** Normalized path set for a Security-Explorer category (for tree filtering). */
export function categoryPathSet(securityIndex = {}, category) {
  if (!category) return null
  const set = new Set()
  for (const p of securityIndex[category] || []) set.add(normalizePath(p))
  return set
}

// ── Quick Filters ────────────────────────────────────────────────────────────
// Convenience shortcuts shown as a row at the top of the Source Explorer. They drive
// the SAME `activeCat` security filter the Security Explorer pane uses — NOT a second
// filtering system. Ids: 'all' = no filter; 'findings' = any file with a finding
// (pseudo-category); the rest are real security categories. `future: true` entries are
// reserved seams (rendered disabled until implemented — Modified ↔ VCS, Favorites ↔
// the Bookmarks extension point).
export const QUICK_FILTERS = [
  { id: 'all', label: 'All Files' },
  { id: 'findings', label: 'Findings' },
  { id: 'secrets', label: 'Secrets' },
  { id: 'network', label: 'Network' },
  { id: 'certificates', label: 'Certificates' },
  { id: 'native', label: 'Native' },
  { id: 'modified', label: 'Modified', future: true },
  { id: 'favorites', label: 'Favorites', future: true },
]

// ── Extension points (future-ready seams — NO implementation in this phase) ──────
// A data registry, mirroring the Engineering Workspace's planned-module pattern: the
// explorer renders these as disabled affordances today; enabling one is flipping its
// `status` to 'available' and wiring a handler (the `on<Ext>` callback props on
// SourceExplorerPanel). No filtering/behavior is attached yet.
export const EXPLORER_EXTENSIONS = [
  { id: 'bookmarks', label: 'Bookmarks', status: 'planned' },
  { id: 'notes', label: 'Notes', status: 'planned' },
  { id: 'compare-scans', label: 'Compare Scans', status: 'planned' },
  { id: 'ai-review', label: 'AI Review', status: 'planned' },
  { id: 'semgrep', label: 'Semgrep Results', status: 'planned' },
]

/**
 * Resolve an activeCat / quick-filter id to a normalized path set (or null = no filter).
 * Routes through the existing category logic — it does NOT introduce a second filter
 * system. 'all'/null → no filter; 'findings' → every annotated file; else the security
 * category set.
 */
export function filterPathSet(filterId, { securityIndex = {}, fileIndex = {} } = {}) {
  if (!filterId || filterId === 'all') return null
  if (filterId === 'findings') {
    const set = new Set()
    for (const p of Object.keys(fileIndex)) set.add(normalizePath(p))
    return set
  }
  return categoryPathSet(securityIndex, filterId)
}

/**
 * Does a node (or any descendant) pass the active filters?
 *  - category: keep files in the category set (and their ancestor dirs)
 *  - query: case-insensitive filename match (dirs kept if any child matches)
 * Returns true if the node should be shown.
 */
export function nodePasses(node, { catSet, query }) {
  const q = (query || '').trim().toLowerCase()
  const matchName = !q || node.name.toLowerCase().includes(q)
  const inCat = !catSet || (!node.dir && catSet.has(normalizePath(node.path)))
  if (!node.dir) return matchName && (!catSet || inCat)
  // Directory: show if any descendant passes.
  return (node.children || []).some(c => nodePasses(c, { catSet, query }))
}

/** Ancestor directory paths of a file path (full, prefixed form preserved). */
export function ancestorsOf(path) {
  const parts = String(path || '').replace(/\\/g, '/').split('/').filter(Boolean)
  const out = []
  let acc = ''
  for (let i = 0; i < parts.length - 1; i++) {
    acc = acc ? `${acc}/${parts[i]}` : parts[i]
    out.push(acc)
  }
  return out
}

/** Resolve a target path (from a finding) to the matching manifest path. */
export function resolveManifestPath(target, manifestPaths) {
  if (!target) return null
  const t = normalizePath(target)
  // Exact (normalized) match first, then suffix match (prefix differences).
  let best = null
  for (const p of manifestPaths || []) {
    const np = normalizePath(p)
    if (np === t) return p
    if (!best && (np.endsWith(t) || t.endsWith(np))) best = p
  }
  return best
}

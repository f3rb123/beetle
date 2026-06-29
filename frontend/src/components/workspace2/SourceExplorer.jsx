/**
 * Source Explorer + Security Explorer (Beetle 2.0, Phase 2.3).
 *
 * The investigation workspace: a lazy file TREE (built client-side from the existing
 * `/api/scans/{id}/files` manifest) with intelligence BADGES (from the backend
 * `results.source_explorer` overlay), a Security Explorer pane that filters the tree
 * by security category, breadcrumb + search, persisted expand state, and one-click
 * "open file" via the existing code viewer (`onOpenCode`). Finding → source jumps
 * (`nav.openSource` / `openInExplorer`) make the tree expand to + select the file.
 *
 * Reuses, does not duplicate: the file API, the CodeBlockViewer (via onOpenCode), the
 * Ownership/Confidence/Evidence metadata already on findings, and the source_explorer
 * overlay. This panel replaces the former flat "Code Browser".
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ChevronRight, ChevronDown, Folder, FolderOpen, FileCode2, FileText, FileJson,
  Image as ImageIcon, Search, KeyRound, Globe, Fingerprint, Boxes, Cpu, ArrowUpRight,
} from 'lucide-react'
import { apiFetch } from '../../lib/auth.js'
import { EmptyState } from './ui.jsx'
import { useWorkspaceNav } from './workspace-context.jsx'
import {
  buildTree, buildOverlay, badgeForNode, nodePasses, filterPathSet,
  ancestorsOf, resolveManifestPath, normalizePath, SEV_COLOR,
  QUICK_FILTERS, EXPLORER_EXTENSIONS,
} from './source-explorer-model.js'

// Backend may return {jadx:[…], apktool:[…]} or a flat list — flatten to paths.
function flattenManifest(files) {
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

const LANG_ICON = {
  java: FileCode2, kt: FileCode2, kts: FileCode2, swift: FileCode2, m: FileCode2,
  h: FileCode2, mm: FileCode2, smali: FileCode2, dart: FileCode2, js: FileCode2,
  jsx: FileCode2, ts: FileCode2, tsx: FileCode2, gradle: FileCode2,
  json: FileJson, yaml: FileText, yml: FileText, xml: FileText, plist: FileText,
  properties: FileText, txt: FileText, md: FileText,
  png: ImageIcon, jpg: ImageIcon, jpeg: ImageIcon, webp: ImageIcon, gif: ImageIcon,
}
function fileIcon(name) {
  const ext = name.slice(name.lastIndexOf('.') + 1).toLowerCase()
  return LANG_ICON[ext] || FileText
}

// The Security Explorer categories (label + icon), aligned with the backend buckets.
const SEC_CATS = [
  ['secrets', 'Secrets', KeyRound], ['crypto', 'Crypto', Fingerprint],
  ['network', 'Network', Globe], ['storage', 'Storage', Boxes],
  ['components', 'Components', Boxes], ['permissions', 'Permissions', Cpu],
  ['certificates', 'Certificates', Fingerprint], ['native', 'Native', Cpu],
  ['authentication', 'Authentication', KeyRound], ['authorization', 'Authorization', KeyRound],
  ['ipc', 'IPC', Boxes],
]

function Badge({ badge }) {
  if (!badge) return null
  return (
    <span className="ws-ex-badges">
      {badge.sev && badge.sev !== 'info'
        ? <span className="ws-ex-dot" style={{ background: SEV_COLOR[badge.sev] || SEV_COLOR.info }} title={badge.sev} />
        : null}
      {badge.secret ? <KeyRound size={11} className="ws-ex-bi" title="Secret" /> : null}
      {badge.network ? <Globe size={11} className="ws-ex-bi" title="Network" /> : null}
      {badge.certificate ? <Fingerprint size={11} className="ws-ex-bi" title="Certificate" /> : null}
      {badge.component ? <Boxes size={11} className="ws-ex-bi" title="Component" /> : null}
    </span>
  )
}

function TreeNode({ node, depth, expanded, toggle, onOpen, overlay, filters, selected }) {
  if (!nodePasses(node, filters)) return null
  const badge = badgeForNode(node, overlay)
  const pad = { paddingLeft: 8 + depth * 14 }

  if (!node.dir) {
    const Icon = fileIcon(node.name)
    const isSel = selected === node.path
    return (
      <div className={`ws-ex-row ws-ex-file${isSel ? ' is-selected' : ''}`} style={pad}
        role="button" tabIndex={0} title={node.path}
        onClick={() => onOpen(node.path)}
        onKeyDown={e => { if (e.key === 'Enter') onOpen(node.path) }}>
        <Icon size={14} className="ws-ex-ficon" />
        <span className="ws-ex-name">{node.name}</span>
        <Badge badge={badge} />
        <ArrowUpRight size={11} className="ws-ex-open" />
      </div>
    )
  }

  const isOpen = expanded.has(node.path)
  return (
    <div className="ws-ex-group">
      <div className="ws-ex-row ws-ex-dir" style={pad} role="button" tabIndex={0}
        onClick={() => toggle(node.path)}
        onKeyDown={e => { if (e.key === 'Enter') toggle(node.path) }} title={node.path}>
        {isOpen ? <ChevronDown size={13} className="ws-ex-chev" /> : <ChevronRight size={13} className="ws-ex-chev" />}
        {isOpen ? <FolderOpen size={14} className="ws-ex-ficon" /> : <Folder size={14} className="ws-ex-ficon" />}
        <span className="ws-ex-name">{node.name}</span>
        <Badge badge={badge} />
      </div>
      {isOpen ? (
        <div className="ws-ex-children">
          {node.children.map((c, i) => (
            <TreeNode key={c.path || i} node={c} depth={depth + 1} expanded={expanded}
              toggle={toggle} onOpen={onOpen} overlay={overlay} filters={filters} selected={selected} />
          ))}
        </div>
      ) : null}
    </div>
  )
}

export function SourceExplorerPanel({ results, scanId, onOpenCode, extensions, initialCategory }) {
  const nav = useWorkspaceNav()
  const explorer = results.source_explorer || {}
  const securityIndex = explorer.security_index || {}
  const fileIndex = explorer.file_index || {}
  const overlay = useMemo(() => buildOverlay(fileIndex), [fileIndex])

  const [manifest, setManifest] = useState(null)
  const [manifestLoading, setManifestLoading] = useState(true)
  const [err, setErr] = useState('')
  const [q, setQ] = useState('')
  // The ONE filter selection, shared by the Quick Filters row and the Security
  // Explorer pane. 'all' = no filter; 'findings' = any file with a finding; else a
  // security category. No second filtering system exists. `initialCategory` lets the
  // Security Explorer launcher open the tree pre-filtered (deep link); the analyst
  // can still change it freely afterward.
  const [activeCat, setActiveCat] = useState(initialCategory || 'all')
  const [selected, setSelected] = useState(null)
  const storeKey = `ws_explorer_expanded_${scanId}`
  const [expanded, setExpanded] = useState(() => {
    try { return new Set(JSON.parse(sessionStorage.getItem(storeKey) || '[]')) } catch { return new Set() }
  })

  // ── Fetch the file manifest once (lazy RENDER below handles large trees) ──────
  useEffect(() => {
    let cancelled = false
    setManifestLoading(true)
    apiFetch(`/api/scans/${scanId}/files`)
      .then(r => r.json())
      .then(d => { if (!cancelled) setManifest(flattenManifest(d.files || [])) })
      .catch(() => { if (!cancelled) setErr('File listing unavailable for this scan.') })
      .finally(() => { if (!cancelled) setManifestLoading(false) })
    return () => { cancelled = true }
  }, [scanId])

  // Fallback manifest from evidence paths when the listing endpoint is empty.
  const evidencePaths = useMemo(() => {
    const s = new Set()
    for (const f of results.findings || []) { const p = f.file_path || f.full_path; if (p) s.add(p) }
    for (const sec of results.secrets || []) { if (sec.file_path) s.add(sec.file_path) }
    return [...s]
  }, [results])

  const paths = (manifest && manifest.length) ? manifest : evidencePaths
  const tree = useMemo(() => buildTree(paths), [paths])
  const filtered = activeCat && activeCat !== 'all'
  const catSet = useMemo(
    () => filterPathSet(activeCat, { securityIndex, fileIndex }),
    [activeCat, securityIndex, fileIndex])

  const persist = useCallback((set) => {
    try { sessionStorage.setItem(storeKey, JSON.stringify([...set])) } catch { /* ignore */ }
  }, [storeKey])

  const toggle = useCallback((path) => {
    setExpanded(prev => {
      const next = new Set(prev)
      next.has(path) ? next.delete(path) : next.add(path)
      persist(next)
      return next
    })
  }, [persist])

  const open = useCallback((path) => {
    setSelected(path)
    if (onOpenCode) onOpenCode(path, [])
    else nav.openSource(path, [])
  }, [onOpenCode, nav])

  // ── Auto-expand on search / category so matches are visible ───────────────────
  useEffect(() => {
    if (!q.trim() && (!activeCat || activeCat === 'all')) return
    const next = new Set(expanded)
    const walk = (node) => {
      if (!node.dir) return
      if (nodePasses(node, { catSet, query: q })) next.add(node.path)
      ;(node.children || []).forEach(walk)
    }
    ;(tree.children || []).forEach(walk)
    setExpanded(next)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, activeCat])

  // ── Follow a finding "Open Source" jump: expand to + select the file ──────────
  const lastToken = useRef(null)
  useEffect(() => {
    const t = nav.explorerTarget
    if (!t || t.token === lastToken.current) return
    lastToken.current = t.token
    const match = resolveManifestPath(t.path, paths) || t.path
    setSelected(match)
    setExpanded(prev => {
      const next = new Set(prev)
      ancestorsOf(match).forEach(a => next.add(a))
      persist(next)
      return next
    })
  }, [nav.explorerTarget, paths, persist])

  const fileCount = paths.filter(p => !p.endsWith('/')).length
  const breadcrumb = selected ? normalizePath(selected).split('/') : []

  // Count files that survive the active search/category filter, so we can show an
  // explicit "no matches" state instead of a silently-empty tree.
  const queryLc = q.trim().toLowerCase()
  const visibleFileCount = (queryLc || filtered)
    ? paths.filter(p => !p.endsWith('/')).filter(p => {
        const np = normalizePath(p)
        if (catSet && !catSet.has(np)) return false
        if (queryLc && !np.split('/').pop().toLowerCase().includes(queryLc)) return false
        return true
      }).length
    : fileCount

  return (
    <div className="ws-ex">
      <div className="ws-section__head">
        <h1>Source Explorer</h1>
        <span className="ws-muted">{fileCount} files{filtered ? ` · filtered: ${activeCat}` : ''}</span>
      </div>

      {/* Quick Filters — convenience shortcuts that drive the SAME security filter as
          the Security Explorer pane (no separate filtering system). */}
      <div className="ws-ex-quick" role="tablist" aria-label="Quick filters">
        {QUICK_FILTERS.map(f => {
          const count = f.id === 'all' ? fileCount
            : f.id === 'findings' ? Object.keys(fileIndex).length
            : (securityIndex[f.id] || []).length
          const disabled = f.future || (f.id !== 'all' && !count)
          const active = activeCat === f.id
          return (
            <button key={f.id} type="button" role="tab" aria-selected={active}
              disabled={disabled}
              title={f.future ? `${f.label} — coming soon` : f.label}
              className={`ws-ex-quick__btn${active ? ' is-active' : ''}${f.future ? ' is-future' : ''}`}
              onClick={() => !disabled && setActiveCat(f.id)}>
              {f.label}
              {!f.future && count ? <span className="ws-ex-quick__n">{count}</span> : null}
              {f.future ? <span className="ws-ex-quick__soon">soon</span> : null}
            </button>
          )
        })}
        {/* Future-ready extension seams (no implementation yet) — Bookmarks, Notes,
            Compare Scans, AI Review, Semgrep Results. Enabling one is flipping its
            registry status + wiring the matching `extensions` handler. */}
        <span className="ws-ex-quick__sep" aria-hidden="true" />
        {EXPLORER_EXTENSIONS.map(ext => {
          const handler = extensions && extensions[ext.id]
          const planned = !handler && ext.status === 'planned'
          return (
            <button key={ext.id} type="button" disabled={planned}
              title={planned ? `${ext.label} — coming soon` : ext.label}
              className={`ws-ex-quick__btn ws-ex-quick__ext${planned ? ' is-future' : ''}`}
              onClick={() => handler && handler({ scanId, results, selected })}>
              {ext.label}
              {planned ? <span className="ws-ex-quick__soon">soon</span> : null}
            </button>
          )
        })}
      </div>

      <div className="ws-ex-layout">
        {/* ── Security Explorer pane ── */}
        <aside className="ws-ex-security">
          <div className="ws-ex-security__title">Security Explorer</div>
          <button type="button" className={`ws-ex-cat${!filtered ? ' is-active' : ''}`}
            onClick={() => setActiveCat('all')}>
            <span className="ws-ex-cat__name">All files</span>
            <span className="ws-ex-cat__count">{fileCount}</span>
          </button>
          {SEC_CATS.map(([id, label, Icon]) => {
            const n = (securityIndex[id] || []).length
            return (
              <button key={id} type="button" disabled={!n}
                className={`ws-ex-cat${activeCat === id ? ' is-active' : ''}${!n ? ' is-empty' : ''}`}
                onClick={() => setActiveCat(activeCat === id ? 'all' : id)}>
                <Icon size={13} className="ws-ex-cat__icon" />
                <span className="ws-ex-cat__name">{label}</span>
                <span className="ws-ex-cat__count">{n}</span>
              </button>
            )
          })}
        </aside>

        {/* ── Tree pane ── */}
        <div className="ws-ex-main">
          <div className="ws-ex-toolbar">
            <Search size={14} className="ws-muted" />
            <input className="ws-input" placeholder="Search files (name, path)…" value={q}
              onChange={e => setQ(e.target.value)} />
            {selected ? (
              <div className="ws-ex-crumb" title={selected}>
                {breadcrumb.map((seg, i) => (
                  <span key={i} className="ws-ex-crumb__seg">{seg}{i < breadcrumb.length - 1 ? <ChevronRight size={11} /> : null}</span>
                ))}
              </div>
            ) : null}
          </div>

          {manifestLoading && !paths.length
            ? <div className="ws-ex-loading ws-muted" style={{ padding: '24px 4px', fontSize: 13 }}>Loading project files…</div> : null}
          {!manifestLoading && err && !paths.length ? <EmptyState title="Source unavailable" body={err} /> : null}
          {!manifestLoading && !err && !paths.length ? <EmptyState title="No source files" body="No decompiled source is available for this scan." /> : null}
          {paths.length > 0 && visibleFileCount === 0 ? (
            <EmptyState
              title="No files match"
              body={queryLc
                ? `No files match “${q.trim()}”${filtered ? ` in ${activeCat}` : ''}.`
                : `No files in the ${activeCat} category.`}
            />
          ) : null}

          {visibleFileCount > 0 ? (
            <div className="ws-ex-tree">
              {(tree.children || []).map((c, i) => (
                <TreeNode key={c.path || i} node={c} depth={0} expanded={expanded}
                  toggle={toggle} onOpen={open} overlay={overlay}
                  filters={{ catSet, query: q }} selected={selected} />
              ))}
            </div>
          ) : null}
          <p className="ws-muted" style={{ marginTop: 10, fontSize: 12 }}>
            Click a file to open it in the viewer (search within, jump between matches, copy).
            Finding evidence links auto-expand the tree and jump to the exact line.
          </p>
        </div>
      </div>
    </div>
  )
}

export default SourceExplorerPanel

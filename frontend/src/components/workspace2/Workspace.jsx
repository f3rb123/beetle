// Analyst Workspace shell (Phase 1.99 — Analyst Workstation foundation).
//
// The shell is now DATA-DRIVEN: navigation and section dispatch derive from the
// panel registry (workspace-registry.js), and all navigation flows through the
// workspace context (workspace-context.jsx). Adding a panel — including the roadmap
// Source Explorer / AI Reviewer / Security Controls / Framework views — is a
// registry entry + a renderer, with no shell refactor. Roadmap panels are already
// navigable (they open a ComingSoon placeholder), which proves the hierarchy,
// routing and layout accommodate them.
import { useEffect, useMemo, useRef, useState } from 'react'
import {
  LayoutDashboard, ShieldAlert, GitBranch, KeyRound, ShieldCheck, FileCode2,
  Download, Search, ChevronLeft, Command, ScrollText, Network, Fingerprint,
  Boxes, Cpu, Bug, GitCompare, Sparkles, FolderTree, Lock, ShieldHalf, Workflow,
  Briefcase, Wrench, MessageSquare, Binary, Rocket,
} from 'lucide-react'
import beetleIcon from '../../assets/beetle-icon.png'
import {
  OverviewPanel, FindingsPanel, FindingDrawer, ChainsPanel, SecretsPanel,
  MasvsPanel, FilesPanel, ExportsPanel,
} from './panels.jsx'
import {
  CertificatePanel, NetworkPanel, ManifestPanel, ComponentsPanel, AndroidApiPanel,
  MalwarePanel, ComparePanel, AiAssistantPanel, CodeBrowserPanel,
  PermissionsPanel, AndroidPosturePanel, TaintFlowPanel,
  CisoSummaryPanel, DeveloperGuidePanel, AskAiPanel,
} from './panels2.jsx'
import { findingPath, useEscape } from './ui.jsx'
import { useCollab, canManage, SHARE_MODES } from '../../lib/collab.js'
import { navGroups, getPanel, isReady } from './workspace-registry.js'
import { WorkspaceProvider, useWorkspaceNav } from './workspace-context.jsx'

// Registry icon-name → lucide component (keeps the registry React-free/testable).
const ICON_MAP = {
  LayoutDashboard, ShieldAlert, GitBranch, KeyRound, ShieldCheck, FileCode2,
  Download, ScrollText, Network, Fingerprint, Boxes, Cpu, Bug, GitCompare,
  Sparkles, FolderTree, Lock, ShieldHalf, Workflow, Briefcase, Wrench,
  MessageSquare, Binary,
}
const iconFor = name => ICON_MAP[name] || ShieldAlert

// Deep-analysis panels keep their existing nav group; they're appended to the
// registry-derived groups so the (large) list stays where analysts expect it.
const DEEP_ANALYSIS = [
  { id: 'manifest', label: 'Manifest', icon: ScrollText },
  { id: 'permissions', label: 'Permissions', icon: Lock },
  { id: 'network', label: 'Network', icon: Network },
  { id: 'certificate', label: 'Certificate', icon: Fingerprint },
  { id: 'androidsec', label: 'Android Security', icon: ShieldHalf },
  { id: 'components', label: 'Components', icon: Boxes },
  { id: 'androidapis', label: 'Android APIs', icon: Cpu },
  { id: 'taint', label: 'Taint Flows', icon: Workflow },
  { id: 'malware', label: 'Malware Analysis', icon: Bug },
  { id: 'codebrowser', label: 'Code Browser', icon: FolderTree },
  { id: 'compare', label: 'Compare', icon: GitCompare },
  { id: 'ai', label: 'AI Assistant', icon: Sparkles },
]

// Build the sidebar groups: registry groups (Workspace / Audience / Source /
// Reviewer) with resolved icons, then the Deep Analysis group.
function useNavGroups() {
  return useMemo(() => {
    const groups = navGroups({ includePlanned: true }).map(g => ({
      label: g.label,
      items: g.items.map(p => ({ id: p.id, label: p.label, icon: iconFor(p.icon),
        count: p.count, planned: p.status === 'planned' })),
    }))
    groups.push({ label: 'Deep Analysis', items: DEEP_ANALYSIS })
    return groups
  }, [])
}

// Roadmap placeholder for a planned panel — proves routing reaches it before the
// feature exists. Implementing the feature flips its registry status to 'ready'.
function ComingSoonPanel({ panelId }) {
  const p = getPanel(panelId) || {}
  return (
    <div className="ws-coming">
      <Rocket size={28} className="ws-muted" />
      <h2>{p.roadmap || p.label || 'Coming soon'}</h2>
      <p className="ws-muted">{p.blurb || 'This analyst surface is on the roadmap.'}</p>
      <span className="ws-badge">Planned</span>
    </div>
  )
}

function ShareControl({ collab }) {
  const mode = collab.collab.share?.share_mode || 'team'
  if (!canManage()) {
    return <span className="ws-pill ws-pill--ok" title="Workspace visibility" style={{ textTransform: 'none' }}>● {mode}</span>
  }
  return (
    <select className="ws-input" style={{ width: 'auto', padding: '4px 8px' }} value={mode}
      title="Workspace visibility" onChange={e => collab.setShare(e.target.value)}>
      {SHARE_MODES.map(m => <option key={m.id} value={m.id}>{m.label}</option>)}
    </select>
  )
}

// ── Global search palette ──────────────────────────────────────────────────
function SearchPalette({ index, onClose, onPick }) {
  const [q, setQ] = useState('')
  const inputRef = useRef(null)
  useEscape(onClose)
  useEffect(() => { inputRef.current?.focus() }, [])

  const groups = useMemo(() => {
    const ql = q.trim().toLowerCase()
    if (!ql) return index.slice(0, 7)
    return index.map(g => ({
      ...g, items: g.items.filter(it => it.text.toLowerCase().includes(ql)).slice(0, 6),
    })).filter(g => g.items.length)
  }, [q, index])

  return (
    <div className="ws-palette-backdrop" onClick={onClose}>
      <div className="ws-palette" onClick={e => e.stopPropagation()}>
        <input ref={inputRef} className="ws-palette__input" placeholder="Search findings, files, packages, secrets, MASVS, chains…"
          value={q} onChange={e => setQ(e.target.value)} />
        <div className="ws-palette__results">
          {groups.length ? groups.map(g => (
            <div key={g.group}>
              <div className="ws-palette__group">{g.group}</div>
              {g.items.map((it, i) => (
                <div key={i} className="ws-palette__item" onClick={() => { onPick(it); onClose() }}>
                  <it.icon size={15} className="ws-muted" />
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{it.text}</span>
                  <span className="ws-mono">{g.group}</span>
                </div>
              ))}
            </div>
          )) : <div className="ws-palette__empty">No matches for “{q}”.</div>}
        </div>
      </div>
    </div>
  )
}

// ── Shell (consumes the workspace context) ───────────────────────────────────
function WorkspaceShell({ results, scanId, actions }) {
  const nav = useWorkspaceNav()
  const { section, finding } = nav
  const onOpenCode = nav._onOpenCode
  const [searchOpen, setSearchOpen] = useState(false)
  const scrollRef = useRef(null)
  const collab = useCollab(scanId)
  const groups = useNavGroups()

  useEffect(() => {
    const h = e => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setSearchOpen(true) }
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [])

  const goSection = id => { nav.openSection(id); scrollRef.current?.scrollTo({ top: 0 }) }

  const counts = useMemo(() => {
    const findings = results.findings || []
    return {
      findings: findings.length,
      chains: (results.cloud_attack_paths || []).length + findings.filter(f => f.is_attack_chain).length,
      secrets: (results.secrets || []).length,
      masvs: (results.masvs_coverage || []).length,
      files: new Set(findings.map(findingPath).filter(Boolean)).size,
      developer: (results.developer_summary?.groups || []).length,
    }
  }, [results])

  const searchIndex = useMemo(() => {
    const findings = results.findings || []
    const idx = []
    if (findings.length) idx.push({ group: 'Findings', items: findings.slice(0, 200).map(f => ({ text: f.title || f.name, icon: ShieldAlert, go: 'findings', finding: f })) })
    const files = [...new Set(findings.map(findingPath).filter(Boolean))]
    if (files.length) idx.push({ group: 'Files', items: files.map(p => ({ text: p, icon: FileCode2, go: 'files' })) })
    const pkgs = [...new Set(findings.map(f => f.owner_package).filter(Boolean))]
    if (pkgs.length) idx.push({ group: 'Packages', items: pkgs.map(p => ({ text: p, icon: FileCode2, go: 'findings' })) })
    const secrets = results.secrets || []
    if (secrets.length) idx.push({ group: 'Secrets', items: secrets.map(s => ({ text: s.name || s.type || s.provider, icon: KeyRound, go: 'secrets' })) })
    const masvs = results.masvs_coverage || []
    if (masvs.length) idx.push({ group: 'MASVS', items: masvs.map(m => ({ text: `${m.category} — ${m.maturity}`, icon: ShieldCheck, go: 'masvs' })) })
    const chains = results.cloud_attack_paths || []
    if (chains.length) idx.push({ group: 'Chains', items: chains.map(c => ({ text: c.title, icon: GitBranch, go: 'chains' })) })
    return idx
  }, [results])

  const onPick = it => {
    if (it.go) goSection(it.go)
    if (it.finding) setTimeout(() => nav.openFinding(it.finding), 60)
  }

  // Section dispatch — ready panels render their component; planned panels render
  // the roadmap placeholder. A future panel adds one case (or we move to a map).
  const renderPanel = () => {
    if (!isReady(section)) {
      const known = getPanel(section)
      const deep = DEEP_ANALYSIS.find(d => d.id === section)
      if (known && !deep) return <ComingSoonPanel panelId={section} />
    }
    switch (section) {
      case 'overview': return <OverviewPanel results={results} onOpenSection={goSection} onOpenFinding={nav.openFinding} onOpenCode={onOpenCode} />
      case 'findings': return <FindingsPanel results={results} onOpenFinding={nav.openFinding} onOpenCode={onOpenCode} collab={collab} />
      case 'chains': return <ChainsPanel results={results} onOpenCode={onOpenCode} />
      case 'secrets': return <SecretsPanel results={results} onOpenCode={onOpenCode} />
      case 'masvs': return <MasvsPanel results={results} />
      case 'askai': return <AskAiPanel results={results} scanId={scanId} />
      case 'ciso': return <CisoSummaryPanel results={results} onOpenSection={goSection} />
      case 'developer': return <DeveloperGuidePanel results={results} onOpenCode={onOpenCode} />
      case 'files': return <FilesPanel results={results} onOpenCode={onOpenCode} />
      case 'exports': return <ExportsPanel actions={actions} results={results} />
      case 'manifest': return <ManifestPanel results={results} />
      case 'permissions': return <PermissionsPanel results={results} onOpenCode={onOpenCode} />
      case 'network': return <NetworkPanel results={results} />
      case 'certificate': return <CertificatePanel results={results} />
      case 'androidsec': return <AndroidPosturePanel results={results} />
      case 'components': return <ComponentsPanel results={results} />
      case 'androidapis': return <AndroidApiPanel results={results} onOpenCode={onOpenCode} />
      case 'taint': return <TaintFlowPanel results={results} onOpenCode={onOpenCode} />
      case 'malware': return <MalwarePanel results={results} />
      case 'codebrowser': return <CodeBrowserPanel results={results} scanId={scanId} onOpenCode={onOpenCode} />
      case 'compare': return <ComparePanel results={results} />
      case 'ai': return <AiAssistantPanel results={results} />
      default: return <ComingSoonPanel panelId={section} />
    }
  }

  const allItems = groups.flatMap(g => g.items)
  const active = allItems.find(s => s.id === section) || allItems[0]

  return (
    <div className="ws">
      <div className="ws-shell">
        <aside className="ws-sidebar">
          <div className="ws-sidebar__brand">
            <img src={beetleIcon} alt="" />
            <div><b>Beetle</b><span>{results.app_name || 'Security Analysis'}</span></div>
          </div>
          <nav className="ws-nav">
            {groups.map(group => (
              <div key={group.label} className="ws-nav__group">
                <div className="ws-nav__grouplabel">{group.label}</div>
                {group.items.map(s => {
                  const Icon = s.icon
                  const n = counts[s.count || s.id]
                  return (
                    <button key={s.id} type="button"
                      className={`ws-nav__item${s.id === section ? ' is-active' : ''}${s.planned ? ' ws-nav__item--planned' : ''}`}
                      onClick={() => goSection(s.id)}>
                      <Icon size={16} />
                      <span className="ws-nav__label">{s.label}</span>
                      {s.planned ? <span className="ws-nav__soon">soon</span> : (n ? <span className="ws-nav__count">{n}</span> : null)}
                    </button>
                  )
                })}
              </div>
            ))}
          </nav>
          <div className="ws-sidebar__foot">Beetle · Analyst Workspace</div>
        </aside>

        <div className="ws-main">
          <header className="ws-topbar">
            <button type="button" className="ws-btn" onClick={actions.onHome} title="Back home"><ChevronLeft size={15} /> Home</button>
            <div className="ws-topbar__title">{active?.label}</div>
            <div className="ws-topbar__spacer" />
            <button type="button" className="ws-search-trigger" onClick={() => setSearchOpen(true)}>
              <Search size={14} /> Search workspace
              <kbd><Command size={10} style={{ verticalAlign: '-1px' }} />K</kbd>
            </button>
            <ShareControl collab={collab} />
            <button type="button" className="ws-btn ws-btn--primary" onClick={actions.onExport}><Download size={14} /> Export</button>
            {actions.user ? <button type="button" className="ws-btn" onClick={actions.onSignOut} title="Sign out">{actions.user}</button> : null}
          </header>

          {/* Layout regions: a primary region today; the secondary region is reserved
              (CSS-ready, collapsed) for the docked Source Explorer / side-by-side
              comparison panes the roadmap will mount — see EVIDENCE_UI_WORKSPACE.md. */}
          <div className="ws-content" ref={scrollRef}>
            <div className="ws-workspace">
              <section className="ws-region ws-region--primary">{renderPanel()}</section>
            </div>
          </div>
        </div>
      </div>

      {finding ? <FindingDrawer finding={finding} onClose={nav.closeFinding} onOpenCode={onOpenCode} collab={collab} /> : null}
      {searchOpen ? <SearchPalette index={searchIndex} onClose={() => setSearchOpen(false)} onPick={onPick} /> : null}
    </div>
  )
}

export default function Workspace({ results, scanId, onOpenCode, actions }) {
  return (
    <WorkspaceProvider onOpenCode={onOpenCode}>
      <WorkspaceShell results={results} scanId={scanId} actions={actions} />
    </WorkspaceProvider>
  )
}

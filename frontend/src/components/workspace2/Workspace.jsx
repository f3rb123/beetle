// Phase 13 — Explainable Security Workspace shell. Presentation only; reuses the
// already-loaded `results` blob and the host's openCode/export/CI plumbing.
import { useEffect, useMemo, useRef, useState } from 'react'
import {
  LayoutDashboard, ShieldAlert, GitBranch, KeyRound, ShieldCheck, FileCode2,
  Download, Search, ChevronLeft, Command, ScrollText, Network, Fingerprint,
  Boxes, Cpu, Bug, GitCompare, Sparkles, FolderTree, Lock, ShieldHalf, Workflow,
  Briefcase, Wrench, MessageSquare,
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
import { severityCounts, findingPath, useEscape } from './ui.jsx'
import { useCollab, canManage, SHARE_MODES } from '../../lib/collab.js'

// Workspace-level sharing control (point 6). Managers/admins can change the
// mode; everyone else sees the current mode read-only.
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

const NAV_GROUPS = [
  {
    label: 'Workspace', items: [
      { id: 'overview', label: 'Overview', icon: LayoutDashboard },
      { id: 'findings', label: 'Findings', icon: ShieldAlert },
      { id: 'chains', label: 'Attack Chains', icon: GitBranch },
      { id: 'secrets', label: 'Secrets', icon: KeyRound },
      { id: 'masvs', label: 'MASVS Coverage', icon: ShieldCheck },
      { id: 'askai', label: 'Ask AI', icon: MessageSquare },
      { id: 'files', label: 'Files', icon: FileCode2 },
      { id: 'exports', label: 'Exports', icon: Download },
    ],
  },
  {
    label: 'Audience Reports', items: [
      { id: 'ciso', label: 'CISO Summary', icon: Briefcase },
      { id: 'developer', label: 'Developer Guide', icon: Wrench },
    ],
  },
  {
    label: 'Deep Analysis', items: [
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
    ],
  },
]
const SECTIONS = NAV_GROUPS.flatMap(g => g.items)

// ── Global search palette ──────────────────────────────────────────────────
function SearchPalette({ index, onClose, onPick }) {
  const [q, setQ] = useState('')
  const inputRef = useRef(null)
  useEscape(onClose)
  useEffect(() => { inputRef.current?.focus() }, [])

  const groups = useMemo(() => {
    const ql = q.trim().toLowerCase()
    if (!ql) return index.slice(0, 7)
    const matched = index.map(g => ({
      ...g, items: g.items.filter(it => it.text.toLowerCase().includes(ql)).slice(0, 6),
    })).filter(g => g.items.length)
    return matched
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

export default function Workspace({ results, scanId, onOpenCode, actions }) {
  const [section, setSection] = useState('overview')
  const [drawer, setDrawer] = useState(null)
  const [searchOpen, setSearchOpen] = useState(false)
  const scrollRef = useRef(null)
  const collab = useCollab(scanId)

  // Cmd/Ctrl+K opens search
  useEffect(() => {
    const h = e => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setSearchOpen(true) }
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [])

  // Preserve scroll position when opening the drawer (no layout shift).
  const openFinding = f => setDrawer(f)

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
    if (it.go) setSection(it.go)
    if (it.finding) setTimeout(() => setDrawer(it.finding), 60)
  }

  const active = SECTIONS.find(s => s.id === section) || SECTIONS[0]
  const info = results.app_info || {}

  return (
    <div className="ws">
      <div className="ws-shell">
        <aside className="ws-sidebar">
          <div className="ws-sidebar__brand">
            <img src={beetleIcon} alt="" />
            <div><b>Beetle</b><span>{results.app_name || 'Security Analysis'}</span></div>
          </div>
          <nav className="ws-nav">
            {NAV_GROUPS.map(group => (
              <div key={group.label} className="ws-nav__group">
                <div className="ws-nav__grouplabel">{group.label}</div>
                {group.items.map(s => {
                  const Icon = s.icon
                  const n = counts[s.id]
                  return (
                    <button key={s.id} type="button" className={`ws-nav__item${s.id === section ? ' is-active' : ''}`}
                      onClick={() => { setSection(s.id); scrollRef.current?.scrollTo({ top: 0 }) }}>
                      <Icon size={16} />
                      <span className="ws-nav__label">{s.label}</span>
                      {n ? <span className="ws-nav__count">{n}</span> : null}
                    </button>
                  )
                })}
              </div>
            ))}
          </nav>
          <div className="ws-sidebar__foot">Beetle · Explainable Security Workspace</div>
        </aside>

        <div className="ws-main">
          <header className="ws-topbar">
            <button type="button" className="ws-btn" onClick={actions.onHome} title="Back home"><ChevronLeft size={15} /> Home</button>
            <div className="ws-topbar__title">{active.label}</div>
            <div className="ws-topbar__spacer" />
            <button type="button" className="ws-search-trigger" onClick={() => setSearchOpen(true)}>
              <Search size={14} /> Search workspace
              <kbd><Command size={10} style={{ verticalAlign: '-1px' }} />K</kbd>
            </button>
            <ShareControl collab={collab} />
            <button type="button" className="ws-btn ws-btn--primary" onClick={actions.onExport}><Download size={14} /> Export</button>
            {actions.user ? <button type="button" className="ws-btn" onClick={actions.onSignOut} title="Sign out">{actions.user}</button> : null}
          </header>

          <div className="ws-content" ref={scrollRef}>
            {section === 'overview' && <OverviewPanel results={results} onOpenSection={setSection} onOpenFinding={openFinding} onOpenCode={onOpenCode} />}
            {section === 'findings' && <FindingsPanel results={results} onOpenFinding={openFinding} onOpenCode={onOpenCode} collab={collab} />}
            {section === 'chains' && <ChainsPanel results={results} />}
            {section === 'secrets' && <SecretsPanel results={results} onOpenCode={onOpenCode} />}
            {section === 'masvs' && <MasvsPanel results={results} />}
            {section === 'askai' && <AskAiPanel results={results} scanId={scanId} />}
            {section === 'ciso' && <CisoSummaryPanel results={results} onOpenSection={setSection} />}
            {section === 'developer' && <DeveloperGuidePanel results={results} onOpenCode={onOpenCode} />}
            {section === 'files' && <FilesPanel results={results} onOpenCode={onOpenCode} />}
            {section === 'exports' && <ExportsPanel actions={actions} results={results} />}
            {section === 'manifest' && <ManifestPanel results={results} />}
            {section === 'permissions' && <PermissionsPanel results={results} onOpenCode={onOpenCode} />}
            {section === 'network' && <NetworkPanel results={results} />}
            {section === 'certificate' && <CertificatePanel results={results} />}
            {section === 'androidsec' && <AndroidPosturePanel results={results} />}
            {section === 'components' && <ComponentsPanel results={results} />}
            {section === 'androidapis' && <AndroidApiPanel results={results} onOpenCode={onOpenCode} />}
            {section === 'taint' && <TaintFlowPanel results={results} onOpenCode={onOpenCode} />}
            {section === 'malware' && <MalwarePanel results={results} />}
            {section === 'codebrowser' && <CodeBrowserPanel results={results} scanId={scanId} onOpenCode={onOpenCode} />}
            {section === 'compare' && <ComparePanel results={results} />}
            {section === 'ai' && <AiAssistantPanel results={results} />}
          </div>
        </div>
      </div>

      {drawer ? <FindingDrawer finding={drawer} onClose={() => setDrawer(null)} onOpenCode={onOpenCode} collab={collab} /> : null}
      {searchOpen ? <SearchPalette index={searchIndex} onClose={() => setSearchOpen(false)} onPick={onPick} /> : null}
    </div>
  )
}

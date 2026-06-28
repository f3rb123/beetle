// Phase 1.99 — Analyst Workspace panel registry (pure, no React).
//
// THE single declarative catalog of workspace panels. The shell (Workspace.jsx)
// derives its navigation and its section dispatch from this list instead of a
// hardcoded array + if-chain, so a future phase adds a panel by adding ONE entry
// here (+ a renderer) — no shell refactor.
//
// It also DECLARES the upcoming roadmap panels with status:'planned'. They are real
// navigable routes today (they open a "coming soon" placeholder), which proves the
// hierarchy/routing already accommodates them; implementing one later just flips its
// status to 'ready' and registers a renderer.
//
// `icon` is a string key resolved to a lucide component by the shell, so this module
// stays free of React/JSX and is unit-testable under plain Node.

export const STATUS_READY = 'ready'
export const STATUS_PLANNED = 'planned'

// Group order is the nav order. New groups (Source, Reviewer) exist now so roadmap
// panels have a home the moment they ship.
export const GROUP_ORDER = ['Workspace', 'Audience Reports', 'Source', 'Reviewer', 'Deep Analysis']

export const PANELS = [
  // ── Workspace (ready) ──────────────────────────────────────────────────────
  { id: 'overview', label: 'Overview', group: 'Workspace', icon: 'LayoutDashboard', status: STATUS_READY },
  { id: 'findings', label: 'Findings', group: 'Workspace', icon: 'ShieldAlert', status: STATUS_READY, count: 'findings' },
  { id: 'chains', label: 'Attack Chains', group: 'Workspace', icon: 'GitBranch', status: STATUS_READY, count: 'chains' },
  { id: 'secrets', label: 'Secrets', group: 'Workspace', icon: 'KeyRound', status: STATUS_READY, count: 'secrets' },
  { id: 'masvs', label: 'MASVS Coverage', group: 'Workspace', icon: 'ShieldCheck', status: STATUS_READY, count: 'masvs' },
  { id: 'askai', label: 'Ask AI', group: 'Workspace', icon: 'MessageSquare', status: STATUS_READY },
  { id: 'files', label: 'Files', group: 'Workspace', icon: 'FileCode2', status: STATUS_READY, count: 'files' },
  { id: 'exports', label: 'Exports', group: 'Workspace', icon: 'Download', status: STATUS_READY },

  // ── Audience Reports (ready) ───────────────────────────────────────────────
  { id: 'ciso', label: 'CISO Summary', group: 'Audience Reports', icon: 'Briefcase', status: STATUS_READY },
  { id: 'developer', label: 'Developer Guide', group: 'Audience Reports', icon: 'Wrench', status: STATUS_READY, count: 'developer' },

  // ── Source (roadmap — Reverse Engineering Workspace) ───────────────────────
  { id: 'source-java', label: 'Java Explorer', group: 'Source', icon: 'FolderTree', status: STATUS_PLANNED,
    roadmap: 'Java Source Explorer', blurb: 'A JADX-style decompiled-source tree with in-place evidence highlighting and cross-navigation from findings.' },
  { id: 'source-smali', label: 'Smali Explorer', group: 'Source', icon: 'Binary', status: STATUS_PLANNED,
    roadmap: 'Smali Explorer', blurb: 'Browse the smali/bytecode tree and jump between a finding, its Java source and its smali.' },

  // ── Reviewer (roadmap) ─────────────────────────────────────────────────────
  { id: 'evidence-compare', label: 'Evidence Compare', group: 'Reviewer', icon: 'GitCompare', status: STATUS_PLANNED,
    roadmap: 'Side-by-side Evidence Comparison', blurb: 'Pin two findings or two proofs side by side to compare evidence, ownership and confidence.' },
  { id: 'ai-reviewer', label: 'AI Reviewer', group: 'Reviewer', icon: 'Sparkles', status: STATUS_PLANNED,
    roadmap: 'AI Reviewer Panel', blurb: 'A dedicated reviewer surface where an AI agent triages findings against the selected evidence.' },
  { id: 'security-controls', label: 'Security Controls', group: 'Reviewer', icon: 'ShieldHalf', status: STATUS_PLANNED,
    roadmap: 'Security Controls Dashboard', blurb: 'A controls posture board (crypto, network, storage, platform) rolled up from coverage + findings.' },
  { id: 'framework-view', label: 'Framework View', group: 'Reviewer', icon: 'Boxes', status: STATUS_PLANNED,
    roadmap: 'Framework-specific Views', blurb: 'Flutter / React Native specific lenses (bundle, native libs, framework secrets).' },
]

const _byId = Object.fromEntries(PANELS.map(p => [p.id, p]))

export function getPanel(id) { return _byId[id] || null }
export function readyPanels() { return PANELS.filter(p => p.status === STATUS_READY) }
export function plannedPanels() { return PANELS.filter(p => p.status === STATUS_PLANNED) }
export function isReady(id) { return _byId[id]?.status === STATUS_READY }
export function isPlanned(id) { return _byId[id]?.status === STATUS_PLANNED }

// Nav groups in GROUP_ORDER. `includePlanned` controls whether roadmap panels show
// (as disabled "soon" items). Empty groups are dropped.
export function navGroups({ includePlanned = true } = {}) {
  const groups = GROUP_ORDER.map(label => ({
    label,
    items: PANELS.filter(p => p.group === label && (includePlanned || p.status === STATUS_READY)),
  })).filter(g => g.items.length)
  return groups
}

export function roadmap() {
  return plannedPanels().map(p => ({ id: p.id, title: p.roadmap || p.label, blurb: p.blurb || '' }))
}

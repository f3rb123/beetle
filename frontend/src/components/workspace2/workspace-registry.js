// Analyst Workspace panel registry — the SINGLE declarative catalog of workspace
// panels (Phase 2.5.8 information-architecture pass).
//
// The shell (Workspace.jsx) derives BOTH its sidebar navigation and its section
// dispatch from this list, so a panel is added/renamed/regrouped by editing ONE
// entry here — no shell refactor. Every analysis surface lives here now (the old
// hardcoded "Deep Analysis" array in the shell was folded in), giving one place
// that owns the whole hierarchy.
//
// Groups follow the analyst workflow — Overview → Investigation → Static Analysis →
// Source → Reports → AI → Advanced — so navigation reads top-to-bottom the way an
// engagement actually proceeds. GROUP_ORDER is the nav order.
//
// `icon` is a string key resolved to a lucide component by the shell (ICON_MAP), so
// this module stays free of React/JSX and is unit-testable under plain Node.
//
// Planned (status:'planned') panels are real navigable routes today (they open a
// "coming soon" placeholder), proving the hierarchy already accommodates them;
// shipping one later flips its status to 'ready' and registers a renderer.

export const STATUS_READY = 'ready'
export const STATUS_PLANNED = 'planned'

export const GROUP_ORDER = [
  'Overview', 'Investigation', 'Static Analysis', 'Source', 'Reports', 'AI', 'Advanced',
]

export const PANELS = [
  // ── Overview — triage entry point ───────────────────────────────────────────
  { id: 'overview', label: 'Overview', group: 'Overview', icon: 'LayoutDashboard', status: STATUS_READY },
  { id: 'findings', label: 'Findings', group: 'Overview', icon: 'ShieldAlert', status: STATUS_READY, count: 'findings' },
  { id: 'chains', label: 'Attack Chains', group: 'Overview', icon: 'GitBranch', status: STATUS_READY, count: 'chains' },

  // ── Investigation — drill into concrete evidence ────────────────────────────
  { id: 'secrets', label: 'Secrets', group: 'Investigation', icon: 'KeyRound', status: STATUS_READY, count: 'secrets' },
  { id: 'network', label: 'Network', group: 'Investigation', icon: 'Network', status: STATUS_READY },
  { id: 'permissions', label: 'Permissions', group: 'Investigation', icon: 'Lock', status: STATUS_READY },
  { id: 'certificate', label: 'Certificates', group: 'Investigation', icon: 'Fingerprint', status: STATUS_READY },
  { id: 'components', label: 'Application Components', group: 'Investigation', icon: 'Boxes', status: STATUS_READY },
  { id: 'androidapis', label: 'Android APIs', group: 'Investigation', icon: 'Cpu', status: STATUS_READY },
  { id: 'manifest', label: 'Manifest', group: 'Investigation', icon: 'ScrollText', status: STATUS_READY },
  { id: 'malware', label: 'Malware Analysis', group: 'Investigation', icon: 'Bug', status: STATUS_READY },

  // ── Static Analysis — derived posture & coverage ────────────────────────────
  { id: 'masvs', label: 'MASVS Coverage', group: 'Static Analysis', icon: 'ShieldCheck', status: STATUS_READY, count: 'masvs' },
  { id: 'androidsec', label: 'Android Security', group: 'Static Analysis', icon: 'ShieldHalf', status: STATUS_READY },
  { id: 'taint', label: 'Data Flow Analysis', group: 'Static Analysis', icon: 'Workflow', status: STATUS_READY },
  { id: 'compare', label: 'Scan Compare', group: 'Static Analysis', icon: 'GitCompare', status: STATUS_READY },

  // ── Source — code exploration (Java/Smali are modes inside Source Explorer) ──
  { id: 'codebrowser', label: 'Source Explorer', group: 'Source', icon: 'FolderTree', status: STATUS_READY },
  { id: 'files', label: 'Project Files', group: 'Source', icon: 'FileCode2', status: STATUS_READY, count: 'files' },

  // ── Reports — audience-specific output ──────────────────────────────────────
  { id: 'ciso', label: 'CISO Summary', group: 'Reports', icon: 'Briefcase', status: STATUS_READY },
  { id: 'developer', label: 'Developer Report', group: 'Reports', icon: 'Wrench', status: STATUS_READY, count: 'developer' },
  { id: 'exports', label: 'Reports & Export', group: 'Reports', icon: 'Download', status: STATUS_READY },

  // ── AI — assistance surfaces (distinct: conversational vs one-shot actions) ──
  { id: 'askai', label: 'AI Assistant', group: 'AI', icon: 'MessageSquare', status: STATUS_READY },
  { id: 'ai', label: 'AI Actions', group: 'AI', icon: 'Sparkles', status: STATUS_READY },

  // ── Advanced — roadmap surfaces (navigable placeholders) ────────────────────
  { id: 'evidence-compare', label: 'Evidence Compare', group: 'Advanced', icon: 'GitCompare', status: STATUS_PLANNED,
    roadmap: 'Side-by-side Evidence Comparison', blurb: 'Pin two findings or two proofs side by side to compare evidence, ownership and confidence.' },
  { id: 'ai-reviewer', label: 'AI Reviewer', group: 'Advanced', icon: 'Sparkles', status: STATUS_PLANNED,
    roadmap: 'AI Reviewer Panel', blurb: 'A dedicated reviewer surface where an AI agent triages findings against the selected evidence.' },
  { id: 'security-controls', label: 'Security Controls', group: 'Advanced', icon: 'ShieldHalf', status: STATUS_PLANNED,
    roadmap: 'Security Controls Dashboard', blurb: 'A controls posture board (crypto, network, storage, platform) rolled up from coverage + findings.' },
  { id: 'framework-view', label: 'Framework Analysis', group: 'Advanced', icon: 'Boxes', status: STATUS_PLANNED,
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

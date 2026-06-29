// Phase 1.99 — Analyst Workspace state + navigation context.
//
// Centralizes the workspace's cross-cutting state (active section, open finding,
// comparison selection) and exposes a single NAVIGATION INTENT API. Every "go
// somewhere" action in the workspace flows through this seam:
//
//   nav.openSection(id)            switch the main panel
//   nav.openFinding(f)             open the finding details drawer
//   nav.closeFinding()
//   nav.openSource(path, lines, o) jump to decompiled source   ── source seam
//   nav.openSmali(path, lines, o)  jump to smali                ── source seam
//   nav.addToComparison(f) / removeFromComparison / clearComparison / comparison
//
// Why this matters for the roadmap: today openSource/openSmali delegate to the
// host's onOpenCode (the code modal). When the Java/Smali Source Explorer and the
// side-by-side comparison land, they re-target these SAME intents (e.g. into a
// docked pane) WITHOUT touching any call site — finding rows, evidence cards and
// chain steps already speak `nav`, not a specific viewer. That is the extensibility
// the workspace is being prepared for.
import { createContext, useContext, useMemo, useState, useCallback } from 'react'

const WorkspaceContext = createContext(null)

export function WorkspaceProvider({ children, initialSection = 'overview', onOpenCode, onScrollTop }) {
  const [section, setSection] = useState(initialSection)
  const [finding, setFinding] = useState(null)
  // Comparison selection — the foundation for side-by-side evidence comparison.
  const [comparison, setComparison] = useState([])
  // Source Explorer target (Phase 2.3): the file/line a "jump to source" intent last
  // pointed at. The Source Explorer subscribes to this to expand its tree to + select
  // the file. Carries a monotonically increasing token so repeat-opens still fire.
  const [explorerTarget, setExplorerTarget] = useState(null)

  const openSection = useCallback((id) => { setSection(id); onScrollTop?.() }, [onScrollTop])
  const openFinding = useCallback((f) => setFinding(f), [])
  const closeFinding = useCallback(() => setFinding(null), [])

  // "Review with AI" (Phase 2.5.10): replaces the standalone AI Reviewer page.
  // A finding row/drawer seeds a finding here and jumps to the AI Assistant, which
  // opens with that finding preloaded as context. token makes repeat-reviews fire.
  const [aiSeed, setAiSeed] = useState(null)
  const reviewWithAI = useCallback((f) => {
    if (!f) return
    setAiSeed({ finding: f, token: Date.now() })
    setFinding(null)
    setSection('askai')
    onScrollTop?.()
  }, [onScrollTop])
  const clearAiSeed = useCallback(() => setAiSeed(null), [])

  // Source seam — the single place "jump to source/smali" is defined. The `view`
  // hint is forward-compatible. Phase 2.3: these ALSO record an explorerTarget so the
  // Source Explorer's tree follows the same jump (non-disruptive: no section switch).
  const openSource = useCallback((path, lines = [], opts = {}) => {
    if (path) setExplorerTarget({ path, lines, opts, token: Date.now() })
    onOpenCode?.(path, lines, { ...opts, view: opts.view || 'java' })
  }, [onOpenCode])
  const openSmali = useCallback((path, lines = [], opts = {}) => {
    if (path) setExplorerTarget({ path, lines, opts, token: Date.now() })
    onOpenCode?.(path, lines, { ...opts, view: 'smali' })
  }, [onOpenCode])
  // Explicit "reveal in Source Explorer": switch to the explorer section AND target.
  const openInExplorer = useCallback((path, lines = [], opts = {}) => {
    if (path) setExplorerTarget({ path, lines, opts, token: Date.now() })
    setSection('codebrowser'); onScrollTop?.()
  }, [onScrollTop])

  const addToComparison = useCallback((f) => setComparison(c => (
    c.find(x => x === f) ? c : [...c, f].slice(-2)   // hold at most two for side-by-side
  )), [])
  const removeFromComparison = useCallback((f) => setComparison(c => c.filter(x => x !== f)), [])
  const clearComparison = useCallback(() => setComparison([]), [])

  const value = useMemo(() => ({
    section, finding, comparison, explorerTarget, aiSeed,
    openSection, openFinding, closeFinding, openSource, openSmali, openInExplorer,
    addToComparison, removeFromComparison, clearComparison, reviewWithAI, clearAiSeed,
    // Raw host hook for the rare consumer that needs it directly (kept internal).
    _onOpenCode: onOpenCode,
  }), [section, finding, comparison, explorerTarget, aiSeed, openSection, openFinding, closeFinding,
       openSource, openSmali, openInExplorer, addToComparison, removeFromComparison, clearComparison,
       reviewWithAI, clearAiSeed, onOpenCode])

  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>
}

// Hook. Safe to call outside a provider (returns a no-op nav) so a component can be
// rendered standalone or in tests without crashing.
export function useWorkspaceNav() {
  const ctx = useContext(WorkspaceContext)
  if (ctx) return ctx
  const noop = () => {}
  return {
    section: 'overview', finding: null, comparison: [], explorerTarget: null, aiSeed: null,
    openSection: noop, openFinding: noop, closeFinding: noop,
    openSource: noop, openSmali: noop, openInExplorer: noop,
    addToComparison: noop, removeFromComparison: noop, clearComparison: noop,
    reviewWithAI: noop, clearAiSeed: noop,
    _onOpenCode: null,
  }
}

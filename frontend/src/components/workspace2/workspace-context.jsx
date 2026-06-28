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

  const openSection = useCallback((id) => { setSection(id); onScrollTop?.() }, [onScrollTop])
  const openFinding = useCallback((f) => setFinding(f), [])
  const closeFinding = useCallback(() => setFinding(null), [])

  // Source seam — the single place "jump to source/smali" is defined. The `view`
  // hint is forward-compatible: the code modal ignores it today; the Source
  // Explorer will honor it tomorrow.
  const openSource = useCallback((path, lines = [], opts = {}) => {
    onOpenCode?.(path, lines, { ...opts, view: opts.view || 'java' })
  }, [onOpenCode])
  const openSmali = useCallback((path, lines = [], opts = {}) => {
    onOpenCode?.(path, lines, { ...opts, view: 'smali' })
  }, [onOpenCode])

  const addToComparison = useCallback((f) => setComparison(c => (
    c.find(x => x === f) ? c : [...c, f].slice(-2)   // hold at most two for side-by-side
  )), [])
  const removeFromComparison = useCallback((f) => setComparison(c => c.filter(x => x !== f)), [])
  const clearComparison = useCallback(() => setComparison([]), [])

  const value = useMemo(() => ({
    section, finding, comparison,
    openSection, openFinding, closeFinding, openSource, openSmali,
    addToComparison, removeFromComparison, clearComparison,
    // Raw host hook for the rare consumer that needs it directly (kept internal).
    _onOpenCode: onOpenCode,
  }), [section, finding, comparison, openSection, openFinding, closeFinding,
       openSource, openSmali, addToComparison, removeFromComparison, clearComparison, onOpenCode])

  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>
}

// Hook. Safe to call outside a provider (returns a no-op nav) so a component can be
// rendered standalone or in tests without crashing.
export function useWorkspaceNav() {
  const ctx = useContext(WorkspaceContext)
  if (ctx) return ctx
  const noop = () => {}
  return {
    section: 'overview', finding: null, comparison: [],
    openSection: noop, openFinding: noop, closeFinding: noop,
    openSource: noop, openSmali: noop,
    addToComparison: noop, removeFromComparison: noop, clearComparison: noop,
    _onOpenCode: null,
  }
}

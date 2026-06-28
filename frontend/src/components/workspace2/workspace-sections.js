// Pure URL → workspace-section resolution (no React/JSX) so it is unit-testable and
// shared by the shell. The router speaks the scan-data section vocabulary (e.g.
// `dashboard`), while the shell renders panel-registry ids (e.g. `overview`); this is
// the single bridge between the two. A launcher deep link such as Source Explorer →
// /scans/:id/codebrowser must resolve to a real panel instead of always Overview.
import { PANELS } from './workspace-registry.js'

// Deep-analysis section ids the shell renders in addition to the registry panels.
// MUST stay in sync with the DEEP_ANALYSIS array in Workspace.jsx (same ids).
export const DEEP_ANALYSIS_IDS = [
  'manifest', 'permissions', 'network', 'certificate', 'androidsec',
  'components', 'androidapis', 'taint', 'malware', 'codebrowser', 'compare', 'ai',
]

// Every section id the shell can actually render.
export const WORKSPACE_SECTION_IDS = new Set([
  ...PANELS.map(p => p.id),
  ...DEEP_ANALYSIS_IDS,
])

// Route section ids that differ in name from their workspace section.
export const URL_SECTION_ALIASES = { dashboard: 'overview' }

// Resolve a route :sectionId to the workspace section the shell opens on mount.
// Unknown ids fall back to Overview — matching the prior (URL-agnostic) behavior.
export function urlToWorkspaceSection(urlId) {
  if (!urlId) return 'overview'
  if (URL_SECTION_ALIASES[urlId]) return URL_SECTION_ALIASES[urlId]
  return WORKSPACE_SECTION_IDS.has(urlId) ? urlId : 'overview'
}

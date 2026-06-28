// Deep-link regression coverage (investigation launchers): a route :sectionId must
// resolve to the correct workspace panel — NOT always Overview — and the launcher
// targets must survive the Results page's section guards (default 'quick' view).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  urlToWorkspaceSection, WORKSPACE_SECTION_IDS, DEEP_ANALYSIS_IDS,
} from '../workspace-sections.js'
import { SECTION_IDS, QUICK_SECTION_IDS } from '../../../lib/scan-data.js'

const t = (name, fn) => test(name, fn)

t('dashboard route resolves to the Overview panel (unchanged post-scan behavior)', () => {
  assert.equal(urlToWorkspaceSection('dashboard'), 'overview')
})

t('Source/Security Explorer deep link resolves to the Source Explorer panel', () => {
  // Both explorers deep-link to codebrowser; it must resolve to itself, not Overview.
  assert.equal(urlToWorkspaceSection('codebrowser'), 'codebrowser')
})

t('Semgrep deep link resolves to the Findings panel', () => {
  assert.equal(urlToWorkspaceSection('findings'), 'findings')
})

t('missing or unknown sections fall back to Overview', () => {
  assert.equal(urlToWorkspaceSection(undefined), 'overview')
  assert.equal(urlToWorkspaceSection(''), 'overview')
  assert.equal(urlToWorkspaceSection('not-a-real-section'), 'overview')
})

t('codebrowser is a recognized renderable workspace section', () => {
  assert.ok(WORKSPACE_SECTION_IDS.has('codebrowser'))
  assert.ok(DEEP_ANALYSIS_IDS.includes('codebrowser'))
})

t('investigation deep-link targets survive the Results guards in quick view', () => {
  // Results redirects to /dashboard when :sectionId ∉ SECTION_IDS, and (in the
  // default 'quick' view) when ∉ QUICK_SECTION_IDS. The Source/Security Explorer
  // (codebrowser) and Semgrep (findings) targets must pass both to avoid bouncing
  // back to Overview.
  for (const section of ['codebrowser', 'findings']) {
    assert.ok(SECTION_IDS.includes(section), `${section} must be a known section`)
    assert.ok(QUICK_SECTION_IDS.has(section), `${section} must be quick-view visible`)
  }
})

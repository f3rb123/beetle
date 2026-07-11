// Drawer chain-evidence + ownership-label tests. Pure, runs under plain Node:
//   node frontend/src/components/workspace2/__tests__/drawer-and-ownership.test.mjs
//
// FIX 1 — the finding drawer's primary "View Code" for a chain finding must resolve
//         via chainViewerTarget (evidence_references / steps), NOT evidence[0] from
//         the stale generic path (which could be an excluded R-constant class).
// FIX 2 — ownership renders humanized (THIRD_PARTY_SDK / ThirdPartySDK → "Third-Party
//         SDK"), never the raw CamelCase enum ("Thirdpartysdk").
import assert from 'node:assert/strict'
import {
  chainEvidenceView, chainViewerTarget, humanizeOwnership,
} from '../evidence-model.js'

let pass = 0, fail = 0
const t = (name, fn) => { try { fn(); pass++; console.log('PASS ', name) } catch (e) { fail++; console.log('FAIL ', name, '—', e.message) } }

// ── FIX 1: chain drawer primary comes from chainViewerTarget, not evidence[0] ──
const CHAIN_FINDING = {
  is_attack_chain: true,
  title: 'Attack Chain: Hardcoded Secret / API Key Abuse',
  owner_type: 'Application',
  // Stale generic path — what evidence[0] / the old primary card would have used.
  file_path: 'sources/N0/a.java', line: 1,
  file_evidence: [{ path: 'sources/N0/a.java', lines: [1], snippet: 'public static final int f = 2130837504;' }],
  // The real, normalized chain evidence (R-constant class already excluded upstream).
  evidence_references: [{ file: 'sources/com/app/Keys.java', line: 42, evidence_id: 'EV-1' }],
  affected_files: ['sources/com/app/Keys.java'],
  steps: [
    { order: 1, title: 'Entry point', evidence: '' },
    { order: 2, title: 'A real secret is embedded', evidence: 'sources/com/app/Keys.java:42' },
  ],
}

t('chainEvidenceView primary targets the real evidence file:line, not N0/a.java', () => {
  const view = chainEvidenceView(CHAIN_FINDING)
  assert.ok(view, 'a chain with evidence resolves a view')
  assert.equal(view.primary.file, 'sources/com/app/Keys.java')
  assert.equal(view.primary.line, 42)
  assert.ok(!view.primary.file.includes('N0/a.java'), 'must not point at the stale R-constant class')
})

t('chainEvidenceView primary equals chainViewerTarget (single source of truth)', () => {
  const view = chainEvidenceView(CHAIN_FINDING)
  const target = chainViewerTarget(CHAIN_FINDING)
  assert.equal(view.primary.file, target.file)
  assert.equal(view.primary.line, target.line)
})

t('chainEvidenceView carries a Java language + application ownership on the primary', () => {
  const view = chainEvidenceView(CHAIN_FINDING)
  assert.equal(view.primary.language, 'Java')
  assert.equal(view.primary.owner_type, 'Application')
  assert.equal(view.inAttackChain, true)
  assert.equal(view.fallback, false)
})

t('chainEvidenceView returns null when the chain has no proof location', () => {
  assert.equal(chainEvidenceView({ is_attack_chain: true, title: 'x' }), null)
})

t('a member with only a file (no line) opens the file without a fabricated line', () => {
  const f = { is_attack_chain: true, affected_files: ['sources/com/app/Only.java'] }
  const view = chainEvidenceView(f)
  assert.equal(view.primary.file, 'sources/com/app/Only.java')
  assert.equal(view.primary.line, 0)  // 0 → viewer opens the file, no jump
})

// ── FIX 2: ownership humanization ─────────────────────────────────────────────
t('humanizeOwnership maps the finding_model snake_case label', () => {
  assert.equal(humanizeOwnership('THIRD_PARTY_SDK'), 'Third-Party SDK')
  assert.equal(humanizeOwnership('OPEN_SOURCE_LIBRARY'), 'Open-Source Lib')
  assert.equal(humanizeOwnership('ANDROID_FRAMEWORK'), 'Android Framework')
  assert.equal(humanizeOwnership('GOOGLE_SDK'), 'Google SDK')
  assert.equal(humanizeOwnership('GENERATED_CODE'), 'Generated')
  assert.equal(humanizeOwnership('APPLICATION'), 'Application')
  assert.equal(humanizeOwnership('UNKNOWN'), 'Unknown')
})

t('humanizeOwnership maps the Ownership Engine CamelCase enum', () => {
  // The exact "Thirdpartysdk" overflow bug — the raw owner_type enum.
  assert.equal(humanizeOwnership('ThirdPartySDK'), 'Third-Party SDK')
  assert.equal(humanizeOwnership('OpenSourceLibrary'), 'Open-Source Lib')
  assert.equal(humanizeOwnership('GoogleSDK'), 'Google SDK')
  assert.equal(humanizeOwnership('Application'), 'Application')
})

t('humanizeOwnership never returns the jammed CamelCase enum', () => {
  assert.notEqual(humanizeOwnership('ThirdPartySDK'), 'Thirdpartysdk')
  assert.ok(humanizeOwnership('ThirdPartySDK').includes(' '), 'humanized label has word breaks')
})

t('humanizeOwnership title-cases an unknown label without jamming it', () => {
  assert.equal(humanizeOwnership('SomeNewOwner'), 'Some New Owner')
  assert.equal(humanizeOwnership(''), '')
  assert.equal(humanizeOwnership(undefined), '')
})

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)

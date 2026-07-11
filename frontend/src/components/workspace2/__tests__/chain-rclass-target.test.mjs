// R-class chain-target guard tests. Pure, runs under plain Node:
//   node frontend/src/components/workspace2/__tests__/chain-rclass-target.test.mjs
//
// Bug: the Hardcoded-Secret chain's "View Code" opened an auto-generated R-constants
// class (N0/a.java — 0x7f resource IDs) instead of the secret's real evidence. A
// resource class can never hold a secret, so the target resolver must reject it and
// fall back to the real evidence file (res/values/strings.xml / APKLeaks source).
import assert from 'node:assert/strict'
import {
  isResourceConstantTarget, chainEvidenceTargets, chainViewerTarget,
} from '../evidence-model.js'

let pass = 0, fail = 0
const t = (name, fn) => { try { fn(); pass++; console.log('PASS ', name) } catch (e) { fail++; console.log('FAIL ', name, '—', e.message) } }

// ── the guard ─────────────────────────────────────────────────────────────────
t('isResourceConstantTarget rejects R-class paths', () => {
  assert.ok(isResourceConstantTarget('sources/com/app/R.java'))
  assert.ok(isResourceConstantTarget('sources/com/app/R$layout.java'))
  assert.ok(isResourceConstantTarget('sources/com/app/R2.java'))
})
t('isResourceConstantTarget rejects a 0x7f resource-ID snippet (obfuscated R)', () => {
  assert.ok(isResourceConstantTarget('N0/a.java', 'public static final int x = 0x7f0a00b3;'))
})
t('isResourceConstantTarget accepts real evidence files', () => {
  assert.equal(isResourceConstantTarget('res/values/strings.xml'), false)
  assert.equal(isResourceConstantTarget('sources/com/app/ApiClient.java', 'String k = "x";'), false)
  assert.equal(isResourceConstantTarget(''), false)
})

// ── chainViewerTarget never resolves to an R-class ────────────────────────────
t('chainViewerTarget skips an R-class reference and lands on the real file', () => {
  const chain = {
    is_attack_chain: true, title: 'Hardcoded Secret / API Key Abuse',
    evidence_references: [
      { file: 'sources/com/app/R.java', line: 1272, evidence_id: 'EV-R' },
      { file: 'res/values/strings.xml', line: 58, evidence_id: 'EV-secret' },
    ],
  }
  const target = chainViewerTarget(chain)
  assert.equal(target.file, 'res/values/strings.xml')
  assert.equal(target.line, 58)
})

t('chainEvidenceTargets drops obfuscated R refs carrying a resource-ID snippet', () => {
  const chain = {
    is_attack_chain: true,
    evidence_references: [
      { file: 'N0/a.java', line: 3, evidence_id: 'int x = 0x7f0a00b3;' },
      { file: 'res/values/strings.xml', line: 58, evidence_id: 'artifactory_password' },
    ],
  }
  const files = chainEvidenceTargets(chain).map(t => t.file)
  assert.ok(!files.includes('N0/a.java'), 'R-class ref must be dropped')
  assert.deepEqual(files, ['res/values/strings.xml'])
})

t('a chain whose only ref is an R-class yields no viewer target', () => {
  const chain = { is_attack_chain: true, evidence_references: [{ file: 'com/app/R.java', line: 5 }] }
  assert.equal(chainViewerTarget(chain), null)
})

console.log(`\n${pass} passed, ${fail} failed`)
if (fail) process.exit(1)

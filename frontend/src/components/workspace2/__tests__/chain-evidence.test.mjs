// Chain-evidence normalization tests. Pure, runs under plain Node:
//   node frontend/src/components/workspace2/__tests__/chain-evidence.test.mjs
//
// Bug: view-code on a regular finding jumps to the exact line, but on an
// attack-chain finding it opened the file without positioning to the line — chain
// findings carry evidence as evidence_references[] ({file,line}) + steps[].evidence
// ("path:line"), a different shape than the regular file_path/file_evidence one the
// viewer read. These helpers normalize the chain shape into (file, line) targets.
import assert from 'node:assert/strict'
import {
  parseStepEvidence, chainEvidenceTargets, chainViewerTarget,
} from '../evidence-model.js'

let pass = 0, fail = 0
const t = (name, fn) => { try { fn(); pass++; console.log('PASS ', name) } catch (e) { fail++; console.log('FAIL ', name, '—', e.message) } }

// ── parseStepEvidence ("path:line") ───────────────────────────────────────────
t('parseStepEvidence splits a trailing :line', () => {
  assert.deepEqual(parseStepEvidence('sources/com/app/Dao.java:42'),
    { file: 'sources/com/app/Dao.java', line: 42 })
})
t('parseStepEvidence keeps a bare path with line 0', () => {
  assert.deepEqual(parseStepEvidence('sources/com/app/Dao.java'),
    { file: 'sources/com/app/Dao.java', line: 0 })
})
t('parseStepEvidence handles empty / non-string safely', () => {
  assert.equal(parseStepEvidence(''), null)
  assert.equal(parseStepEvidence(undefined), null)
  assert.equal(parseStepEvidence(null), null)
})

// ── chain finding with evidence_references[] resolves to (file, line) ─────────
t('chainViewerTarget resolves evidence_references[0] to a (file, line)', () => {
  const chain = {
    is_attack_chain: true, title: 'Exported Component to SQL Injection',
    evidence_references: [
      { file: 'sources/com/app/SearchDao.java', line: 42, evidence_id: 'EV-1' },
      { file: 'sources/com/app/Api.java', line: 7, evidence_id: 'EV-2' },
    ],
    affected_files: ['sources/com/app/SearchDao.java'],
  }
  const target = chainViewerTarget(chain)
  assert.equal(target.file, 'sources/com/app/SearchDao.java')
  assert.equal(target.line, 42)
  assert.ok(target.line > 0, 'view-code must land on the exact line, not the file top')
})

t('chainEvidenceTargets keeps a target per reference (for prev/next)', () => {
  const chain = {
    is_attack_chain: true,
    evidence_references: [
      { file: 'A.java', line: 10, evidence_id: 'a' },
      { file: 'B.java', line: 20, evidence_id: 'b' },
    ],
  }
  const targets = chainEvidenceTargets(chain)
  assert.equal(targets.length, 2)
  assert.deepEqual(targets.map(x => [x.file, x.line]), [['A.java', 10], ['B.java', 20]])
})

// ── each step's evidence "path:line" resolves to that step's line ─────────────
t('chainEvidenceTargets resolves each step evidence "path:line" to its line', () => {
  const chain = {
    is_attack_chain: true,
    steps: [
      { order: 1, title: 'Entry point', evidence: '' },
      { order: 2, title: 'SQL sink', evidence: 'sources/com/app/SearchDao.java:42' },
      { order: 3, title: 'Objective achieved', evidence: '' },
    ],
  }
  const targets = chainEvidenceTargets(chain)
  const sink = targets.find(x => x.file.endsWith('SearchDao.java'))
  assert.ok(sink, 'the step with evidence should produce a target')
  assert.equal(sink.line, 42, 'the step must resolve to ITS OWN line')
})

t('references take precedence, then steps, then affected_files', () => {
  const refsFirst = chainEvidenceTargets({
    is_attack_chain: true,
    evidence_references: [{ file: 'R.java', line: 5 }],
    steps: [{ evidence: 'S.java:9' }],
    affected_files: ['F.java'],
  })
  assert.equal(refsFirst[0].file, 'R.java')
  assert.ok(refsFirst.some(x => x.file === 'S.java' && x.line === 9), 'step target also included')
  assert.ok(!refsFirst.some(x => x.file === 'F.java'), 'affected_files only used as a last resort')
})

// ── graceful fallback: no line → open file, no jump ──────────────────────────
t('a member with no line falls back to affected_files with line 0 (graceful)', () => {
  const chain = { is_attack_chain: true, affected_files: ['sources/com/app/OnlyFile.java'] }
  const target = chainViewerTarget(chain)
  assert.equal(target.file, 'sources/com/app/OnlyFile.java')
  assert.equal(target.line, 0, 'no line known → 0 so the viewer opens the file without a jump')
})

t('a null line in a reference does not fabricate a jump', () => {
  const chain = { is_attack_chain: true, evidence_references: [{ file: 'X.java', line: null }] }
  const target = chainViewerTarget(chain)
  assert.equal(target.file, 'X.java')
  assert.equal(target.line, 0)
})

t('a chain with no proof file yields no target (not a crash)', () => {
  assert.equal(chainViewerTarget({ is_attack_chain: true }), null)
  assert.deepEqual(chainEvidenceTargets({ is_attack_chain: true }), [])
})

// ── dedup: the same file:line reported twice collapses to one target ─────────
t('chainEvidenceTargets de-duplicates identical file:line', () => {
  const chain = {
    is_attack_chain: true,
    evidence_references: [{ file: 'D.java', line: 3 }],
    steps: [{ evidence: 'D.java:3' }],
  }
  const targets = chainEvidenceTargets(chain)
  assert.equal(targets.length, 1, 'the same physical location should be one navigable target')
})

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)

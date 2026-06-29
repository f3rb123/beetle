// Phase 1.99 — Workspace registry tests (pure, runs under plain Node):
//   node frontend/src/components/workspace2/__tests__/workspace-registry.test.mjs
import assert from 'node:assert/strict'
import {
  PANELS, GROUP_ORDER, getPanel, readyPanels, plannedPanels, isReady, isPlanned,
  navGroups, roadmap, STATUS_READY, STATUS_PLANNED,
} from '../workspace-registry.js'

let pass = 0, fail = 0
const t = (n, fn) => { try { fn(); pass++; console.log('PASS ', n) } catch (e) { fail++; console.log('FAIL ', n, '—', e.message) } }

t('ready panels include the current workspace sections', () => {
  const ids = readyPanels().map(p => p.id)
  for (const id of ['overview', 'findings', 'chains', 'secrets', 'masvs', 'files', 'exports', 'ciso', 'developer'])
    assert.ok(ids.includes(id), `missing ready panel ${id}`)
})

t('all roadmap items are declared as planned', () => {
  // Java/Smali Explorers were folded into Source Explorer (Phase 2.5.8) — they are
  // viewing modes, not separate roadmap pages.
  const ids = plannedPanels().map(p => p.id)
  for (const id of ['evidence-compare', 'ai-reviewer', 'security-controls', 'framework-view'])
    assert.ok(ids.includes(id), `roadmap item ${id} not declared`)
  for (const gone of ['source-java', 'source-smali'])
    assert.ok(!ids.includes(gone), `${gone} should no longer be a separate page`)
})

t('status helpers are correct', () => {
  assert.equal(isReady('findings'), true)
  assert.equal(isPlanned('findings'), false)
  assert.equal(isPlanned('framework-view'), true)
  assert.equal(isReady('framework-view'), false)
  assert.equal(isReady('nonexistent'), false)
})

t('getPanel returns metadata incl. roadmap blurb', () => {
  const p = getPanel('evidence-compare')
  assert.equal(p.roadmap, 'Side-by-side Evidence Comparison')
  assert.ok(p.blurb && p.blurb.length > 10)
  assert.equal(getPanel('nope'), null)
})

t('navGroups follows GROUP_ORDER and can hide planned', () => {
  const withPlanned = navGroups({ includePlanned: true })
  const labels = withPlanned.map(g => g.label)
  // groups appear in declared order (subset of GROUP_ORDER that has items)
  let last = -1
  for (const l of labels) { const i = GROUP_ORDER.indexOf(l); assert.ok(i > last, `group ${l} out of order`); last = i }
  // 'Advanced' holds only planned panels → present with planned, gone without.
  assert.ok(withPlanned.some(g => g.label === 'Advanced'), 'Advanced group should appear with planned items')

  const readyOnly = navGroups({ includePlanned: false })
  assert.ok(!readyOnly.some(g => g.label === 'Advanced'), 'Advanced group should vanish when planned hidden')
})

t('every panel has id/label/group/icon/status', () => {
  for (const p of PANELS) {
    for (const k of ['id', 'label', 'group', 'icon', 'status']) assert.ok(p[k], `${p.id} missing ${k}`)
    assert.ok([STATUS_READY, STATUS_PLANNED].includes(p.status), `${p.id} bad status`)
    assert.ok(GROUP_ORDER.includes(p.group), `${p.id} in unknown group ${p.group}`)
  }
})

t('roadmap() lists the planned surfaces with titles', () => {
  const r = roadmap()
  assert.equal(r.length, plannedPanels().length)
  assert.ok(r.every(x => x.title && x.id))
})

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)

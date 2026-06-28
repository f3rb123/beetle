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
  const ids = plannedPanels().map(p => p.id)
  for (const id of ['source-java', 'source-smali', 'evidence-compare', 'ai-reviewer', 'security-controls', 'framework-view'])
    assert.ok(ids.includes(id), `roadmap item ${id} not declared`)
})

t('status helpers are correct', () => {
  assert.equal(isReady('findings'), true)
  assert.equal(isPlanned('findings'), false)
  assert.equal(isPlanned('source-java'), true)
  assert.equal(isReady('source-java'), false)
  assert.equal(isReady('nonexistent'), false)
})

t('getPanel returns metadata incl. roadmap blurb', () => {
  const p = getPanel('source-java')
  assert.equal(p.roadmap, 'Java Source Explorer')
  assert.ok(p.blurb && p.blurb.length > 10)
  assert.equal(getPanel('nope'), null)
})

t('navGroups follows GROUP_ORDER and can hide planned', () => {
  const withPlanned = navGroups({ includePlanned: true })
  const labels = withPlanned.map(g => g.label)
  // groups appear in declared order (subset of GROUP_ORDER that has items)
  let last = -1
  for (const l of labels) { const i = GROUP_ORDER.indexOf(l); assert.ok(i > last, `group ${l} out of order`); last = i }
  assert.ok(withPlanned.some(g => g.label === 'Source'), 'Source group should appear with planned items')

  const readyOnly = navGroups({ includePlanned: false })
  assert.ok(!readyOnly.some(g => g.label === 'Source'), 'Source group should vanish when planned hidden')
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

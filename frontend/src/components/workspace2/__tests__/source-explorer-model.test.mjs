// Phase 2.3 — Source Explorer model tests. Pure, runs under plain Node:
//   node frontend/src/components/workspace2/__tests__/source-explorer-model.test.mjs
import assert from 'node:assert/strict'
import {
  buildTree, buildOverlay, badgeForNode, categoryPathSet, nodePasses,
  ancestorsOf, resolveManifestPath, normalizePath, filterPathSet,
  QUICK_FILTERS, EXPLORER_EXTENSIONS,
} from '../source-explorer-model.js'

let pass = 0, fail = 0
const t = (name, fn) => { try { fn(); pass++; console.log('PASS ', name) } catch (e) { fail++; console.log('FAIL ', name, '—', e.message) } }

const PATHS = [
  'jadx/sources/com/app/Crypto.java',
  'jadx/sources/com/app/Net.java',
  'jadx/sources/com/app/util/Helper.java',
  'apktool/AndroidManifest.xml',
  'index.android.bundle',
]

const FILE_INDEX = {
  'sources/com/app/Crypto.java': { max_severity: 'high', categories: ['crypto'], findings: 2, secret: false, network: false, certificate: false, component: false },
  'sources/com/app/Net.java': { max_severity: 'low', categories: ['network'], findings: 1, secret: false, network: true, certificate: false, component: false },
  'AndroidManifest.xml': { max_severity: 'medium', categories: ['components'], findings: 1, component: true },
}
const SECURITY_INDEX = {
  crypto: ['sources/com/app/Crypto.java'],
  network: ['sources/com/app/Net.java'],
  components: ['AndroidManifest.xml'],
  secrets: [],
}

// ── Tree building (Android/iOS/Flutter/RN are all just path lists) ────────────
t('buildTree nests folders and files, dirs first', () => {
  const tree = buildTree(PATHS)
  const top = tree.children.map(c => c.name)
  // jadx + apktool are dirs (first), index.android.bundle is a file (last).
  assert.deepEqual(top, ['apktool', 'jadx', 'index.android.bundle'])
  const jadx = tree.children.find(c => c.name === 'jadx')
  assert.equal(jadx.dir, true)
  const crypto = jadx.children[0].children[0].children[0] // jadx>sources>com>app
  assert.ok(crypto)
})

t('buildTree marks files vs dirs correctly', () => {
  const tree = buildTree(['a/b/c.java', 'a/d.kt'])
  const a = tree.children.find(c => c.name === 'a')
  assert.equal(a.dir, true)
  assert.equal(a.children.find(c => c.name === 'b').dir, true)   // folder
  assert.equal(a.children.find(c => c.name === 'd.kt').dir, false) // file
})

t('lazy shape: nodes expose children arrays only on dirs', () => {
  const tree = buildTree(['x/y.java'])
  const x = tree.children[0]
  assert.ok(Array.isArray(x.children))
  assert.equal(x.children[0].children, undefined) // file node has no children array
})

// ── Path normalization (manifest prefix vs overlay paths) ─────────────────────
t('normalizePath strips the subdir prefix', () => {
  assert.equal(normalizePath('jadx/sources/com/app/Crypto.java'), 'sources/com/app/Crypto.java')
  assert.equal(normalizePath('apktool/AndroidManifest.xml'), 'AndroidManifest.xml')
  assert.equal(normalizePath('index.android.bundle'), 'index.android.bundle')
})

// ── Badge aggregation: folders roll up child severity + flags ─────────────────
t('buildOverlay aggregates folder severity from children', () => {
  const ov = buildOverlay(FILE_INDEX)
  // sources/com/app contains a high (Crypto) and a low (Net) → folder is high.
  assert.equal(ov.dirSev.get('sources/com/app').sev, 'high')
  assert.equal(ov.dirSev.get('sources/com/app').network, true)
})

t('badgeForNode resolves a file via normalized path', () => {
  const ov = buildOverlay(FILE_INDEX)
  const b = badgeForNode({ dir: false, name: 'Crypto.java', path: 'jadx/sources/com/app/Crypto.java' }, ov)
  assert.equal(b.sev, 'high')
  assert.equal(b.findings, 2)
})

t('badgeForNode rolls a folder badge up to the worst child', () => {
  const ov = buildOverlay(FILE_INDEX)
  const b = badgeForNode({ dir: true, name: 'app', path: 'jadx/sources/com/app' }, ov)
  assert.equal(b.sev, 'high')
})

// ── Security Explorer filtering ───────────────────────────────────────────────
t('categoryPathSet returns normalized paths for a category', () => {
  const set = categoryPathSet(SECURITY_INDEX, 'crypto')
  assert.ok(set.has('sources/com/app/Crypto.java'))
  assert.equal(set.has('sources/com/app/Net.java'), false)
})

t('nodePasses filters files by security category (+ keeps ancestor dirs)', () => {
  const tree = buildTree(PATHS)
  const catSet = categoryPathSet(SECURITY_INDEX, 'crypto')
  const jadx = tree.children.find(c => c.name === 'jadx')
  // The jadx dir passes (a descendant Crypto.java is in the crypto set) …
  assert.equal(nodePasses(jadx, { catSet, query: '' }), true)
  // … apktool does not (its only child is the manifest, in components not crypto).
  const apktool = tree.children.find(c => c.name === 'apktool')
  assert.equal(nodePasses(apktool, { catSet, query: '' }), false)
})

// ── File search ───────────────────────────────────────────────────────────────
t('nodePasses filters by filename query', () => {
  const tree = buildTree(PATHS)
  const jadx = tree.children.find(c => c.name === 'jadx')
  assert.equal(nodePasses(jadx, { catSet: null, query: 'crypto' }), true)
  assert.equal(nodePasses(jadx, { catSet: null, query: 'zzz-nope' }), false)
})

// ── Source jump (finding → manifest path) ─────────────────────────────────────
t('resolveManifestPath maps a finding path to the prefixed manifest path', () => {
  assert.equal(resolveManifestPath('sources/com/app/Crypto.java', PATHS), 'jadx/sources/com/app/Crypto.java')
  assert.equal(resolveManifestPath('AndroidManifest.xml', PATHS), 'apktool/AndroidManifest.xml')
})

t('ancestorsOf returns the expandable folder chain for a file', () => {
  assert.deepEqual(ancestorsOf('jadx/sources/com/app/Crypto.java'),
    ['jadx', 'jadx/sources', 'jadx/sources/com', 'jadx/sources/com/app'])
})

// ── Quick Filters drive the SAME filter (no second system) ────────────────────
t('filterPathSet: all → no filter', () => {
  assert.equal(filterPathSet('all', { securityIndex: SECURITY_INDEX, fileIndex: FILE_INDEX }), null)
  assert.equal(filterPathSet(null, {}), null)
})

t('filterPathSet: findings pseudo-category = every annotated file', () => {
  const set = filterPathSet('findings', { securityIndex: SECURITY_INDEX, fileIndex: FILE_INDEX })
  assert.equal(set.size, 3)
  assert.ok(set.has('sources/com/app/Crypto.java'))
  assert.ok(set.has('AndroidManifest.xml'))
})

t('filterPathSet: a category routes through categoryPathSet (same result)', () => {
  const a = filterPathSet('crypto', { securityIndex: SECURITY_INDEX, fileIndex: FILE_INDEX })
  const b = categoryPathSet(SECURITY_INDEX, 'crypto')
  assert.deepEqual([...a], [...b])
})

t('Quick Filters + extension seams are data-only registries', () => {
  assert.equal(QUICK_FILTERS[0].id, 'all')
  assert.ok(QUICK_FILTERS.some(f => f.id === 'findings'))
  assert.ok(QUICK_FILTERS.some(f => f.future))               // Modified / Favorites reserved
  const ids = EXPLORER_EXTENSIONS.map(e => e.id)
  for (const id of ['bookmarks', 'notes', 'compare-scans', 'ai-review', 'semgrep']) {
    assert.ok(ids.includes(id), `extension seam present: ${id}`)
  }
  assert.ok(EXPLORER_EXTENSIONS.every(e => e.status === 'planned'), 'seams are planned-only')
})

console.log(`\n${pass}/${pass + fail} passed`)
if (fail) process.exit(1)

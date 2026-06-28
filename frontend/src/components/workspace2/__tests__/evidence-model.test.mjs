// Phase 1.99 — Evidence UI data-model tests. Pure, runs under plain Node:
//   node frontend/src/components/workspace2/__tests__/evidence-model.test.mjs
import assert from 'node:assert/strict'
import {
  getEvidenceView, detectionSources, trustScore, trustBand, confidenceContributions,
  languageOf, reachabilityLabel, matchesFilters, findingDetectionSourceSet,
} from '../evidence-model.js'

let pass = 0, fail = 0
const t = (name, fn) => { try { fn(); pass++; console.log('PASS ', name) } catch (e) { fail++; console.log('FAIL ', name, '—', e.message) } }

const APP = 'com/insecureshop'
function cryptoFinding() {
  return {
    title: 'Broken Crypto', severity: 'high', cwe: 'CWE-327', detected_by: ['Beetle Native', 'APKLeaks'],
    detection_count: 2, fusion_score: 68, overall_confidence: 78, reachability: 'YES', in_attack_chain: true,
    owner_type: 'Application', owner_name: 'Application', confidence_reason: 'app-owned; reachable',
    confidence_breakdown: { band: 'High', dimensions: { detection: { score: 80 }, ownership: { score: 90 }, evidence: { score: 70 }, context: { score: 40 }, exploitability: { score: 30 } } },
    evidence_view: {
      primary: { file: `sources/${APP}/CryptoUtil.java`, line: 12, snippet: 'Cipher.getInstance("AES/ECB")',
        owner_type: 'Application', owner_name: 'Application', source: 'Beetle Native', score: 115,
        reasons: ['Application-owned', 'Reachable from an entry point'] },
      supporting: [{ file: `sources/${APP}/CryptoManager.java`, line: 4, snippet: 'x', owner_type: 'Application' }],
      additional_references: [],
      hidden_library_evidence: { count: 2, owners: ['AndroidX AppCompat', 'Google Play Services'],
        items: [{ file: 'sources/androidx/appcompat/App.java', owner_name: 'AndroidX AppCompat', reasons: ['AndroidX AppCompat library/framework'] }] },
      evidence_score: 115, selection_reason: 'Selected from 3 candidate proof file(s): Application-owned; …',
      evidence_ownership: 'Application', evidence_source: 'Beetle Native',
      detection_sources: ['Beetle Native', 'APKLeaks'], reachability: 'YES', in_attack_chain: true, fallback: false,
    },
  }
}

// ── language ─────────────────────────────────────────────────────────────────
t('languageOf maps extensions', () => {
  assert.equal(languageOf('a/B.java'), 'Java')
  assert.equal(languageOf('a/B.smali'), 'Smali')
  assert.equal(languageOf('AndroidManifest.xml'), 'Android Manifest')
  assert.equal(languageOf('Info.plist'), 'Info.plist')
})

// ── evidence view ────────────────────────────────────────────────────────────
t('getEvidenceView surfaces app primary + hidden libraries', () => {
  const v = getEvidenceView(cryptoFinding())
  assert.ok(v.primary.file.endsWith('CryptoUtil.java'))
  assert.equal(v.primary.language, 'Java')
  assert.equal(v.primary.owner_type, 'Application')
  assert.equal(v.hidden.count, 2)
  assert.ok(v.hidden.owners.includes('AndroidX AppCompat'))
  assert.equal(v.supporting.length, 1)
  assert.equal(v.fallback, false)
})

t('getEvidenceView falls back to legacy file_evidence', () => {
  const v = getEvidenceView({ title: 'X', file_evidence: [{ path: 'a/Y.java', lines: [3], snippet: 'z' }] })
  assert.equal(v.fallback, true)
  assert.ok(v.primary.file.endsWith('Y.java'))
  assert.equal(v.primary.line, 3)
})

t('getEvidenceView normalizes evidence_selection shape', () => {
  const v = getEvidenceView({ evidence_selection: { primary: { file_path: 'a/Z.java', line: 9, owner_type: 'Application', selected_because: ['app'] },
    supporting: [], rejected: [{ file_path: 'androidx/x.java', owner_type: 'ThirdPartySDK', rejected_because: ['lib'] }], reason: 'r' } })
  assert.ok(v.primary.file.endsWith('Z.java'))
  assert.equal(v.hidden.count, 1)
})

// ── detection sources (future engines appear automatically) ──────────────────
t('detectionSources reads detected_by incl. unknown future engines', () => {
  assert.deepEqual(detectionSources({ detected_by: ['Beetle Native', 'APKLeaks', 'Semgrep'] }),
    ['Beetle Native', 'APKLeaks', 'Semgrep'])
})
t('detectionSources infers from legacy producer fields', () => {
  assert.deepEqual(detectionSources({ discovery_method: 'taint_flow' }), ['Taint'])
  assert.deepEqual(detectionSources({ source_module: 'Manifest' }), ['Manifest'])
  assert.deepEqual(detectionSources({}), ['Beetle Native'])
})
t('findingDetectionSourceSet aggregates across findings', () => {
  const s = findingDetectionSourceSet([{ detected_by: ['Beetle Native'] }, { detected_by: ['APKLeaks', 'Semgrep'] }])
  assert.deepEqual(s, ['APKLeaks', 'Beetle Native', 'Semgrep'])
})

// ── trust score ──────────────────────────────────────────────────────────────
t('trustScore blends confidence + fusion + evidence', () => {
  const s = trustScore(cryptoFinding())
  assert.ok(s > 0 && s <= 100)
  // 78*.6 + 68*.25 + 100*.15(capped from 115) = 46.8 + 17 + 15 = ~79
  assert.ok(s >= 75, `expected high trust, got ${s}`)
  assert.equal(trustBand(s), 'high')
})
t('trustScore handles findings with no signals', () => {
  assert.equal(trustScore({}), 0)
  assert.equal(trustBand(0), 'info')
})

// ── confidence contributions ─────────────────────────────────────────────────
t('confidenceContributions splits positive/negative + fusion contribution', () => {
  const c = confidenceContributions(cryptoFinding())
  assert.equal(c.overall, 78)
  assert.ok(c.positives.some(p => p.label === 'Ownership'))
  assert.ok(c.negatives.some(p => p.label === 'Exploitability'))
  assert.match(c.fusionContribution, /2 independent engines/)
})

// ── reachability ─────────────────────────────────────────────────────────────
t('reachabilityLabel maps states', () => {
  assert.equal(reachabilityLabel({ reachability: 'YES' }), 'Reachable')
  assert.equal(reachabilityLabel({ reachability: 'NO' }), 'Not reachable')
  assert.equal(reachabilityLabel({}), '')
})

// ── filters ──────────────────────────────────────────────────────────────────
t('matchesFilters composes all criteria', () => {
  const f = cryptoFinding()
  assert.equal(matchesFilters(f, {}), true)
  assert.equal(matchesFilters(f, { severity: 'high' }), true)
  assert.equal(matchesFilters(f, { severity: 'low' }), false)
  assert.equal(matchesFilters(f, { detectionSource: 'APKLeaks' }), true)
  assert.equal(matchesFilters(f, { detectionSource: 'Semgrep' }), false)
  assert.equal(matchesFilters(f, { ownership: 'Application' }), true)
  assert.equal(matchesFilters(f, { ownership: 'ThirdPartySDK' }), false)
  assert.equal(matchesFilters(f, { minEvidence: 100 }), true)
  assert.equal(matchesFilters(f, { minEvidence: 200 }), false)
  assert.equal(matchesFilters(f, { minTrust: 50 }), true)
})

// ── API compatibility / regression: mixed old+new shapes never throw ─────────
t('API compatibility: legacy + modern findings both render safely', () => {
  for (const f of [cryptoFinding(), { title: 'legacy', file_path: 'a/B.java', line: 2 }, {}, { detected_by: null }]) {
    const v = getEvidenceView(f)
    assert.ok(v && typeof v === 'object')
    assert.ok(Array.isArray(v.supporting))
    assert.ok(v.hidden && typeof v.hidden.count === 'number')
    assert.ok(Array.isArray(detectionSources(f)))
    assert.ok(Number.isFinite(trustScore(f)))
  }
})

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)

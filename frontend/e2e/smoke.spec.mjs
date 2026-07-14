// RUN 30 — real-UI smoke tests (headless Chromium against a running Beetle instance).
//
// These are the DURABLE guard for the class of bugs that shipped broken in RUN 24/28 because there
// was no automated real-render check: view-code autoscroll, the binary "extracted strings" view, and
// the finding narrative. Everything here asserts the RENDERED DOM, not an HTTP response.
//
// Requires a running stack + a completed scan. Configure via env:
//   E2E_BASE_URL   (default http://localhost:9005)
//   E2E_USER / E2E_PASS  (default beetle / beetle)
//   E2E_SCAN       an existing completed scan id  — fastest, OR
//   E2E_IPA        path to an .ipa/.apk fixture to upload and wait on (used only if E2E_SCAN unset)
// When neither the stack nor a scan is reachable the tests SKIP (never fail the build).
import { test, expect, request as pwRequest } from '@playwright/test'
import fs from 'fs'

const BASE = process.env.E2E_BASE_URL || 'http://localhost:9005'
const USER = process.env.E2E_USER || 'beetle'
const PASS = process.env.E2E_PASS || 'beetle'

let token = null
let scanId = null
let stackUp = false

async function pollScan(rc, id) {
  for (let i = 0; i < 60; i++) {
    const r = await rc.get(`${BASE}/api/scans/${id}/status`, { headers: { Authorization: `Bearer ${token}` } })
    if (r.ok()) {
      const s = (await r.json()).status
      if (['completed', 'failed', 'error'].includes(s)) return s
    }
    await new Promise(res => setTimeout(res, 3000))
  }
  return 'timeout'
}

test.beforeAll(async () => {
  const rc = await pwRequest.newContext()
  try {
    const h = await rc.get(`${BASE}/api/health`)
    stackUp = h.ok()
  } catch { stackUp = false }
  if (!stackUp) { await rc.dispose(); return }

  try {
    const login = await rc.post(`${BASE}/api/auth/login`, { data: { username: USER, password: PASS } })
    if (login.ok()) token = (await login.json()).access_token
  } catch { /* leave token null -> skip */ }

  scanId = process.env.E2E_SCAN || null
  if (!scanId && token && process.env.E2E_IPA && fs.existsSync(process.env.E2E_IPA)) {
    const p = process.env.E2E_IPA
    const up = await rc.post(`${BASE}/api/analyze`, {
      headers: { Authorization: `Bearer ${token}` },
      multipart: { file: { name: p.split(/[\\/]/).pop(), mimeType: 'application/octet-stream', buffer: fs.readFileSync(p) } },
    })
    if (up.ok()) { scanId = (await up.json()).scan_id; await pollScan(rc, scanId) }
  }
  await rc.dispose()
})

test.beforeEach(async ({ page }) => {
  test.skip(!stackUp, 'Beetle stack not reachable — set E2E_BASE_URL to a running instance')
  test.skip(!token, 'could not authenticate — set E2E_USER / E2E_PASS')
  test.skip(!scanId, 'no scan available — set E2E_SCAN=<id> or E2E_IPA=<fixture path>')
  // Inject the auth token the way the app stores it, then load the app.
  await page.goto(`${BASE}/login`)
  await page.evaluate(([t]) => {
    localStorage.setItem('cortex_token', t)
    localStorage.setItem('cortex_user', JSON.stringify({ username: 'beetle', role: 'admin' }))
  }, [token])
})

// BUG 1 (RUN 24/29): view-code must scroll the evidence line INTO the viewport. The RUN 29
// regression was a focus row that rendered but sat far below the scroll body — only a real render
// with a geometry check catches it.
test('view-code scrolls the evidence line into view', async ({ page }) => {
  await page.goto(`${BASE}/scans/${scanId}/findings`, { waitUntil: 'networkidle' })
  const viewCode = page.locator('.ws-fcard button', { hasText: /view code/i }).first()
  await expect(viewCode).toBeVisible()
  await viewCode.click()

  await expect(page.locator('.code-viewer__body')).toBeVisible()
  await page.waitForTimeout(1200)  // let the rAF scroll + re-assert settle
  expect(await page.locator('.code-table tr').count()).toBeGreaterThan(0)

  // If the finding resolved to a real line, its row must be within the scroll body's box.
  const verdict = await page.evaluate(() => {
    const foc = document.querySelector('.code-table tr.is-focus-line')
    const body = document.querySelector('.code-viewer__body')
    if (!foc || !body) return 'approximate'   // line-1 / no-anchor findings are acceptable
    const fr = foc.getBoundingClientRect(), br = body.getBoundingClientRect()
    return (fr.top >= br.top - 4 && fr.bottom <= br.bottom + 4) ? 'in-view' : 'OUT-OF-VIEW'
  })
  expect(verdict).not.toBe('OUT-OF-VIEW')
})

// BUG 2 (RUN 29): a compiled binary must open to its searchable extracted strings, not a dead card.
test('a Mach-O opens to searchable extracted strings, not a dead card', async ({ page }) => {
  await page.goto(`${BASE}/scans/${scanId}/codebrowser`, { waitUntil: 'networkidle' })
  const search = page.locator('input[placeholder*="Search files"]').first()
  test.skip(!(await search.count()), 'no browsable file tree for this scan')
  await search.fill('Runner')
  await page.waitForTimeout(800)

  const rows = await page.locator('.ws-ex-file').all()
  let opened = false
  for (const r of rows) {
    if (((await r.textContent()) || '').trim() === 'Runner') { await r.click(); opened = true; break }
  }
  test.skip(!opened, 'no Mach-O named "Runner" in this bundle (not an iOS scan)')

  await page.waitForTimeout(1200)
  await expect(page.locator('.code-viewer__binary')).toHaveCount(0)   // NOT a dead card
  expect(await page.locator('.code-table tr').count()).toBeGreaterThan(50)  // strings rendered
  const vs = page.locator('.code-viewer__search input').first()
  await expect(vs).toBeVisible()                                       // searchable
})

// BUG 3 (RUN 29): the finding drawer must render a Why-Dangerous narrative, and a non-firebase
// finding must never borrow the "Permissive Firebase rules" text (the exact false-match symptom).
test('finding narrative renders and never borrows a wrong-category description', async ({ page }) => {
  await page.goto(`${BASE}/scans/${scanId}/findings`, { waitUntil: 'networkidle' })
  const count = await page.locator('.ws-fcard').count()
  expect(count).toBeGreaterThan(0)

  const readWhy = () => page.evaluate(() => {
    const b = [...document.querySelectorAll('.ws-block')].find(x => {
      const l = x.querySelector('.ws-block__label')?.textContent || ''
      return l.includes('Why Dangerous') || l.includes('Summary')
    })
    return b?.querySelector('p')?.textContent?.trim() || ''
  })

  let firstWhyLen = 0
  const n = Math.min(count, 6)
  for (let i = 0; i < n; i++) {
    const card = page.locator('.ws-fcard').nth(i)
    const title = ((await card.locator('.ws-fcard__title').textContent()) || '').toLowerCase()
    await card.click()
    await page.waitForTimeout(500)
    const why = (await readWhy()).toLowerCase()
    if (i === 0) firstWhyLen = why.length
    if (!title.includes('firebase')) {
      expect(why).not.toContain('permissive firebase')
    }
    await page.keyboard.press('Escape')
    await page.waitForTimeout(200)
  }
  expect(firstWhyLen).toBeGreaterThan(10)   // a real narrative rendered, not an empty block
})

// L6 closure (RUN 36): the RUN 35 R35-B tracker/SDK split and chain labels are verified by DATA in
// the backend, but the RENDER was the last surface still trusted from data not pixels. These assert
// the real DOM. Robust: relative (no hardcoded "3"), and skip cleanly on a non-Android/no-tracker scan.
test('trackers render split from bundled SDKs, count is not inflated', async ({ page }) => {
  // 'malware' is reached via the in-app nav (not a direct URL section) — load a routable section
  // first, then click the "Malware Analysis" nav item.
  await page.goto(`${BASE}/scans/${scanId}/findings`, { waitUntil: 'networkidle' })
  const navItem = page.locator('.ws-nav__item', { hasText: 'Malware Analysis' }).first()
  test.skip(!(await navItem.count()), 'no Malware Analysis nav for this scan')
  await navItem.click()
  await page.waitForTimeout(700)

  // The "Third-Party Trackers" section header carries the tracker count next to it.
  const trackersHead = page.locator('.ws-section__head', { hasText: 'Third-Party Trackers' }).first()
  test.skip(!(await trackersHead.count()), 'no trackers panel for this scan')

  const trackerCount = parseInt(((await trackersHead.locator('.ws-muted').first().textContent()) || '0').trim(), 10)
  // The bundled-SDK subsection only exists when functional SDKs were detected (e.g. IB2: Maps, Sign-In).
  const bundledHead = page.locator('.ws-section__head', { hasText: 'Bundled SDKs' }).first()
  const hasBundled = (await bundledHead.count()) > 0
  test.skip(!hasBundled, 'this scan has no bundled SDKs to split out (nothing to prove)')

  const bundledCount = parseInt(((await bundledHead.locator('.ws-muted').first().textContent()) || '0').trim(), 10)
  expect(bundledCount).toBeGreaterThan(0)

  // The tracker count must EXCLUDE bundled SDKs (the R35-B fix): a bundled SDK name must not appear
  // among the tracker rows, and the tracker header count must equal the tracker-row count only.
  const trackerRowCount = await page.locator('.ws-card').first().locator('.ws-file').count()
  expect(trackerRowCount).toBe(trackerCount)
  // A bundled SDK (Maps / Sign-In) must be listed under Bundled SDKs, never counted as a tracker.
  const trackerText = ((await page.locator('.ws-card').first().textContent()) || '').toLowerCase()
  expect(trackerText).not.toContain('maps sdk')
  expect(trackerText).not.toContain('sign-in')
})

// The attack-chain label must show the chain's real name (not a mislabel), closing the "chain-label
// verified by data" half of L6.
test('attack-chain cards render their real name + a severity/proof label', async ({ page }) => {
  await page.goto(`${BASE}/scans/${scanId}/findings`, { waitUntil: 'networkidle' })
  await page.waitForTimeout(600)
  const chainCard = page.locator('.ws-fcard', { hasText: /Attack Chain|Exported Component|Reflection|WebView/i }).first()
  test.skip(!(await chainCard.count()), 'no attack-chain finding in this scan')
  const title = ((await chainCard.locator('.ws-fcard__title').textContent()) || '').trim()
  expect(title.length).toBeGreaterThan(8)                 // a real chain name rendered
  // Its severity chip must be one of the real levels — never blank/undefined.
  const sev = ((await chainCard.locator('.ws-sev, .ws-tag').first().textContent()) || '').toLowerCase()
  expect(sev).toMatch(/crit|high|med|low|info/)
})

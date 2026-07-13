import { defineConfig } from '@playwright/test'

// RUN 30 — real-UI smoke tests. These drive a RUNNING Beetle instance (not a mock) with a headless
// browser and assert the rendered DOM, because the view-code scroll / binary-strings / finding
// narrative bugs (RUN 24/28/29) only reproduce in an actual render — unit tests and HTTP checks
// passed while the UI was broken. The suite SKIPS cleanly when no stack/scan is available, so it
// never fails a build spuriously; point it at a running instance to exercise it.
export default defineConfig({
  testDir: './e2e',
  timeout: 120_000,
  expect: { timeout: 15_000 },
  reporter: process.env.CI ? 'line' : 'list',
  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://localhost:9005',
    headless: true,
    viewport: { width: 1400, height: 900 },
  },
})

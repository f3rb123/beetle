# Real-UI smoke tests (Playwright)

These drive a **running** Beetle instance with a headless browser and assert the **rendered DOM**.
They exist because the view-code autoscroll, binary "extracted strings" view, and finding-narrative
bugs (RUN 24/28/29) reproduced only in a real render — unit tests and HTTP checks passed while the
UI was visibly broken. This is the durable guard so those can't silently break again.

## What they check
- **view-code scroll** — the evidence line's row is actually scrolled into the code viewport.
- **binary strings** — a Mach-O opens to its searchable extracted strings, not a dead "no source" card.
- **finding narrative** — Why-Dangerous renders, and a non-firebase finding never borrows the
  "Permissive Firebase rules" description (the categorizer false-match symptom).

## Run
Requires a running stack and a completed scan. The suite **skips cleanly** if neither is reachable.

```bash
cd frontend
npm install                 # first time (installs @playwright/test)
npx playwright install chromium

# fastest: point at an existing completed scan
E2E_SCAN=<scan-id> npm run test:e2e

# or upload a fixture and wait (iOS scan exercises the binary-strings test)
E2E_IPA=/abs/path/to/testapp.ipa npm run test:e2e
```

Env: `E2E_BASE_URL` (default `http://localhost:9005`), `E2E_USER`/`E2E_PASS` (default `beetle`/`beetle`),
`E2E_SCAN`, `E2E_IPA`. The categorizer logic itself is unit-tested in
`backend/tests/test_analyst_categorize.py`; these tests confirm it reaches the screen.

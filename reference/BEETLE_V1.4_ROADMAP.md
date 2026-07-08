# Beetle v1.4 — Roadmap: Product Polish & Scan Comparison

> **Status:** Planning / architecture only. No code, tests, schema, or Docker config changed.
> **Scope guardrail:** The v1.3 analysis engine is STABLE. Nothing in this milestone
> changes detection, scoring, decompilation, SourceCorpus, attack chains, secrets,
> endpoints, CVE, taint, report generation, authentication, or Docker configuration.
> Everything below is **additive UI/UX and a read-only comparison layer** over data the
> engine already produces.

This document is grounded in the current codebase (branch `v1.3-dev`, commit `470d169`).
Every claim about existing behaviour cites the real file it was read from.

---

## 0. What already exists (so we build, not rebuild)

A scan-comparison foundation is **already partially present** and must be the starting point:

| Layer | What exists today | File |
|---|---|---|
| Diff engine | `compare_scans(a, b)` → added / removed / common findings (keyed `rule_id or title`), `severity_changes`, `trust` delta, `attack_chains` added/removed | `backend/database.py:817` |
| API | `GET /api/scans/compare?a=&b=` and `GET /api/compare?scan_a=&scan_b=` | `backend/main.py:1139`, `1454` |
| UI panel | `ComparePanel` — a metric-delta table (score/trust/MASVS/findings/crit/high/secrets/components/perms/chains) | `frontend/src/components/workspace2/panels2.jsx:1242` |
| Nav slot | `compare` section id already routed & rendered (`case 'compare' → <ComparePanel>`) | `Workspace.jsx:202`, `workspace-sections.js` |
| Persistence | Per-scan metadata + per-finding rows in SQLite; full results JSON on disk (`/data/scans/<id>/results.json`) | `backend/database.py` |

**The critical gap:** the UI `ComparePanel` does **not** call the backend diff engine. It reads
`loadLocalHistory()` / `getStoredScan()` from **browser localStorage**, so it can only compare
scans "viewed in this browser," has **no same-app guard**, and shows **no finding-level diff**
(no new/fixed lists, no evidence/confidence/MASVS/timeline). v1.4 closes this gap by wiring a
richer backend diff to a dedicated comparison experience.

---

## 1. Current strengths

**Architecture & data model**
- Clean scan-target ingestion → analyzer → intelligence-engine → report pipeline; the UI is a thin, read-only consumer of a stable results contract.
- Findings are already persisted **relationally** (`findings` table: `rule_id, severity, category, masvs, cwe, owasp, confidence, exploitability, file_path, line_number, cve, cvss, kev`) **and** as a full JSON blob on disk — so comparison has both fast queryable columns and complete evidence.
- Per-scan metadata already includes everything a diff needs to anchor on: `package`, `platform`, `sha256`, `score`, severity summary, `trust_score`, `findings_count`, `created_at`, `completed_at`.
- Stable `rule_id`s (v1.3 rule-ID stabilization) make cross-scan finding matching viable **today**.

**UX foundations that are genuinely good**
- Deep-linkable workspace sections (`/scans/:scanId/:sectionId`) with a URL↔section resolver (`workspace-sections.js`) and graceful fallback to Overview.
- A single, coherent investigation shell (`workspace2/Workspace.jsx`) with a rich panel registry (overview, findings, evidence, attack chains, MASVS, source explorer, malware, AI, compare…).
- Top-level `ErrorBoundary` that preserves scan data on a UI crash (`App.jsx:13`).
- Evidence-first findings (file+line+snippet+View Code), ownership/confidence/trust already surfaced — a real differentiator vs. list-only scanners.
- Scan History with search and a `package` column already present (`History.jsx`).

---

## 2. Current UX weaknesses (prioritized)

Ranked by analyst impact × effort-to-fix. (Informed by reading the routes, panels, and history
page; a live click-through pass is recommended before build to confirm pixel-level items.)

**P0 — blocks the v1.4 objective**
1. **Comparison is localStorage-bound and shallow.** `ComparePanel` can't compare arbitrary persisted scans, has no same-app matching, and shows only aggregate metrics — no per-finding new/fixed/changed, no evidence or confidence diffs, no timeline. This is the headline gap.
2. **No "application" concept in the UI.** Scans are listed individually; there is no grouping of *"all scans of package X over time,"* which is the natural anchor for comparison and trend. The data (`scans.package`) exists but isn't surfaced as an entity.

**P1 — high-value polish**
3. **No cross-scan trend.** Score/severity history over time for one app is not visualized anywhere (History is a flat table).
4. **Filtering/search is inconsistent per surface.** History has search; findings filtering lives inside the workspace panel; there is no shared, saved-filter vocabulary (severity, ownership, MASVS, confidence, category) across surfaces.
5. **Baseline selection is manual and hidden.** There's no "compare to previous scan" one-click affordance from a scan overview or history row.
6. **Executive summary is not diff-aware.** It describes a single scan; leadership wants "what changed since last release."

**P2 — refinement**
7. **Empty/loading/error states vary by panel** (some `EmptyState`, some ad-hoc). A shared state kit would tighten the feel.
8. **Navigation depth.** Many deep-analysis sections share one flat list; a grouped/tiered nav (Overview · Findings · Evidence · Chains · Compare · Deep Analysis) would aid orientation.
9. **Keyboard & density.** No global command palette / keyboard nav; tables are comfortable-density only (enterprises expect a compact mode + shortcuts).
10. **Shareable comparison URL.** Comparison state isn't deep-linkable (`/compare?base=&target=`), so results can't be shared or bookmarked.

---

## 3. Proposed improvements (this milestone)

**Comparison-centric (the objective)**
- Promote **"Application"** as a first-class grouping in History (collapse scans by `package`+`platform`), with a per-app timeline.
- A dedicated **Scan Comparison view** driven by an enhanced backend diff (see §4), covering all requested dimensions: new / fixed findings, severity Δ, confidence Δ, evidence Δ, new/removed attack chains, MASVS posture Δ, security-score Δ, risk trend, timeline.
- One-click **"Compare with previous"** from a scan overview and from a History row; **"Compare"** multi-select mode in History (pick exactly two scans of the same app).
- **Deep-linkable** comparison (`/compare?base=<id>&target=<id>`).

**General polish (non-detection)**
- Shared **filter bar** component (severity · ownership · MASVS · confidence · category · text) reused by Findings and History.
- Shared **state kit** (loading / empty / error) applied across panels.
- **Trend chart** on the app page (score & severity counts over time).
- Diff-aware **Executive Summary** ("since baseline: +N critical, M fixed, score −X").
- Optional: global **command palette** (⌘K) and a compact table density toggle.

---

## 4. Scan Comparison architecture

### 4.1 Principles
- **Read-only.** The comparator never mutates findings, chains, scores, or files. It reads the two scans' persisted rows + results.json and computes a diff.
- **Same-application by contract.** The API accepts two scan ids and validates they share `package`+`platform` (warn, don't hard-block, if a user forces a cross-app compare).
- **Deterministic matching.** Findings match on a **stable fingerprint** (below), not array position — reproducible and order-independent.
- **Compute-on-demand, cache-optional.** A diff is cheap (hundreds of findings); compute per request. A cache table is optional (see §5) and additive.

### 4.2 Finding identity (matching key)
Today `compare_scans` keys on `rule_id or title` — collides when one rule fires at multiple sites.
v1.4 uses a **composite fingerprint**, computed at read time from columns that already exist:

```
fingerprint = sha1( rule_id | normalized_file_path | symbol_or_line_bucket | masvs )
```

- Primary match: exact fingerprint.
- Secondary (fuzzy) match: same `rule_id` + same file (line moved) → classified as **"moved / evidence changed,"** not new+fixed. This prevents a refactor from showing as churn.
- Falls back to `rule_id|title` when a component is missing (parity with today).

No schema change is required to compute this (it's derived); an optional stored column (§5) makes it faster and canonical.

### 4.3 Diff dimensions → data source (all already persisted)

| Dimension | Source | Notes |
|---|---|---|
| New findings | `findings` rows in B not in A (by fingerprint) | already ~half-done in `compare_scans` |
| Fixed findings | in A not in B | already present |
| Severity changes | `findings.severity` A vs B | already present |
| Confidence changes | `findings.confidence` A vs B | column exists, not yet diffed |
| Evidence changes | `findings.file_path/line_number/snippet` (+ results.json `evidence_selection`) | new: "moved / snippet changed" class |
| New / removed attack chains | results.json (`quick_summary.attack_chain`, `is_attack_chain` findings) | partial today; formalize chain identity by title/id |
| MASVS posture Δ | `findings.masvs` counts + results.json MASVS coverage | new: per-category covered/failed delta |
| Security score Δ | `scans.score` (and `trust_score`) A vs B | today only trust delta — add score |
| Risk trend | `scans` rows for the package, ordered by `created_at` | new: N-point series |
| Timeline | `scans.created_at`/`completed_at` across the app | new |

### 4.4 Proposed API surface (additive; existing endpoints untouched)

```
GET /api/apps                          → list distinct applications (group scans by package+platform)
GET /api/apps/{package}/scans          → scans for one app, newest→oldest (timeline anchor)
GET /api/apps/{package}/trend          → score/severity series over time (chart data)
GET /api/compare/full?base=&target=    → the enriched diff object (§4.3), same-app validated
```

`GET /api/compare/full` returns a single envelope:
```jsonc
{
  "base":   { "scan_id", "created_at", "score", "severity_summary", "masvs" },
  "target": { ... },
  "same_app": true,
  "findings": { "new":[...], "fixed":[...], "unchanged_count":N,
                "severity_changes":[...], "confidence_changes":[...],
                "evidence_changes":[...] },
  "attack_chains": { "added":[...], "removed":[...] },
  "masvs":  { "improved":[...], "regressed":[...] },
  "score":  { "base":X, "target":Y, "delta":Z },
  "trust":  { "base":X, "target":Y, "delta":Z },
  "trend":  [ { "scan_id","created_at","score","critical","high" }, ... ],
  "summary":{ "new":a, "fixed":b, "worsened":c, "improved":d, "verdict":"regressed|improved|stable" }
}
```

The existing `compare_scans` becomes the **core** of `/api/compare/full` (extended with
confidence/evidence/MASVS/score); the two legacy endpoints keep their current shape for
backward compatibility.

### 4.5 Backend module layout (additive, outside the frozen analyzer tree)
```
backend/comparison/            (new package — NOT under analyzers/)
  __init__.py
  engine.py        # build_full_diff(base_id, target_id) — pure, read-only
  fingerprint.py   # stable finding identity
  apps.py          # group scans by package+platform, trend series
```
Wiring: 3 thin route handlers in `main.py` that call `comparison.engine`. No analyzer import.

---

## 5. Database changes (minimum, and mostly optional)

**Verdict: the schema already stores enough for a functional v1.4 comparison. Zero changes are
strictly required.** Matching, all requested diff dimensions, trend, and timeline are all derivable
from existing `scans` columns (`package, platform, sha256, score, trust_score, severity summary,
created_at`), existing `findings` columns (`rule_id, severity, confidence, masvs, cwe, file_path,
line_number, snippet`), and the on-disk results.json.

**Optional, minimal, additive (pure performance/robustness — safe idempotent `ALTER`/`CREATE INDEX`,
same pattern as the existing migrations at `database.py:184`):**

1. `findings.fingerprint TEXT` — precomputed stable identity (§4.2). *Benefit:* faster, canonical matching. *Derivable, so optional.*
2. `CREATE INDEX idx_findings_fingerprint ON findings(scan_id, fingerprint)` — fast diff joins.
3. `CREATE INDEX idx_scans_package ON scans(package, created_at)` — fast per-app timeline/trend.
4. *(Optional cache, only if diffs ever feel slow)* `scan_comparisons(base_id, target_id, diff_json, created_at)` — memoize computed diffs. **Not recommended for v1.4** (compute-on-demand is fast enough); listed for completeness.

None of these touch analyzer code, detection, or the results contract. They are index/column
additions guarded by `IF NOT EXISTS` / `PRAGMA table_info` checks.

---

## 6. UI wireframe ideas

**A. History → grouped by Application (new default view, toggle to flat)**
```
Applications                                        [ search ]  [ flat view ]
┌──────────────────────────────────────────────────────────────────────┐
│ com.app.damnvulnerablebank   Android   5 scans   ▸ trend ▁▂▃▅▇        │
│    latest  score 39  ● 3C ● 8H       2026-07-08   [Open] [Compare ▾]   │
│ com.example.shop             Android   2 scans   ▸ trend ▇▅            │
└──────────────────────────────────────────────────────────────────────┘
```

**B. Application page (new): timeline + trend + one-click compare**
```
com.app.damnvulnerablebank · Android
Score trend ────────────●───────●──────●   Findings ▇▅▃  Critical ▂▂▁
[ scan 07-08 ] [ scan 06-30 ] [ scan 06-12 ] …      (click two → Compare)
```

**C. Comparison view (base ← → target); shareable `/compare?base=&target=`**
```
Baseline 06-30 (score 34)  →  Target 07-08 (score 39)      Verdict: ▲ improved
┌ Summary cards ─────────────────────────────────────────────────────────┐
│  +5 New   ▼ 12 Fixed   ⬆ 2 Worsened   ⬇ 4 Improved   Score +5   MASVS +3 │
└─────────────────────────────────────────────────────────────────────────┘
[ New (5) ] [ Fixed (12) ] [ Severity Δ (2) ] [ Confidence Δ ] [ Evidence Δ ]
[ Attack Chains (+1/−0) ] [ MASVS posture ]

New findings
  ● HIGH  Hardcoded AWS Key         app/.../S3.java:42     rule: secret_aws_...
Fixed findings
  ✓ MED   Firebase Realtime DB URL  (was strings.xml:71)   rule: secret_fire...
Severity changes
  ⬆ Insecure WebView   medium → high   app/.../WebActivity.java:88
```

**D. Diff-aware Executive Summary block (top of Comparison)**
> Since the 06-30 baseline: **5 new** findings (1 critical), **12 fixed**, security score
> **+5**, MASVS coverage **+3 categories**. Net posture: **improved**.

**E. Diff row interaction:** each new/fixed/changed finding expands to the same evidence viewer
used elsewhere (reuse, no new evidence rendering), with an A|B split for "evidence changed."

---

## 7. Implementation order

1. **Backend `comparison/` package** — `fingerprint.py`, then `engine.build_full_diff` extending the existing `compare_scans` (add confidence/evidence/MASVS/score dims). Pure, unit-testable, no UI.
2. **`apps.py` + `/api/apps*` endpoints** — group by package, timeline, trend series.
3. **`/api/compare/full` endpoint** — thin handler over `engine`.
4. **Optional indexes/column** (§5) once matching is finalized.
5. **Frontend data layer** — `lib/compare.js` (fetch `/api/compare/full`, `/api/apps*`), replacing `ComparePanel`'s localStorage source with the backend.
6. **Comparison components** — summary cards, diff tabs, severity/confidence/evidence diff rows, chain diff, MASVS posture (`components/compare/`).
7. **Application grouping + trend** in History; new **Application page**.
8. **One-click "Compare with previous"** affordances + deep-linkable `/compare`.
9. **Shared polish** — filter bar, state kit, diff-aware executive summary.
10. **Command palette / density** (stretch).

Each step is independently shippable and reversible; steps 1–4 are backend-only and can land
behind the existing (already-wired) `compare` nav slot before any UI change is visible.

---

## 8. Estimated complexity

| Workstream | Complexity | Notes |
|---|---|---|
| `fingerprint.py` + engine extension | **Medium** | logic over existing data; heavy unit tests, no UI |
| `/api/apps*` + trend | **Low–Medium** | grouping/ordering over `scans` |
| `/api/compare/full` | **Low** | thin wrapper |
| Optional indexes/column | **Low** | idempotent migrations, same pattern as today |
| `lib/compare.js` data layer | **Low** | fetch + shape |
| Comparison components (cards/tabs/diff rows) | **Medium–High** | most of the UI effort; reuse evidence viewer |
| History grouping + Application page + trend chart | **Medium** | new route + chart component |
| Shared filter bar / state kit | **Medium** | cross-surface refactor (UI only) |
| Command palette / density | **Low–Medium** | stretch |

Overall: **Medium.** No engine work; the risk/effort concentrates in comparison UI components.

---

## 9. Risks

- **R1 — Frozen-engine scope creep.** Temptation to "improve" a detector while wiring diffs.
  *Mitigation:* the `comparison/` package lives outside `analyzers/`; a review checklist forbids
  touching detection/scoring/report/auth/Docker.
- **R2 — Finding-match instability.** A naive key makes refactors look like mass churn.
  *Mitigation:* composite fingerprint + "moved/evidence-changed" class + fuzzy same-rule/same-file fallback.
- **R3 — Cross-app comparison confusion.** Users compare unrelated apps.
  *Mitigation:* group by `package`; `same_app` flag + explicit UI warning; default baseline = previous scan of the same app.
- **R4 — Score/severity comparability.** Comparing scans produced by different engine versions could misattribute deltas to the app.
  *Mitigation:* stamp/read the results' engine/version already present; surface a "different engine version" note; never block.
- **R5 — Data availability.** A scan whose results.json was pruned can't show evidence diffs.
  *Mitigation:* degrade gracefully to relational-column diffs (already what `findings` supports); show a "full evidence unavailable" note (mirrors existing `get_scan_results` fallback).
- **R6 — Legacy compare endpoints.** Two endpoints already return the old shape.
  *Mitigation:* keep them unchanged; add `/api/compare/full` alongside; migrate UI to the new one.

---

## 10. Recommended milestone breakdown

**v1.4.0 — Comparison Engine (backend, invisible)**
- `comparison/` package, fingerprint, `build_full_diff` (all dimensions), `/api/compare/full`, `/api/apps*`.
- Unit tests for the comparator only (new tests; existing tests untouched).
- *Exit:* diff object correct for two DVB scans; legacy endpoints unaffected.

**v1.4.1 — Comparison UI**
- `lib/compare.js`, comparison components, wire the existing `compare` nav slot to the backend diff, deep-linkable `/compare`.
- *Exit:* full new/fixed/severity/confidence/evidence/chain/MASVS/score diff renders; shareable URL.

**v1.4.2 — Applications & Trend**
- History grouping by application, Application page, score/severity trend chart, one-click "Compare with previous."
- *Exit:* pick an app → see timeline & trend → compare any two of its scans in two clicks.

**v1.4.3 — Product Polish**
- Shared filter bar + state kit across Findings/History, diff-aware Executive Summary, empty/loading/error consistency.
- *Exit:* consistent filtering and states platform-wide.

**v1.4.4 — Enterprise niceties (stretch)**
- Command palette (⌘K), compact density, saved filters, comparison export (PDF/JSON "delta report").

---

### Appendix — evidence map (files read for this plan)
- Routing/nav: `frontend/src/App.jsx`, `components/workspace2/workspace-sections.js`, `Workspace.jsx`
- Existing compare UI: `components/workspace2/panels2.jsx:1242` (`ComparePanel`)
- Existing diff engine + endpoints: `backend/database.py:817` (`compare_scans`), `backend/main.py:1139/1454`
- Schema: `backend/database.py:76–216` (`scans`, `findings`, migrations), persistence `save_scan` / `get_scan_results`
- History surface: `frontend/src/pages/History.jsx`, `database.py` history query

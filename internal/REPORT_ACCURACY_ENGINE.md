# Report Accuracy & Evidence Rendering Engine (Beetle 2.0 — Phase 1.97)

The Evidence Selection Engine (Phase 1.96) computes the correct, application-owned
**Primary / Supporting / Rejected** proof for every finding. But several report
surfaces still rendered **legacy `file_path`**, so analysts kept seeing wrong proof
files (e.g. *Broken Crypto → `androidx.appcompat…AppCompatDelegateImpl.java`*). This
phase makes **every** surface — PDF, HTML, SARIF, JSON/REST, dashboard, attack
chains, developer guide — render the selected evidence, consistently.

> The objective is not better detection. It is that every consumer surfaces the
> evidence the Intelligence Pipeline already selected.

## Architecture

Two pieces, both additive:

1. **A unified rendering view** — `analyzers/evidence_selection/view.py`:
   `build_evidence_view(finding)` returns the single presentation model every
   renderer consumes; `primary_location(finding)` returns the `(file, line, snippet)`
   to display. It reads the precomputed `evidence_selection` block and falls back to
   legacy fields for any finding that never went through selection. **No rendering
   logic is duplicated and nothing is recomputed at report time.**

2. **A keystone location correction** — during `evidence_selection.annotate` the
   chosen primary is **promoted into the finding's legacy `file_path`/`line`/
   `snippet`** (conservatively: only when the primary is application/manifest-owned
   and differs from the current value). The original detection site is preserved
   under `detected_location` / `legacy_file_path`. This single correction fixes
   **every** consumer that still reads `file_path` — including the baked React
   frontend and any surface not yet migrated to the view.

```
… Ownership → Confidence → Evidence Intelligence → Triage →
   ★ EVIDENCE SELECTION + REPORT ACCURACY ★   (select → stamp evidence_view → correct file_path)
   → Attack Chains → Bug Bounty → reconcile → analyst/MASVS/reports
```

The stage was moved to run **before** Attack Chains so chains reference the corrected
primaries. It depends only on signals already present by then (ownership, confidence,
evidence, reachability, fusion); bridged secret→finding mirrors are skipped so they
never claim a shared proof file.

## The rendering model (`build_evidence_view`)

| Field | Meaning |
|---|---|
| `primary` | the one proof to review: `{file, line, snippet, owner_type, owner_name, source, score, reasons}` |
| `supporting` | other useful application/manifest proofs |
| `additional_references` | non-library extras beyond the supporting cap |
| `hidden_library_evidence` | `{count, owners, items}` — AndroidX/GMS/etc., collapsed by default |
| `evidence_score` / `selection_reason` | the primary's score and why it was chosen |
| `evidence_confidence` | finding confidence (or evidence-bundle quality) |
| `evidence_ownership` / `evidence_source` | owner type + producing engine of the primary |
| `provenance` / `detection_sources` | Fusion metadata + the engines that detected it |
| `reachability` / `in_attack_chain` | analyst context |

No internal scoring implementation details (raw `file_score`, contributor internals)
are exposed.

## Migration

| Surface | Before | After |
|---|---|---|
| **REST / JSON** (`main.py`) | finding dict (`file_path`) | corrected `file_path` + `evidence_view` (auto via serialization) |
| **SARIF** (`sarif_exporter.py`) | `file_path`/`snippet`; `file_evidence[1:4]` | `primary_location()`; related = view `supporting` |
| **PDF** (`report/pdf_generator.py`) | flat `file_evidence`/`file_path` | view: **Primary → Supporting → Hidden library (N)** |
| **Developer Guide** (`report/report_summaries.py`) | `file_path` | `primary_location()` per row |
| **Attack Chains** (`analyzers/attack_chains/engine.py`) | `evidence_bundle.primary` (confidence-only) | view primary (application-owned) |
| **Compliance PDF**, **Dashboard**, **Frontend** | `file_path` | auto-fixed by the keystone correction |

Each migrated consumer imports lazily and falls back to legacy fields, so a missing
selection never breaks a report.

## Rendering hierarchy

Every finding renders in this order: **Primary Evidence** (with its selection
reason) → **Supporting Evidence** → **Additional References** → **Hidden Library
Evidence** (count + owners, expandable). Library/framework/generated proofs are never
shown as the lead; they collapse into the hidden bucket.

## Special cases

- **Manifest / exported components / permissions / deep links** — a synthesized
  `AndroidManifest.xml` (`Info.plist` on iOS) candidate is added and a manifest
  scoring signal makes it the primary, so an exported component points at the
  manifest declaration, not the SDK class that implements it.
- **Secrets / Crypto / WebView** — the ownership-weighted model already prefers the
  application wrapper over framework/library constants.

## Legacy compatibility

- `file_path` is **corrected**, not removed; the original is preserved
  (`detected_location`, `legacy_file_path`).
- The correction is conservative: it never replaces an application location with a
  library one — it only ever improves.
- The view falls back to legacy fields when `evidence_selection` is absent, so
  pre-1.96 data and partial pipelines still render.

## Future extensibility

A future GraphQL API, the Reverse Engineering Workspace, or any new exporter consumes
`build_evidence_view(finding)` — one function, identical evidence everywhere. New
evidence inputs (AI reviewer, runtime, CVE) flow in through the Evidence Selection
Engine's contributor seam (Phase 1.96) and appear in the view automatically.

## Performance

Evidence is selected once and the view is stamped onto each finding during the
pipeline; renderers only read precomputed data. No evidence is recomputed during
report generation.

## Tests

`backend/tests/test_report_accuracy.py` (15 tests): view primary/hidden/detection
sources/fallback, `primary_location`, the Broken-Crypto / Hardcoded-Key AndroidX
regressions, exported-component→manifest, secret→app-file, SARIF location + full
document, developer-guide row, attack-chain aggregation, and JSON/REST serialization.
`backend/tests/test_evidence_selection.py` adds the promotion + library-only
no-false-promotion regressions. Run:

```
cd backend && python -m tests.test_report_accuracy && python -m tests.test_evidence_selection
```

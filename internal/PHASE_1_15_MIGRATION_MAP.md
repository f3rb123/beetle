# Beetle 2.0 — Phase 1.15 Canonical Migration: status & remaining map

**Branch:** `beetle-2.0` · **Scope:** architectural only, no user-visible change.

This phase made `CanonicalFinding` the *spine* of finding handling without
rewriting the dict-based finalize pipeline (which the phase brief forbids:
"do NOT perform a massive rewrite"; "preserve existing behavior and clearly
document the remaining migration point rather than forcing a rewrite").

## Delivered in 1.15

1. **One authoritative legacy↔canonical boundary** — `analyzers/finding_pipeline.py`
   (`to_canonical` / `to_legacy` / `enrich_canonical_fields` / diagnostics).
   These are the edges the upcoming Ownership and Confidence engines plug into:
   each engine calls `to_canonical()` once at entry and `to_legacy()` once at
   exit, so canonical objects flow *through* the engine and legacy dicts live
   only at its edges (the "good" pattern, no dict↔canonical bouncing).
2. **Normalization consolidated to one authority.** `finding_model.normalize_severity_label`
   now delegates to `common.normalize_severity` (the same authority the DB,
   sorting and severity-summary already use, and which `CanonicalFinding` uses).
   Behaviorally identical for every severity producers emit; verified by test.
3. **First live use of the canonical model.** `database.save_scan` runs
   `finding_pipeline.log_canonical_diagnostics` over the final finding set of
   every scan (both platforms). Read-only — no value changes, no serialized
   output — so it cannot regress behavior, while proving on every real scan that
   the model represents the live finding set.
4. **Compatibility tests.** `tests/test_finding_pipeline.py` (lossless round-trip,
   idempotency, mixed lists, additive enrichment, normalization equivalence,
   diagnostics-is-read-only) + the Phase 1.1 model tests. 20/20 pass on stdlib.

## Deliberately NOT migrated yet (with reason)

The live finalize pipeline still passes dicts. Re-typing it now would be the
forbidden big-bang rewrite and is where regressions would hide. Tracked in
`finding_pipeline.MIGRATION_MAP`; ordered by safety/leverage:

| # | Stage | Today | Canonical-native target | Risk |
|---|-------|-------|-------------------------|------|
| 1 | ~25 analyzers' finding production | `dict` literals appended | emit via canonical builder, `to_legacy()` at append edge | medium — many sites; per-analyzer + golden tests |
| 2 | `finding_model` finalize passes | order-dependent dict mutation | `list[CanonicalFinding]`, one `to_canonical` in / `to_legacy` out around the finalize block | high — core noise engine; after #1 |
| 3 | `database.save_scan` findings-table write | `f.get()` → columns; `confidence` stored as str or int | `CanonicalFinding` → row mapper (numeric confidence, normalized line) | low-but-not-zero — changes some internal column values; **deferred to keep stored values byte-identical this phase** |
| 4 | report/SARIF/SBOM + API serializer | read result dict | consume `CanonicalFinding.to_legacy()` at the API edge | low — additive keys |

### Known compatibility traps (do not "consolidate" naively)

- **`common.dedupe_findings` keys on `line_number`**, which `code_analyzer`
  never sets (so SAST findings dedupe at line `0`). `CanonicalFinding.dedup_key`
  reads `line`; swapping it in would change dedup results and finding counts.
  Left exactly as-is.
- **Don't route live serialized findings through `to_legacy`/`enrich`** until the
  consumers expect canonical names — it adds keys to the emitted JSON. Additive
  and frontend-safe, but it changes scan output, so it's a deliberate later step.

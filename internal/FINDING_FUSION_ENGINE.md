# Finding Fusion Engine (Beetle 2.0 — Phase 1.95)

The Fusion Engine is the central intelligence layer that lets Beetle grow from two
detection engines today to **many** (Semgrep, MobSF, YARA, custom rules, AI-generated
findings) **without increasing report noise**. Every detection engine only has to
*emit* canonical-shaped findings; the Fusion Engine is solely responsible for
recognizing when several of them describe the **same logical issue** and folding them
into **one** canonical finding that is "Detected By" all of them — with complete,
explainable provenance.

> The user never sees a duplicate finding just because multiple engines detected it.

```
APK / IPA
  ↓
Detection Sources  (Beetle Native, APKLeaks, … future: Semgrep / MobSF / YARA / AI)
  ↓   each emits canonical findings into results["findings"]
Canonical Finding
  ↓
★ FINDING FUSION ENGINE ★   group → merge → resolve conflicts → stamp provenance
  ↓                          (+ multi-engine agreement signal)
Ownership → Confidence → Secret Intel → Evidence → Triage → Attack Chains → Bug Bounty
```

## Architecture

A dedicated, modular package — fusion logic is **not** spread across analyzers.

```
analyzers/fusion/
  __init__.py   public API: fuse(results, platform=…), identity, conflict, FUSION_VERSION
  config.py     all tunables (line bucket, score weights, category precedence)
  identity.py   engine-independent SEMANTIC identity + data-only alias registry
  conflict.py   deterministic conflict resolution (severity/category/ownership/location)
  engine.py     grouping + merge + provenance + agreement scoring (the pipeline stage)
```

It runs as **one deterministic pipeline stage** over `results["findings"]`, replacing
the old exact-key `common.dedupe_findings` collapse, at the same point in both
`android_analyzer` and `ios_analyzer` — **after** canonicalization, **before** the
Confidence Engine (so the agreement signal can feed confidence).

### Two-layer relationship with `detection_sources/fusion.py`

These compose; neither is redundant:

| Layer | When | Scope | Keyed on |
|---|---|---|---|
| `detection_sources/fusion.py` | detection time | merges detection **streams** (secrets/endpoints) + the secret→finding bridge | exact rule/value |
| `analyzers/fusion/` (this) | finalize | finding-LEVEL **semantic** fusion across ALL engines | semantic identity (CWE/class + location) |

The stream layer collapses Beetle-native + APKLeaks hits that share an exact rule
name up front. This engine is the superset that also unifies **cross-engine
equivalents** — different rule ids, different titles, small line drift — and is the
single seam every future engine flows through.

## Merge strategy

1. **Group by semantic identity** (`identity.fusion_key`):

   ```
   (issue_class, file, line_bucket[, value_fingerprint])
   ```

   - `issue_class` is resolved, in priority order, from: an **alias-registry** entry
     for this `(engine, rule_id)` → the **CWE** id → a normalized `category:title`.
     CWE is the strongest cross-engine signal: Beetle "AWS Access Key ID" and a
     Semgrep "hardcoded-aws-credentials" both carry **CWE-798**, so they land in one
     class even though their rule ids and titles differ.
   - `line_bucket` tolerates small line drift between engines (`config.LINE_BUCKET`,
     default 3) without merging genuinely separate issues — `issue_class` + `file`
     already scope the group.
   - `value_fingerprint` keeps two **different** secret literals in the same file
     apart, while letting two engines on the **same** literal merge.

   Attack-chain findings (`is_attack_chain`) and malformed entries are passed through
   untouched — they are not engine duplicates.

2. **Fold each group** with the existing `CanonicalFinding.merge`, which already
   unions evidence / sources / references / standards (CWE/MASVS/OWASP), keeps the
   higher severity and confidence, and unions `detected_by` / `sources`.

3. **Apply documented conflict resolutions** (below).

4. **Stamp provenance** on every finding (fused *and* singleton).

## Conflict resolution (deterministic + documented)

When engines disagree, `conflict.analyze` resolves and **records** every decision in
`finding["fusion"]["conflicts"]`:

| Field | Rule |
|---|---|
| **Severity** | Most severe wins (`severity_rank`). Tools under-rate as often as over-rate; trust the worst case. |
| **Category** | `config.CATEGORY_PRECEDENCE` — the most security-meaningful label wins (e.g. "Cloud Credentials" over "Secrets"). |
| **Ownership** | Highest `owner_confidence` wins; `Unknown` never beats a concrete owner. |
| **Location** | Primary location taken from the **strongest evidence** (validated > has-snippet > most file-evidence). Only a different file or beyond-bucket line drift counts as a conflict; all locations are retained as `merged_locations`. |
| **Confidence** | Not resolved here — surfaced as `fusion_score` and a documented spread. |

Every resolution is a structured record: `{field, values, chosen, rule}`.

## Confidence boosting (multi-engine agreement)

Confidence is no longer pure per-finding heuristics. The Confidence Engine
(`confidence/engine.py`) reads the Fusion Engine's `detection_count` and applies a
**bounded, explainable bonus** to the *detection* dimension (so it flows through the
existing weights into `overall_confidence` and into the human reason):

- `+AGREEMENT_PER_ENGINE` (default 12) per **additional** independent engine, capped
  at `AGREEMENT_MAX` (default 24).
- Damped by `AGREEMENT_CONFLICT_DAMP` (default ×0.5) when the engines disagree on
  core metadata.

Example reasons:

- *"corroborated by 3 independent engines"* → higher confidence.
- *"corroborated by 3 engines (metadata conflict - corroboration damped)"* → tempered.

This is additive: a finding that never passed through fusion (count ≤ 1) is scored
exactly as before.

## Provenance (exposed on every finding)

| Field | Meaning |
|---|---|
| `detected_by` | list of engines that found it |
| `detection_count` | number of distinct engines |
| `sources` | per-engine detail `[{engine, rule_id, confidence}]` (unioned) |
| `fusion_score` | 0-100 corroboration strength |
| `evidence_count` | distinct evidence locations |
| `merged_files` | every file the issue was seen in |
| `merged_locations` | every `(file, line)` it was seen at |
| `fusion` | full record: `{version, detection_count, engines, sources, evidence_count, merged_files, merged_locations, conflicts, resolutions, score, reason}` |

`fusion_score = BASE(50) + PER_ENGINE(18)·(count−1) + EVIDENCE(4·extra, cap 16) −
CONFLICT_PENALTY(15 if any conflict)`, clamped 0-100.

A per-scan rollup is stored at `results["fusion_summary"]`
(`{version, before, after, groups, merged, multi_engine, passthrough}`).

## Reporting

Because fusion collapses duplicates to one canonical finding, every report (UI / PDF
/ HTML / JSON / SARIF / dashboard) shows **one** finding carrying the `detected_by`
list, `detection_count`, `fusion_score` and the explainable `fusion.reason`, e.g.:

```
AWS Access Key ID                                    CRITICAL
Detected By:  Beetle Native · APKLeaks · Semgrep
Confidence:   95%
Reason:       Detected independently by 3 engines. No metadata conflicts.
```

## Future extensibility

Adding a detection engine requires **no** analyzer, pipeline or engine changes:

1. The engine emits canonical-shaped findings into `results["findings"]` with
   `detected_by` / `sources` (and ideally a CWE).
2. Fusion groups, merges, resolves and scores them automatically.
3. If the engine uses an idiosyncratic rule name that shares neither CWE nor title
   with an existing rule, declare the equivalence with **data only**:

   ```python
   from analyzers.fusion import identity
   identity.register_alias("MobSF", "android_insecure_webview", "cwe-749")
   ```

No engine "knows" about fusion; fusion performs the merge. This is the architectural
seam that keeps report noise flat as the number of detection engines grows.

## Tests

`backend/tests/test_finding_fusion.py` (21 tests): cross-engine CWE unification,
distinct-value / distinct-file separation, alias registry, two/three-engine merge,
partial overlap, severity/category/ownership/location/confidence conflict resolution,
evidence de-dup + merged locations, singleton + unattributed provenance, confidence
agreement boost + conflict damping, attack-chain pass-through, canonical round-trip,
dedupe-superset parity, and malformed-input safety. Run:

```
cd backend && python -m tests.test_finding_fusion
```

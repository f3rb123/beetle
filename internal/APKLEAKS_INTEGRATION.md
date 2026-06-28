# APKLeaks Intelligence Integration (Beetle 2.0 — Phase 1.9)

APKLeaks is integrated into Beetle as **another Detection Source feeding the one
intelligence pipeline** — not as a wrapper, a subprocess, or a second report.
Beetle learns from APKLeaks' curated pattern intelligence and runs it natively, so
every APKLeaks-derived signal becomes a first-class Canonical Finding that flows
through Ownership → Confidence → Secret Intelligence → Evidence → Triage → Attack
Chain → Bug Bounty exactly like a native finding.

```
APK / IPA
  ↓ (jadx + apktool, already done by Beetle)
Detection Sources ── Beetle Native ──┐
                  └─ APKLeaks ────────┤→ fusion (attribution + de-dup)
                  └─ (future: Semgrep / MobSF / YARA)
  ↓
results["secrets"] / results["findings"] / results["endpoints"]
  ↓
Secret Intelligence → masking → secret→finding BRIDGE
  ↓
Ownership → Confidence → Evidence → Triage → Attack Chain → Bug Bounty
```

## Why not a wrapper

The phase brief forbids turning Beetle into an APKLeaks wrapper. APKLeaks the tool
shells out to `jadx`, greps a flat `config/regexes.json`, and emits raw,
ungraded matches grouped by rule (`{"package", "results":[{"name","matches"}]}`) —
no line/snippet, no severity, no confidence, no FP filtering, no ownership, no
dedup. We reuse only its **pattern intelligence**:

- **No `apkleaks` dependency, no subprocess, no jadx re-run, no second report.**
- The ported catalog is plain data consumed by Beetle's own
  `evidence_scanner.scan_file_for_patterns`, so each hit inherits Beetle's
  line/snippet capture, entropy gate, length cap, binary-dump suppression and
  per-file dedup — the context APKLeaks itself never produces.

## Components

| File | Role |
|---|---|
| `analyzers/secret_catalog.py` | The UNIFIED secret pattern catalog. Beetle Native + APKLeaks register here as `provenance`-tagged contributors; `combined()` returns one list so a SINGLE walk applies them all. |
| `analyzers/detection_sources/registry.py` | `DetectionSource` protocol + registry. APKLeaks registers; future non-pattern engines (Semgrep / MobSF / YARA) register the same way. |
| `analyzers/detection_sources/apkleaks_patterns.py` | The APKLeaks slice of the unified catalog: APKLeaks regexes re-expressed in Beetle's pattern dict shape with severity/category/CWE/MASVS/OWASP/confidence + routing `kind` + `redact_context`. |
| `analyzers/detection_sources/routing.py` | Splits the combined-walk hit stream into native (untouched) vs APKLeaks (reshaped + attributed, bucketed by `kind`). |
| `analyzers/detection_sources/apkleaks_source.py` | The registered `DetectionSource` (registry/fallback path): scans via `scan_directory_for_secrets` with the APKLeaks slice, returns attributed secrets/findings/endpoints. |
| `analyzers/detection_sources/fusion.py` | Cross-source de-dup/merge + the masked secret→finding bridge **and its reconcile** (Finding Fusion prep). |
| `analyzers/detection_sources/__init__.py` | `run_detection_sources()` — registry-driven orchestrator for the fallback/standalone path (the primary path uses the combined-catalog walk, not this). |

## The adapter (detection mapping → canonical conversion)

APKLeaks rules carry only `name + regex`. The catalog supplies the missing
security metadata and a routing `kind`:

- `kind="secret"` → `results["secrets"]` (inherits Secret Intelligence + masking).
  **All private-key material — RSA / DSA / EC / OpenSSH / PGP / PKCS#8 — routes
  here** (Priority 1) so it is masked and assessed exactly like a native PEM
  secret. Each private-key rule also sets `redact_context=True` so the windowed
  `code_context` (which can hold raw key body) is dropped at match time.
- `kind="endpoint"` → `results["endpoints"]` (S3/Firebase URLs).
- `kind="finding"` → `results["findings"]` — supported by the router for future
  rules that are neither a secret nor an endpoint. **No current APKLeaks rule uses
  it** (private keys are secrets), so `finding_patterns()` is presently empty.

Each hit is produced in Beetle's existing internal dict shape (so no new finding
model) and stamped with attribution before it ever reaches the pipeline. From
there `CanonicalFinding.from_legacy` carries the attribution losslessly like any
other field.

The catalog **deliberately overlaps** Beetle Native on AWS/Google/Firebase/Stripe/
Twilio/GitHub/Slack/JWT/PEM so the fusion layer can demonstrate cross-source merge;
its net new value is the **gap rules** (Heroku, PayPal/Braintree, Square, Mailgun,
MailChimp, Discord, Facebook/Twitter/Google OAuth, Authorization headers,
RSA/DSA/EC/OpenSSH/PGP key blocks, credentials-in-URL, …).

## Source attribution

`CanonicalFinding` gained two additive, lossless fields (Phase 1.9):

- `detected_by: list[str]` — engine display names, e.g. `["Beetle Native", "APKLeaks"]`.
- `sources: list[dict]` — per-engine detail `[{engine, rule_id, confidence, …}]`.

`source_module` (single producing analyzer) is unchanged. Native detections are
stamped `"Beetle Native"` during fusion so the UI can always show a "Detected By".
`CanonicalFinding.merge` unions both fields, so a merged finding is attributed to
**every** engine that found it.

## Deduplication strategy

`fusion.py` is the single seam where cross-source duplicates collapse:

- **Secrets** — keyed on `(normalized type/name, value)`. A native + APKLeaks hit
  on the same literal becomes ONE secret with `detected_by` unioned and missing
  evidence filled from the newcomer.
- **Findings** — keyed on `CanonicalFinding.dedup_key()` `(rule_id, file_path,
  line, title)`, so it agrees with the pipeline's own `dedupe_findings` and the DB
  uniqueness index. Collisions union via `CanonicalFinding.merge`.

Native detections always keep their position/data; a duplicate only *adds*
attribution. Note `to_legacy()` is non-destructive, so the finding merge explicitly
writes the unioned `detected_by`/`sources` back over the base values.

## The "both stream + bridge" model

Decision (reviewed): APKLeaks secrets land in `results["secrets"]` **and** are
mirrored into `results["findings"]`.

1. They sit in `results["secrets"]`, so they get Secret Intelligence + masking +
   the Secrets section UI, identical to native secrets.
2. After masking, `bridge_secrets_to_findings()` mirrors each APKLeaks-attributed
   secret into `results["findings"]` as a **masked** finding, so it also traverses
   ownership → confidence → evidence → triage → attack-chain → bug-bounty.

Safety + correctness guarantees:

- **Never raw.** The bridge refuses any secret lacking `masked_value`, so a raw
  value can never enter the findings stream. (Test: `test_bridge_refuses_unmasked_secret`.)
- **No double counting.** Bridged findings are de-duplicated via the fusion merge
  and marked `secret_bridge=True` (+ `secret_id`) so reports/UI can recognize a
  finding already shown in the Secrets section. Idempotent across re-runs.
- **Scoped.** `MIRROR_ALL_SECRETS=False` limits the bridge to APKLeaks-attributed
  secrets in this phase (native secret surfacing is unchanged). Flip the flag to
  broaden to every secret — a one-line change.

## Pipeline wiring

- **Detection (primary path)**: a SINGLE combined walk applies
  `secret_catalog.combined()` (native + APKLeaks), then `routing.extract_apkleaks`
  splits the hits and `fusion.merge_*` folds the APKLeaks slice into the native
  streams. Android does this in `_scan_precise_source_secrets`; iOS does it inline
  in its parallel secrets stage. **No second filesystem traversal.**
- **Detection (fallback path)**: when the combined walk is not taken (no-JADX
  Android fallback), `run_detection_sources()` runs the registered APKLeaks source
  as one extra walk and fuses it. iOS has no separate fallback — it always uses the
  combined walk.
- **Bridge**: `bridge_secrets_to_findings()` runs **after** masking and **after**
  `severity_summary` (so bridged copies never inflate the user-facing severity
  counts), and before the ownership→…→bug-bounty engines, so bridged findings are
  scored/enriched like any finding. **Android and iOS place it identically.**
- **Reconcile**: `reconcile_bridged_findings()` runs **after** bug-bounty (the last
  enrichment engine) and **before** analyst/MASVS/workspaces/quick-summary/score/
  reports. It harvests the engine-computed intelligence onto the linked secret and
  REMOVES the bridged copies, so a bridged secret is shown exactly once (Secrets
  view) and never appears as a duplicate finding in UI / PDF / HTML / JSON / SARIF /
  dashboard. **Android and iOS both run it** (its earlier absence on iOS caused
  double-display + inflated iOS summaries — now fixed).

Per-scan stats are recorded under `results["apkleaks_integration"]`
(`detection` + `bridge` + `reconcile`).

## Future Finding Fusion integration

This phase intentionally builds the *seam*, not a full fusion engine:

- The `DetectionSource` protocol + registry make Semgrep / MobSF / YARA / custom
  detectors pluggable with zero pipeline changes.
- `merge_secret_streams` / `merge_finding_streams` are deterministic, key-based
  merges. The Finding Fusion Engine will grow from these by adding fuzzy identity
  (semantic equivalence, location proximity), confidence reconciliation across
  sources, and conflict resolution — without changing the analyzers or the
  canonical model, since attribution already travels on every finding.

## Tests

`backend/tests/test_apkleaks_integration.py` (18 tests): catalog shape/routing
(private keys = secrets + redact_context), source scanning + attribution,
native-only / APKLeaks-only / mixed, duplicate merge (secrets + findings), evidence
merge, bridge masked-only / idempotent / scope, **reconcile removes bridged copies
+ harvests intelligence** (the iOS double-display regression guard), bridged-finding
pipeline pass-through (ownership/confidence/bug-bounty), end-to-end orchestrator,
and canonical round-trip/merge regression. Run:

```
cd backend && python -m tests.test_apkleaks_integration
```

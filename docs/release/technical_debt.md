# Technical Debt — Phase 11.5 Inventory

> Categorized backlog from release-hardening review of the Tier-1 corpus. No new
> engines/detections were added in this phase; items below are tracked, not all
> fixed.

## HIGH

| Item | Detail | Recommendation |
|------|--------|----------------|
| Full-pipeline validation is container-gated | Taint (androguard), Semgrep, manifest enforcement, LIEF, PDF render and real JADX/APKTool timing cannot run on the bare-metal validation host. All Phase 11.5 metrics for those are "container-only". | Stand up a container CI job that runs the three Tier-1 apps end-to-end and publishes `scan_metrics` + a rendered PDF per app. This is the single biggest gap to RELEASE_CANDIDATE. |
| Benchmark baseline drift | Phases 9–11 add many additive result keys (`secrets_summary`, `cloud_exposures`, `cloud_attack_paths`, `analyst_summary`, `masvs_coverage`, per-finding `analyst_explanation`). The committed benchmark baseline predates these. | Regenerate the benchmark baseline in the container and commit it, so quality-gate diffs are meaningful again. |

## MEDIUM

| Item | Detail | Recommendation |
|------|--------|----------------|
| Secret detection coverage gap (InsecureShop) | 0 secrets detected in InsecureShop; its known plant isn't matched by the current pattern set. | Add the missing pattern(s) in a future detection phase (out of 11.5 scope — no new detections). |
| Firebase URL in finding snippets | The Firebase DB URL is masked in the secrets section but appears unmasked in a finding's evidence snippet (it is a public endpoint, not a credential). | Decide policy: either accept (endpoint, not a secret) or extend masking to finding snippets for `FIREBASE_URL`-class values. Document the chosen policy. |
| Ownership certainty on obfuscated apps | DVBA 44 / WaPo 55 ownership-certainty (ProGuard/R8). Drags the trust score's ownership factor. | Improve obfuscated-package heuristics or surface an "obfuscated — ownership uncertain" badge so the lower factor reads as expected, not as a defect. |

## LOW

| Item | Detail | Recommendation |
|------|--------|----------------|
| PDF Strings-section escaping | "Sample Values"/category cells (`pdf_generator.py` ~1210–1225) may bypass `_safe()`. | Wrap in `_safe()` to guarantee no malformed-HTML abort on exotic string values. |
| Validation harness lives in `.tools/` (gitignored) | The offline release harness + decompiled corpus are local scratch. | If continuous validation is desired, promote a trimmed harness into `backend/tests/` with a small fixture, behind the container CI. |
| LF/CRLF noise on Windows | Git warns on every commit (LF→CRLF). | Add a `.gitattributes` normalizing `*.py` to LF. |
| Docs are skeletons | `docs/TRUST_SCORE.md` etc. are skeletons. | Flesh out with worked Tier-1 examples once the container baseline exists. |

## Explicitly out of scope for 11.5

Per the phase brief: no new detections, no new intelligence engines, no trust-score
changes. The detection-coverage and masking-policy items above are recorded for a
later phase.

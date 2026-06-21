# Secret Intelligence

> Skeleton — Phase 11.5. See `docs/PHASE9_SECRET_INTELLIGENCE.md` for the full design.

## What it answers

"Is this secret real, application-owned, usable — and what does it expose?" — not
just "a string looks like a secret".

## Pipeline (Phase 9.x)

| Stage | Module | Output |
|-------|--------|--------|
| Canonical model + masking | `secret_intel.py` | masked `value`, `value_sha256`, evidence gate |
| Cross-secret scrub | `secret_intel.py` | no raw value in any text field |
| Ownership suppression | `secret_intel.py` | APPLICATION/UNKNOWN shown; SDK/framework suppressed |
| Pairing | `secret_intel.py` | AWS/Twilio/Stripe/Firebase/Azure composite pairs |
| Validation gating | `secret_intel.py` + `secret_validators/` | states: skipped/eligible/valid/invalid/error |
| Cloud exposure | `cloud_intel.py` | FIREBASE_PUBLIC_READ, S3_PUBLIC_LISTING, … |
| Correlation | `cloud_correlation.py` | cloud attack paths |

## Safety invariants

- Raw values are **never** serialized — masked at creation, cross-scrubbed,
  transient `_raw` stripped before return.
- Live validation / cloud intel are opt-in (`CORTEX_ENABLE_SECRET_VALIDATION`,
  `CORTEX_ENABLE_CLOUD_INTELLIGENCE`, `CORTEX_ENABLE_CLOUD_CORRELATION`) and OFF in
  benchmark/offline mode.

## Executive summary

`results["secrets_summary"]` — validated/invalid, paired/unpaired,
validation_candidates, suppressed SDK/low-confidence, cloud exposures + chains.

## TODO

- [ ] Per-provider masking examples
- [ ] Validation state machine diagram

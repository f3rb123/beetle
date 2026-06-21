# MASVS Coverage

> Skeleton — Phase 11.5. Expand with control catalog + radar screenshot before GA.

## What it answers

"How much of the OWASP MASVS is implemented?" — posture/coverage, not a
vulnerability count. Lets Beetle say "Cryptography maturity is weak" rather than
"5 crypto findings".

## Where it lives

`backend/analyzers/masvs_intel.py` → `annotate(results)` →
`results["masvs_coverage"]` (per-category) + `results["masvs_summary"]`.

## Model (per category)

`{category, controls_present, controls_missing, score (0–100), maturity
(weak/moderate/strong), confidence, evidence}` for the 8 MASVS v2 categories.

## Scoring

`score = control coverage (≤60) + hygiene (≤40 − severity-weighted weaknesses)`.

## Positive control signals

Network Security Config · Certificate Pinning · No Cleartext · Biometric Auth ·
Keystore/Keychain keys · Encrypted Storage · Root/Tamper Detection ·
Integrity/Attestation · Strong App Signing. Detected over a positive corpus with a
negation guard (so "no certificate pinning" is not counted as present).

## TODO

- [ ] Full control catalog per category
- [ ] Radar visualization in report
- [ ] Tune scoring weights against the Tier-1 corpus

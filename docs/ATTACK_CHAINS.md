# Attack Chains

> Skeleton — Phase 11.5. Expand with chain catalog + diagrams before GA.

## What it answers

"Do these individually-minor findings combine into a real attack path?"

## Two kinds of chains

1. **Finding attack chains** — `backend/analyzers/chain_analyzer.py` synthesizes
   chains from co-occurring findings (exported component + WebView, etc.). Marked
   `is_attack_chain`, lead the findings list.
2. **Cloud attack paths** — `backend/analyzers/cloud_correlation.py` (Phase 9.5)
   correlates secrets + validation state + cloud exposures into
   `results["cloud_attack_paths"]`:
   - `AWS pair + S3_PUBLIC_LISTING → CLOUD_DATA_EXPOSURE_CHAIN`
   - `Firebase + FIREBASE_PUBLIC_READ/WRITE → FIREBASE_EXPOSURE_CHAIN`
   - `Google key + GOOGLE_KEY_UNRESTRICTED → GOOGLE_API_EXPOSURE_CHAIN`

## Confidence

HIGH = validated credential + confirmed exposure · MEDIUM = unvalidated +
confirmed exposure · LOW = credential only (suppressed).

## TODO

- [ ] Full chain-rule catalog
- [ ] Component/evidence rendering in UI + PDF
- [ ] Worked example: AWS → public S3

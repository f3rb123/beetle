# False-Positive Inventory — Tier-1 Corpus

> Phase 11.5. Measured over DVBA / InsecureShop / Washington Post (offline harness).
> No new suppression logic was added in this phase — this is an inventory and a
> prioritized backlog.

## Measured suppression (already working)

| Mechanism | DVBA | InsecureShop | WaPo | Where |
|-----------|-----:|-------------:|-----:|-------|
| Findings refined/suppressed | 3 | 1 | 2 | `finding_model.refine_findings` |
| SDK secrets suppressed | 0 | 0 | 4 | `secret_intel` ownership collapse |
| Low-confidence secrets suppressed | 0 | 0 | 3 | `secret_intel` confidence gate |
| Paired members hidden | 2 | 0 | 2 | `secret_intel` pairing |

Ownership suppression and the secret evidence/confidence gates are functioning on
real data — none of the suppressed items are lost (they remain in
`suppressed_findings` / `suppressed_secrets`).

## Inventory by class

### 1. TensorFlow / ML-library noise
- **Frequency (Tier-1):** not observed in these three apps (none ship TensorFlow).
- **Root cause:** large vendored ML libs match generic SAST/secret patterns in
  framework code.
- **Suppression recommendation:** covered by ownership classification
  (`THIRD_PARTY_LIBRARY` → suppressed). Add `org.tensorflow.` / `libtensorflow`
  prefixes to the library table if it surfaces in a Tier-2 app.
- **Priority:** LOW (no occurrence in corpus; mechanism already exists).

### 2. Certificate-metadata noise
- **Frequency:** present as INFO/context across apps (signing scheme, cert fields).
- **Root cause:** certificate findings describe configuration, not a proven
  exploit; they can read as actionable when they are not.
- **Suppression recommendation:** keep as INFO; the analyst explanation now carries
  a false-positive note ("may not be actionable on modern v2+/v3 devices"). No
  hard suppression — it is useful context.
- **Priority:** LOW (already de-escalated + annotated).

### 3. SDK / third-party noise
- **Frequency:** WaPo — 4 SDK secrets suppressed; finding-level SDK noise removed
  by ownership filtering.
- **Root cause:** analytics/ads/crash SDKs embed their own keys and match rules.
- **Suppression recommendation:** working as designed (default view =
  application-owned). Keep the suppressed-count visible for transparency.
- **Priority:** LOW (mechanism validated on WaPo).

### 4. Unresolved findings
- **Frequency:** **0** across all three (source resolution 100 %).
- **Root cause:** n/a in corpus.
- **Suppression recommendation:** the Phase-5 unresolved-evidence cap already
  drops/penalizes findings whose claimed source cannot be resolved.
- **Priority:** LOW (no occurrence).

### 5. View-code failures
- **Frequency:** **0** across all three (view-code coverage 100 %).
- **Root cause:** n/a in corpus (jadx sources persisted and resolvable).
- **Suppression recommendation:** none needed; monitor on Tier-2 apps with native
  or heavily-obfuscated code.
- **Priority:** LOW (no occurrence).

## Notes / open items

- **InsecureShop secret detection = 0.** Its known plant is not matched by the
  current secret pattern set. This is a **detection-coverage** gap, not a false
  positive — out of scope for 11.5 (no new detections), tracked in
  `technical_debt.md`.
- **Firebase URL in finding snippets.** The Firebase DB URL appears (unmasked) in
  a finding's evidence snippet. It is a public network endpoint (also listed under
  endpoints), not a credential — see `pdf_validation_report.md` for the leak
  characterization.

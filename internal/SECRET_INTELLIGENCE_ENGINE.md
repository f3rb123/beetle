# Beetle 2.0 — Secret Intelligence Engine

**Phase:** 1.4 · **Branch:** `beetle-2.0` · **Scope:** secret detection quality only.

> *"A value should not become a security finding simply because it matches a
> regular expression."*

The Secret Intelligence Engine validates every detected value through multiple
independent, deterministic signals before it is treated as a real secret. It
dramatically reduces false positives and gives genuine secrets richer, explainable
metadata. It is **not** another regex scanner — existing detectors still find
candidates; this engine decides what they actually are.

This phase **only** improves secret quality: no suppression, no severity changes,
no UI/report changes.

---

## 1. Architecture

```
analyzers/secret_intelligence/
  __init__.py   public API (assess, annotate, get_engine, …)
  config.py     THE tuning file — weights, thresholds, FP vocab, known examples
  patterns.py   secret-type DB + deterministic validators (entropy/base64/hex/
                uuid/JWT/PEM/CRC32 checksum/Luhn)
  engine.py     the multi-stage pipeline + SecretAssessment + annotate()
```

Same shape as the Ownership and Confidence engines: pure, deterministic, cached
singleton; data in `config.py`/`patterns.py`, logic in `engine.py`. Offline only —
live probing remains in the separate `secret_validator`.

### Metadata attached
Each secret gets a nested `secret_intelligence` assessment (plus flat
`secret_status` / `secret_overall_confidence`), and the `CanonicalFinding` carries
a `secret_intelligence` dict for secret-bearing findings. **The raw value is never
stored** in the assessment — only derived signals (entropy, format flags, status).

---

## 2. Pipeline (validation stages)

```
raw value + context
  → 1. Type classification     value format → secret_type + provider (patterns.py)
  → 2. Context analysis        file_path → context kind (BuildConfig/manifest/xml/…)
  → 3. Ownership analysis      reuse the Ownership Engine (app vs SDK vs framework)
  → 4. Entropy analysis        Shannon entropy — one signal, never alone
  → 5. Format validation       length/prefix/charset, base64/hex/UUID, JWT/PEM structure
  → 6. Checksum validation     deterministic where possible (GitHub CRC32, Luhn)
  → 7. Provider validation     combine format + checksum into a provider verdict
  → 8. Environment classify    production / test / example / unknown
  → 9. False-positive detect   known examples, placeholders, crypto vectors, public material
  → 10. Confidence scoring     detection / ownership / evidence / validation / overall
  → 11. Final classification   one Status
```

`annotate(results)` runs in both orchestrators **before** `secret_intel`
masks values (it needs raw values), guarded, additive-only. It enriches
`results['secrets']` and secret-bearing findings, and emits
`results['secret_intelligence_summary']`.

---

## 3. Secret types & providers

`patterns.py` ships a priority-ordered type database (public material first so a
public key/cert is never called a secret), covering: AWS, Google/Firebase (incl.
FCM), GitHub (classic + fine-grained, with **CRC32 checksum**), GitLab, Slack
(token + webhook), Stripe (secret/publishable, live/test), Twilio, SendGrid,
Mailgun, OpenAI, Anthropic, Telegram, Discord, Mapbox, npm, Square, Shopify,
DigitalOcean, Heroku, Azure; JWT; RSA/EC/DSA/OpenSSH/PGP private keys; public
keys & certificates; SSH keys; basic-auth URLs; UUIDs; and generic hex/base64
fallbacks. Adding a provider = one `_t(...)` record.

---

## 4. Deterministic validation

> *"Prefer deterministic validation over heuristics whenever possible."*

* **GitHub checksum** — the 6-char suffix is `base62(crc32(body))`; a real token's
  checksum holds, a fabricated one fails (a strong, deterministic discriminator).
* **JWT structure** — three segments; header base64url-decodes to JSON with `alg`.
* **PEM structure** — matching BEGIN/END and a base64 body.
* **base64 / hex / UUID** — strict structural validity.
* **Luhn** — for card-like numbers.
* **Entropy** — Shannon bits/char, used only to corroborate (never alone, and
  never on strings shorter than `ENTROPY_MIN_LENGTH`).

---

## 5. False-positive handling

Actively recognizes non-secrets: famous documentation/example credentials (the
AWS docs access/secret keys, the jwt.io canonical token, the Stripe docs test key,
the Google "AIza…Example" key). These are stored as **SHA-256 hashes**, never as
literals, so the repo carries no provider-format strings — detection still works
because scanned values are hashed at runtime. Also: FIPS-197/NIST AES
test vectors and common IV/zero constants; nil/degenerate UUIDs; placeholder text
(`your_…`, `changeme`, `example`, `<insert…>`, …); near-constant low-entropy
garbage; public keys & certificates (→ Public Value); and crypto-library constants
(e.g. BouncyCastle hex) by **ownership** (→ Generated Constant). Sample/test/docs
**paths** set the environment and dampen confidence.

---

## 5a. AWS detection philosophy & Cognito coverage

AWS appears in mobile apps as both **credentials** and **configuration identifiers**,
and Beetle deliberately reports both — but classifies them honestly so a config id is
never dressed up as a live key.

**Credentials** (high severity, treated as live until rotated):

| Identifier | Prefix / shape | Rule |
|---|---|---|
| Access Key ID (long-term) | `AKIA…16` | `beetle_native` AWS Access Key ID |
| STS / temporary key | `ASIA…16` | `coverage` `cov_aws_sts_key` |
| IAM principal unique id | `AROA/AIDA/AGPA/…16` | `coverage` `cov_aws_iam_unique_id` |
| Secret access key | 40-char base64 | `beetle_native` AWS Secret Key |

**Cognito / configuration identifiers** (recon signal, not a credential by itself —
reported at lower exploitability with a `CWE-200` info framing):

| Identifier | Shape | Rule |
|---|---|---|
| **Cognito Identity Pool** | `region:uuid` (e.g. `us-east-1:7e94…65c1c`) | `coverage` `cov_aws_cognito_identity_pool` |
| **Cognito User Pool** | `region_id` (e.g. `us-east-1_aBcD1234X`) | `coverage` `cov_aws_cognito_user_pool` |
| ARN (account id) | `arn:aws:…:123456789012:…` | `coverage` `cov_aws_account_arn` |
| CloudFront distribution | `…​.cloudfront.net` | `coverage` `cov_cloudfront_url` |

**Why configuration identifiers are reported.** A Cognito Identity Pool with
unauthenticated/guest access enabled, or an over-broad guest IAM role, can grant
real access to AWS resources *without any key* — so the pool id is the finding. A
User Pool id enables account enumeration / unauthenticated sign-up abuse when
self-service registration is open. These are surfaced as **low-exploitability recon
identifiers**, not as critical secrets, keeping the report honest while never
silently missing what a mature scanner (MobSF) surfaces.

The Identity Pool (colon-separated `:uuid`) and User Pool (`_id`) patterns use
**disjoint separators**, so a single value never double-reports as both — no
duplicate findings. All of these flow through the one unified `secret_catalog`
combined walk (provenance `coverage`) → Secret Intelligence → fusion → evidence
selection, exactly like every other secret. **App Client IDs** (26-char
lowercase-alnum) are *intentionally not* value-regex'd: that shape is
indistinguishable from countless non-secret tokens and would inflate false
positives — they are left to be surfaced by context adjacent to a detected pool,
matching Beetle's minimize-FP philosophy (and MobSF itself relies on key-name
heuristics, not a value regex, for them).

**MobSF benchmark.** The MobSF v4.4.6 comparison flagged one missed value —
`aws_Identity_pool_ID` = `us-east-1:7e9426f7-42af-4717-8689-00a9a4b65c1c`. MobSF
surfaces it via its key-name heuristic (`is_secret_key` matching `aws`/key-value
pairs) plus entropy; Beetle now detects it via a precise **value regex**, which is
more specific (no reliance on the surrounding key name) and carries Beetle's
file+line evidence and explainable confidence. With Cognito Identity **and** User
Pool added, the known AWS benchmark gap vs MobSF is closed. See
`internal/DETECTION_COVERAGE_ENGINE.md` for the benchmark engine and corpus.

---

## 6. Ownership awareness

The engine calls the **Ownership Engine** directly (no duplicated logic). A value's
owner drives both `ownership_confidence` and false-positive logic: a key in
first-party `Application`/BuildConfig code is high-value; the identical bytes inside
`AndroidFramework`, a `GoogleSDK`, `OpenSourceLibrary` (BouncyCastle) or
`GeneratedCode` are demoted or reclassified as constants.

---

## 7. Confidence & status

Five explainable dimensions (each 0-100): **detection** (format strength),
**ownership** (relevance by owner), **evidence** (file/line/snippet × context
weight), **validation** (format + checksum + entropy − FP penalty), and a weighted
**overall** (`0.30·detection + 0.35·validation + 0.15·ownership + 0.20·evidence`,
all in `config.py`).

Final **status** (every value ends in exactly one): `Validated Secret`,
`Probable Secret`, `Possible Secret`, `False Positive`, `Documentation Example`,
`Public Value`, `Generated Constant`, `Unknown`. Reject classes force `overall`
low so the number reflects "is this a real, live secret"; the dimensions stay
independent so the breakdown still explains *why*.

### Explainability
Every assessment carries `reasons`: why **detected**, why **classified**, why the
**provider** was selected, why the **confidence**, and (if rejected) why
**rejected**.

---

## 8. Extensibility

* New provider/type → one record in `patterns.py`.
* New placeholder/example/test-vector → one line in `config.py`.
* New checksum/format validator → a small pure function in `patterns.py` + a
  `checksum`/`structure` key on the record. Engine logic is untouched.

---

## 9. Future integration

| Consumer | Uses |
|----------|------|
| **AI Reviewer** | feed `secret_intelligence` (status, reasons, breakdown) as context; focus the model on `Possible`/`Unknown` |
| **Bug Bounty Mode** | surface only `Validated`/`Probable` secrets in app-owned, production context |
| **Confidence Engine** | a validated/probable secret already raises finding confidence; this gives a richer secret-specific signal |
| **Report Engine** | status badges, "verified secrets" sections, FP counts, provider inventory |
| **SDK Suppression** | combine secret `owner_type` + status to group library/example noise |

---

## 10. Compatibility & testing

* **Additive only.** `annotate()` writes `secret_intelligence` / `secret_status` /
  `secret_overall_confidence` via `dict.update`; it never removes, re-severities,
  or masks (masking stays in `secret_intel`, which still runs after). Existing
  detection is unchanged.
* **Tests:** `backend/tests/test_secret_intelligence.py` (20 cases) — real vs fake
  AWS/Google/Stripe/Twilio/GitHub/SendGrid, JWT vs example JWT, private vs public
  keys & certs, AWS/jwt.io doc examples, placeholders, crypto vectors, degenerate
  UUIDs, BouncyCastle/generated constants, high/low-entropy garbage, ownership
  influence, environment/context, determinism, explainability, and the
  non-destructive + regression guarantee (genuine secrets stay detected, known
  FPs rejected). The Phase 1.1/1.15/1.2/1.3 suites continue to pass.

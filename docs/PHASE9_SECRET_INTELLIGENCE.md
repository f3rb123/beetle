# Phase 9 — Secret Validation & Cloud Exposure Intelligence

> **Status:** Design / architecture only. No implementation in this document.
> **Goal:** Move Beetle from *"a string looks like a secret"* to *"this secret is
> usable, owned by the application, and grants concrete privileges."*
> Think TruffleHog + Semgrep + MobSF + analyst workflow — but quiet by default.

---

## 0. Design Principles

1. **Evidence or it didn't happen.** No secret is reported without a source file,
   a line number, and a masked snippet. (`No evidence → no finding.`)
2. **Never emit raw secret values.** Reports, SSE, PDF, and the API surface only
   ever see masked values. The raw value lives only long enough to validate, then
   is dropped from the serialized record.
3. **Application-owned by default.** Third-party SDK / framework secrets are
   classified, counted, and *suppressed* from the primary view — not deleted.
4. **Validation is optional and safe.** Offline scans must never break. Live
   probing is read-only, rate-bounded, and gated behind `CORTEX_DISABLE_LIVE_CHECKS`.
5. **Benchmarks are deterministic.** Benchmark mode disables all network
   validation so results never depend on a live credential's state.
6. **Additive, not destructive.** Phase 9 layers on top of the existing
   `results["secrets"]` pipeline; it does not rewrite detection.

---

## 1. Where Phase 9 Fits (current state)

Phase 9 is **not** a greenfield. The following already exist and are reused:

| Concern | Existing module | Reused as |
|---------|-----------------|-----------|
| Detection (regex + entropy) | `evidence_scanner.SECRET_PATTERNS_EVIDENCE` (~50 patterns) | **Detection layer** |
| Evidence attribution (file/line/snippet) | `evidence_scanner.make_finding` / `scan_directory_for_secrets` | **Evidence model** |
| Live probing | `secret_validator.validate_secrets` (live/invalid/unknown) | **Validation layer** (extended) |
| Ownership vocabulary | `finding_model.classify_ownership_label` (`APPLICATION`/`THIRD_PARTY_LIBRARY`/`GOOGLE_SDK`/`FIREBASE`/…) | **Ownership classifier** |
| SDK-secret separation | `results["sdk_secrets"]` list | **Suppressed SDK bucket** |
| Cloud probing | `live_checks.check_firebase_db` / `check_s3_buckets` | **Cloud intelligence layer** |
| Confidence / trust | `finding_model.compute_confidence`, `trust_engine.evidence_quality` | **Confidence model** |

### Gaps Phase 9 must close

- **G1 — No masking.** Secrets currently carry a raw `value`. There is no
  `masked_value` and raw values reach the serialized blob. *(Safety-critical.)*
- **G2 — Validation is always-on.** `validate_secrets` is called unconditionally
  at `android_analyzer.py:769` and **ignores** `CORTEX_DISABLE_LIVE_CHECKS`. It
  must become opt-in and benchmark-safe.
- **G3 — No privilege enumeration.** Validation returns only live/invalid. There
  is no notion of *what the credential can do* (S3 read, mail send, repo scope).
- **G4 — AWS can't be validated.** `_probe_aws` returns `unknown` because the
  detector finds the access-key ID and secret key independently and never pairs
  them. Phase 9 introduces **secret pairing**.
- **G5 — No canonical secret object.** Secrets are loose dicts with inconsistent
  keys (`name` vs `title`). Phase 9 defines one canonical model.
- **G6 — No secrets executive summary.** No aggregate "validated / invalid /
  public DB / high-risk" rollup exists.

---

## 2. Layered Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        PHASE 9 SECRET INTELLIGENCE                      │
│                                                                        │
│  ┌────────────────┐   raw candidates    ┌──────────────────────────┐  │
│  │ DETECTION      │ ──────────────────▶ │ NORMALIZATION             │  │
│  │ layer          │                     │ → CanonicalSecret objects │  │
│  │ (regex+entropy)│                     │ → mask value (G1)         │  │
│  │ evidence_scanner│                    │ → pair related keys (G4)  │  │
│  └────────────────┘                     └────────────┬─────────────┘  │
│                                                       │                 │
│                          ┌────────────────────────────▼─────────────┐  │
│                          │ OWNERSHIP CLASSIFIER                       │  │
│                          │ APPLICATION / THIRD_PARTY_LIBRARY /        │  │
│                          │ FRAMEWORK   (finding_model)                │  │
│                          │ → suppress non-APPLICATION (count only)    │  │
│                          └────────────────────────────┬─────────────┘  │
│                                                       │                 │
│        live? (CORTEX_DISABLE_LIVE_CHECKS off)         │                 │
│        benchmark? → SKIP                               ▼                 │
│   ┌──────────────────────┐    ┌──────────────────────────────────────┐ │
│   │ VALIDATION layer     │    │ CLOUD INTELLIGENCE layer              │ │
│   │ provider probes      │    │ Firebase / S3 / Azure enumeration     │ │
│   │ → valid / invalid /  │    │ → public read / write / authenticated │ │
│   │   unknown            │    │ → only emit if exposed                │ │
│   │ → privileges/scopes  │    └──────────────────────────────────────┘ │
│   └──────────┬───────────┘                                              │
│              ▼                                                          │
│   ┌──────────────────────────────────────────────────────────────┐    │
│   │ SCORING                                                        │    │
│   │ confidence (HIGH/MED/LOW) · exposure_score · exploitability    │    │
│   └──────────────────────────┬───────────────────────────────────┘    │
│                              ▼                                          │
│   ┌──────────────────────────────────────────────────────────────┐    │
│   │ PRESENTATION                                                   │    │
│   │ Executive Secrets Summary · masked findings · suppressed count │    │
│   └──────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
```

### 2.1 Detection layer

Unchanged in spirit. `evidence_scanner` continues to walk the decompiled trees
and emit candidate matches with file/line/snippet. Phase 9 adds a thin
**provider tagging** step: each pattern is annotated with a stable
`provider` (e.g. `AWS`, `STRIPE`, `GITHUB`) and a `type`
(e.g. `AWS_ACCESS_KEY`, `STRIPE_SECRET`). This makes downstream routing to the
correct validator deterministic instead of matching on free-text `name`.

### 2.2 Normalization layer (new)

Converts loose detector dicts into `CanonicalSecret` objects (§3). Responsibilities:

- **Mask** the value immediately (G1). The raw value is held in a transient,
  non-serialized field (`_raw`) used only by the validation layer, then cleared.
- **Pair** related credentials (G4): an `AWS_ACCESS_KEY` (`AKIA…`) co-located with
  an `AWS_SECRET_KEY` in the same file/module is fused into one validatable unit.
  Same for Twilio SID+token, Azure account+key.
- **Deduplicate** across detectors (the JS-bundle and dex scanners can re-emit the
  same secret — existing dedup logic at `android_analyzer.py:796` is reused).

### 2.3 Ownership classifier

Reuses `finding_model.classify_ownership_label`. Each `CanonicalSecret` gets:

- `APPLICATION` — first-party app package, app config, resources, manifest.
- `THIRD_PARTY_LIBRARY` — known SDK packages (`com.facebook.*`, `io.sentry.*`, …).
- `FRAMEWORK` — platform / language runtime (`android.*`, `java.*`, `androidx.*`).

**Default behavior:** only `APPLICATION` secrets are shown. `THIRD_PARTY_LIBRARY`
and `FRAMEWORK` secrets are moved to a suppressed bucket and surfaced only as a
count (e.g. *"14 SDK secrets suppressed"*), mirroring the existing
`results["sdk_secrets"]` pattern. Nothing is discarded — an "All Secrets" view can
restore them.

### 2.4 Validation layer

Optional, read-only probing. Routed by `provider`. Returns a `validation_result`:

| Result | Meaning |
|--------|---------|
| `valid` | Issuer API confirmed the credential is live |
| `invalid` | Issuer API rejected the credential |
| `unknown` | Network error / timeout / insufficient data to validate |
| `skipped` | Validation disabled (offline / benchmark / no validator) |

When valid, the validator additionally returns **privileges/scopes** (G3) — e.g.
`["s3:GetObject", "dynamodb:ListTables"]`, `["mail.send"]`, `["repo", "read:org"]`.

### 2.5 Cloud intelligence layer

For secrets that point at a *data store* rather than an API credential (Firebase
URL, S3 bucket, Azure storage), this layer answers **exposure** questions:
public read? public write? authenticated only? It reuses and extends
`live_checks.check_firebase_db` / `check_s3_buckets`. A finding is generated
**only if the store is actually exposed** — a Firebase URL that returns 401 is not
a finding, it's evidence the rules are correct.

### 2.6 Scoring & presentation

The canonical object carries `confidence`, `exposure_score`, and
`exploitability_score` (§6). Presentation renders an **Executive Secrets Summary**
plus masked, application-owned findings (§7 / §14).

---

## 3. Canonical Secret Model (Task 1)

A single object every secret is normalized into. JSON-serializable; raw value is
**never** part of the serialized form.

```jsonc
{
  "id":            "BEETLE-SECRET-<sha1[:10]>",   // stable across rescans
  "provider":      "AWS",                          // AWS | GOOGLE | FIREBASE | STRIPE | TWILIO | SENDGRID | GITHUB | AZURE | ...
  "type":          "AWS_ACCESS_KEY",               // see enumeration below
  "ownership":     "APPLICATION",                  // APPLICATION | THIRD_PARTY_LIBRARY | FRAMEWORK
  "owner_package": "com.example.app.net",          // from finding_model

  "evidence": {                                    // REQUIRED — no evidence, no finding
    "file_path": "sources/com/example/app/Api.java",
    "line":      42,
    "snippet":   "String key = \"AKIA****************\";",  // masked
    "code_context": "…masked multi-line…"
  },

  "masked_value":  "AKIA************GH7Q",          // ONLY masked form is serialized
  "value_sha256":  "<hash>",                        // for dedup / cache key, not reversible

  "confidence":    "HIGH",                          // HIGH | MEDIUM | LOW
  "validated":     true,                            // convenience boolean (== validation_result=="valid")
  "validation_result": "valid",                     // valid | invalid | unknown | skipped
  "privileges":    ["s3:GetObject", "dynamodb:ListTables"],

  "exposure_score":       72,                       // 0-100, how reachable/exposed the secret is
  "exploitability_score": 88,                       // 0-100, blast radius if abused

  "severity":      "critical",                      // derived; bumped on valid
  "paired_with":   ["BEETLE-SECRET-<id>"],          // e.g. access key ↔ secret key
  "suppressed_reason": ""                           // non-empty when hidden (e.g. "third_party_sdk")
}
```

### Provider / type enumeration (initial)

| `provider` | `type` values |
|-----------|---------------|
| `AWS`     | `AWS_ACCESS_KEY`, `AWS_SECRET_KEY`, `AWS_SESSION_TOKEN` |
| `GOOGLE`  | `GOOGLE_API_KEY` (sub-typed: `MAPS` / `PLACES` / `FIREBASE` / `UNKNOWN`) |
| `FIREBASE`| `FIREBASE_URL`, `FIREBASE_REALTIME_DB`, `FIRESTORE` |
| `STRIPE`  | `STRIPE_SECRET`, `STRIPE_PUBLISHABLE` |
| `TWILIO`  | `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` |
| `SENDGRID`| `SENDGRID_API_KEY` |
| `GITHUB`  | `GITHUB_PAT`, `GITHUB_FINE_GRAINED_PAT` |
| `AZURE`   | `AZURE_STORAGE_KEY`, `AZURE_CONNECTION_STRING` |

(Existing detectors for Slack, OpenAI, Anthropic, Mailgun, etc. continue to map
into this model with their own `provider`; the table above is the Phase 9
*validation-prioritized* set.)

### Masking rules

- Show a provider-recognizable prefix + last 4 chars; mask the middle.
  `AKIAIOSFODNN7EXAMPLE → AKIA************MPLE`.
- Tokens shorter than 12 chars are fully masked except a 2-char prefix.
- PEM / connection strings collapse to `<REDACTED PRIVATE KEY>` /
  `<REDACTED CONNECTION STRING>` — never partially shown.
- Masking happens in the **normalization layer**, before any serialization,
  logging, or SSE emission.

---

## 4. Ownership Model (Task 2)

```
classify(secret.evidence.file_path, app_package)
   ├── APPLICATION          → SHOW
   ├── THIRD_PARTY_LIBRARY   → SUPPRESS (count in "Suppressed SDK secrets")
   └── FRAMEWORK             → SUPPRESS (count)
```

- Default report = `APPLICATION` only.
- Display a single line: **"N SDK/library secrets suppressed"** with an expandable
  detail view.
- Rationale: a Firebase or Crashlytics key shipped *inside* a vendored SDK is the
  SDK author's design choice, not the app's vulnerability. Surfacing them is the
  #1 source of secret-scanner noise.

---

## 5. Validation Layer Strategy (Task 3)

### Activation matrix

| Mode | `CORTEX_DISABLE_LIVE_CHECKS` | Benchmark flag | Validation |
|------|------------------------------|----------------|-----------|
| Offline scan | `1` | — | **OFF** (`skipped`) |
| Benchmark | (forced) | on | **OFF** (deterministic) |
| Standard live scan | unset | off | **ON** |

> **Fix for G2:** `validate_secrets` must check `CORTEX_DISABLE_LIVE_CHECKS` (and a
> new explicit `CORTEX_VALIDATE_SECRETS` opt-in, defaulting off in benchmark runs)
> *before* issuing any network call. Today it does not.

### Contract for every provider validator

- **Read-only.** Never create, modify, send, or delete. The single tolerated
  exception is a benign no-op probe (e.g. Slack webhook empty POST that the API
  rejects with `no_text`) — already used and acceptable because it has no effect.
- **Bounded.** 6s timeout per probe (existing `PROBE_TIMEOUT`), max 8 concurrent
  (existing `ThreadPoolExecutor`), one attempt — no retries.
- **Privilege-aware.** On `valid`, attempt a *least-privilege* capability probe to
  populate `privileges` (e.g. STS GetCallerIdentity → then a single
  `s3:ListBuckets` HEAD). Capability probing is itself read-only and best-effort;
  failure downgrades to `valid` with empty `privileges`, never to `invalid`.
- **Fail safe.** Any exception → `unknown`. Never raise into the scan pipeline.

---

## 6. Per-Provider Intelligence

### 6.1 AWS (Task 4)

- **Detect:** access key (`AKIA[0-9A-Z]{16}`), secret key (40-char base64-ish),
  session token. **Pair** access+secret in the normalization layer (G4) — without
  the pair, AWS can only be reported as *detected*, never *validated*.
- **Validate:** sign an `sts:GetCallerIdentity` request (SigV4) with the paired
  credentials. 200 → `valid` (returns account/ARN); 403 `InvalidClientTokenId` /
  `SignatureDoesNotMatch` → `invalid`.
- **Privileges:** best-effort read-only probes — `s3:ListBuckets`,
  `dynamodb:ListTables`, `lambda:ListFunctions`, `sns:ListTopics`,
  `sqs:ListQueues`. Each success appends to `privileges`. Access-denied is
  expected and simply omits that privilege.
- **Output example:**

  ```
  AWS Credentials  —  Valid: YES
  Privileges: S3 (read), DynamoDB (list)
  Exploitability: HIGH
  Credentials: AKIA************MPLE / wJal****…  (masked)
  ```

### 6.2 Firebase (Task 5)

- **Detect:** Firebase URL / Realtime DB / Firestore project ref.
- **Probe:** `GET <db>/.json` for read; a Firestore REST list for collections.
  Determine **public read / public write / authenticated**. Write is probed only
  by checking rules metadata where available — *no data is written*.
- **Enumerate** top-level collections/keys *safely* (read-only, capped count, no
  recursion into large trees). Extends existing `check_firebase_db`.
- **Finding only if exposed.** 401/permission-denied → no finding (rules correct).

### 6.3 Google API Keys (Task 6)

- **Distinguish** by usage signals + a metadata probe: Maps, Places, Firebase.
- **Restriction check:** call a cheap endpoint for the key's API; an unrestricted
  key returns 200, a restricted key returns `API_KEY_*` restriction errors.
- **Suppress harmless keys.** A correctly application-restricted Maps key is
  `INFO` and not surfaced as a vulnerability.

### 6.4 Stripe (Task 7)

- `sk_live_…` → `STRIPE_SECRET` → **CRITICAL**; validate via `GET /v1/balance`.
- `pk_…` publishable → `STRIPE_PUBLISHABLE` → **INFO** (expected in clients), no
  finding unless explicitly requested.
- Validation optional; severity does not depend on it.

### 6.5 GitHub (Task 8)

- Detect classic PATs (`ghp_…`) and fine-grained (`github_pat_…`).
- Validate via `GET /user`; read scopes from the `X-OAuth-Scopes` response header.
- Report token validity + scope list. Mask token (`ghp_****…****`).

### 6.6 SendGrid (Task 9)

- Validate via `GET /v3/user/profile`; enumerate scopes via `GET /v3/scopes`.
- Risk score keys on whether `mail.send` is present (active mail-send = HIGH).

### 6.7 Twilio (Task 10)

- Pair `AC…` Account SID with auth token. Validate via
  `GET /2010-04-01/Accounts/<SID>.json` (Basic auth).
- Capabilities: from account status / connected numbers (read-only). Valid token =
  account takeover class.

### 6.8 Azure (Task 11)

- Detect storage account keys and connection strings.
- Determine access level by a read-only `List Containers` against the Blob
  endpoint derived from the connection string. Exposed write access = CRITICAL.

---

## 7. Evidence Model (Task 12)

Every emitted secret **must** carry:

- `evidence.file_path` (resolvable by `scan_storage.resolve_source_file`),
- `evidence.line` (> 0),
- `evidence.snippet` (masked).

Enforcement mirrors the existing `trust_engine` / `_has_extractable_evidence`
pattern: a normalization pass drops any candidate lacking all three. The snippet
is masked at creation so no raw value ever lands in `code_context` either.

> **No evidence → no finding.** This is a hard gate, not a downgrade.

---

## 8. Confidence Model (Task 13)

| Confidence | Requirement |
|-----------|-------------|
| `HIGH`    | Pattern match **+** successful live validation (`valid`) |
| `MEDIUM`  | Pattern match **+** strong context (assignment, known key var, paired credential) **but** not validated (offline / `unknown`) |
| `LOW`     | Pattern match only (entropy/format) with weak context |

- **`LOW` is suppressed by default** (kept in data, hidden from primary view).
- Reuses `finding_model.compute_confidence` semantics: validated secrets already
  jump to 95 there; Phase 9 maps the numeric band to the HIGH/MEDIUM/LOW label and
  adds the "validation present" requirement for HIGH.
- In offline/benchmark mode, the ceiling is `MEDIUM` (nothing can be validated),
  which keeps benchmark output deterministic.

---

## 9. Risk Model

Two orthogonal 0-100 scores, kept separate (consistent with the existing
reachability-vs-trust separation in `trust_engine`):

### exposure_score — *how reachable is the secret?*

Inputs: ownership (`APPLICATION` > library), evidence quality, whether the secret
sits in shipped config vs. dead code, and (for cloud stores) whether the store is
publicly reachable. A library secret buried in a framework = low exposure.

### exploitability_score — *what's the blast radius if abused?*

Inputs: provider class (payments/cloud-admin > analytics), validation result
(valid >> unknown), and enumerated `privileges` (write/admin >> read).
Drives the final `severity`.

```
severity = f(provider_base_severity, validation_result, privileges)
   valid + write/admin privilege   → critical
   valid + read-only privilege     → high
   detected (unknown), secret-class→ high
   publishable / restricted / INFO → info
```

---

## 10. Executive Secrets Summary (Task 14)

A rollup object on `results` (e.g. `results["secrets_summary"]`), rendered as a
new Overview/Evidence section. **Application-owned only.**

```jsonc
{
  "validated_secrets":     3,   // confirmed live, APPLICATION
  "invalid_secrets":       5,   // detected but rejected by issuer
  "public_databases":      1,   // Firebase/S3/Azure confirmed exposed
  "high_risk_credentials": 2,   // critical exploitability
  "suppressed_sdk_secrets": 14, // ownership != APPLICATION
  "providers":             ["AWS", "FIREBASE", "STRIPE"]
}
```

Preferred phrasings (success criteria):

- ✅ *"Validated AWS credential with S3 read access"* — not *"Possible AWS key"*.
- ✅ *"Public Firebase database"* — not *"Firebase URL detected"*.

---

## 11. Safety Model

| Risk | Control |
|------|---------|
| Leaking raw secrets | Masking in normalization layer before any serialization/log/SSE; only `masked_value` + `value_sha256` persisted |
| Breaking offline scans | Validation gated on `CORTEX_DISABLE_LIVE_CHECKS`; all probes fail to `unknown`, never raise |
| Non-deterministic benchmarks | Benchmark mode forces validation OFF (§12) |
| Destructive API calls | Read-only contract; capability probes are list/get only; no writes/sends/deletes |
| Abuse / rate limits | 6s timeout, ≤8 concurrent, single attempt, no retries |
| Probing third-party infra unnecessarily | Only `APPLICATION`-owned secrets are validated; suppressed SDK secrets are never probed |
| Account lockout from invalid attempts | One probe per credential; `invalid` is terminal |

---

## 12. Benchmark Safety (Task 15)

- Benchmark runs set (or inherit) `CORTEX_DISABLE_LIVE_CHECKS=1` **and** a
  `CORTEX_BENCHMARK=1` flag; either one forces `validation_result = "skipped"`.
- With validation off, confidence is capped at `MEDIUM`, scores derive purely from
  static signals, and no network call is made → **byte-deterministic** secret
  output across runs.
- This aligns with the existing "frozen decompile cache" benchmark stabilization
  (commit `6f7987e`) — Phase 9 adds the *network determinism* half.

---

## 13. Integration Points (for the implementation phase)

| Step | File | Change |
|------|------|--------|
| Tag patterns with `provider`/`type` | `evidence_scanner.py` | additive metadata on `SECRET_PATTERNS_EVIDENCE` |
| Normalize + mask + pair | new `analyzers/secret_intel.py` | `to_canonical_secrets(results)` |
| Gate validation | `secret_validator.py` | honor `CORTEX_DISABLE_LIVE_CHECKS` / `CORTEX_BENCHMARK`; add privilege probes |
| Cloud exposure | `live_checks.py` | extend Firebase; add Azure/S3 exposure → canonical |
| Call site | `android_analyzer.py` (~L769) / `ios_analyzer.py` | replace unconditional `validate_secrets` with gated `secret_intel` pass |
| Summary | finalize stage | build `results["secrets_summary"]` |
| UI | `scan-data.js` + `SectionViews.jsx` | new "Secret Intelligence" section, masked rendering, suppressed-count chip |

---

## 14. Proposed Phased Implementation

> Design first (this doc). Then ship in safe, independently-verifiable slices.

**Phase 9.1 — Safety foundation (no network).**
Canonical model + masking (G1) + provider tagging + ownership suppression +
evidence gate + LOW suppression + executive summary. Fully offline; benchmark-safe
by construction. *Highest priority — closes the raw-value leak.*

**Phase 9.2 — Validation gating + correctness.**
Make `validate_secrets` honor `CORTEX_DISABLE_LIVE_CHECKS` / `CORTEX_BENCHMARK`
(G2). Map validation → confidence HIGH. No new providers yet.

**Phase 9.3 — Credential pairing + AWS intelligence.**
Pairing (G4), SigV4 STS validation, read-only privilege enumeration (G3),
exploitability scoring.

**Phase 9.4 — Cloud exposure intelligence.**
Firebase read/write/collection enumeration, S3, Azure connection strings → public
read/write findings (exposed-only).

**Phase 9.5 — Remaining provider validators + scopes.**
GitHub scopes, SendGrid scopes, Twilio capabilities, Stripe, Google key
restriction checks.

**Phase 9.6 — UI + reporting.**
Secret Intelligence section, masked rendering, suppressed-count chip, PDF
integration, executive summary surfacing.

Each phase is additive, leaves offline/benchmark behavior intact, and is verifiable
against the existing benchmark framework.

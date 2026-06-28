# Beetle 2.0 — Secret Detection v2

**Phase:** 1.91 · **Branch:** `beetle-next` · **Scope:** secret-detection *precision
and coverage* — a refinement of the existing architecture, not a rebuild.

> *"Beetle should no longer report a random high-entropy string simply because it is
> long — and it should never silently miss a well-known vendor secret APKLeaks catches."*

This phase changes **four** things and **nothing else**. It does not add a pipeline,
does not wrap APKLeaks, and does not duplicate any engine. It makes the intelligence
Beetle *already computes* actually drive what an analyst sees.

---

## 1. The problem (validated against the implementation)

Benchmarking against a real banking app surfaced two issues. Inspecting the code
showed the architecture was already 80 % of the way there — the gaps were precise:

| Observation | Reality in the code | Verdict |
|---|---|---|
| APKLeaks caught **Facebook** secrets Beetle missed | `apkleaks_patterns.py` already ships Facebook Access Token + OAuth Secret | already fixed |
| APKLeaks caught **Artifactory** secrets Beetle missed | `grep artifactory` → **zero** hits in the whole backend | **true gap** |
| Beetle false-positives on **UUIDs / hashes / crypto constants / library constants** | The Secret Intelligence Engine *already classified* these as `False Positive` / `Generated Constant` (`engine.py`), but that verdict was **advisory only** | **true — a wiring gap** |

**The root cause was not detection — it was that the verdict was ignored at the one
gate that controls visibility.** `secret_intel.process_secrets` partitioned
`secrets` vs `suppressed_secrets` using *legacy* signals alone (ownership + the
detector's numeric confidence). A value the engine had already judged a non-secret
still showed, because its ownership was `Application` and its detector confidence
rounded to `MEDIUM`. The intelligence was computed and then thrown away.

---

## 2. New architecture (unchanged shape, one new data flow)

```
APK → decompile
  → ONE combined secret walk            secret_catalog.combined()  (native + APKLeaks + coverage)
       routing.extract_apkleaks()       split by provenance
       fusion.merge_secret_streams()    cross-source de-dup → ONE canonical secret, "Detected By" all engines
  → secret_intelligence.annotate()      CONTEXT VALIDATION + verdict per value     ← extended this phase
  → secret_intel.process_secrets()      MASK + partition visible/suppressed        ← now CONSUMES the verdict
  → ownership → confidence → evidence → triage → bug-bounty → reports
```

The only new arrow is **annotate → process_secrets**: the engine's verdict now
reaches the visibility gate. Everything else (unified catalog, single walk, fusion,
masking, downstream engines) is untouched.

---

## 3. Responsibility split

* **APKLeaks** — primary detector for well-known, curated vendor formats (AWS,
  Google, Firebase, Azure, GCP, Stripe, Twilio, Slack, GitHub, GitLab, Facebook,
  OAuth, JWT, **Artifactory** (new), SSH/PEM private keys, certificates, …). It is a
  *contributor to the unified catalog* (`secret_catalog`, provenance `apkleaks`).
* **Beetle Context Engine** — context analysis, ownership, validation, confidence,
  scoring, application-specific secrets, custom enterprise tokens, and generic
  secrets **only when contextual evidence supports them**.
* **Secret Fusion** (`detection_sources/fusion.py`) — when both engines hit the same
  value, produces **one** Canonical Secret with merged sources/evidence/confidence,
  shown as `Detected By ✓ APKLeaks ✓ Beetle`.

---

## 4. Context validation (the precision half)

`SecretIntelligenceEngine._context_signals` (in `secret_intelligence/engine.py`)
reads only the already-captured `snippet` / `code_context` / detector `name` — no
file re-read, no network — and produces a **Context Score (0–100)**:

| Signal | Effect | Source |
|---|---|---|
| **Variable name** names a credential (`apiKey`, `clientSecret`, `accessToken`, `bearerToken`, `privateKey`, `password`, …) | **+30** | `CONTEXT_VAR_NAME_HINTS` |
| **Nearby usage** of a security API (`Authorization`/`Bearer`, Retrofit, OkHttp, `Cipher`, `KeyStore`, `SharedPreferences`, Firebase, cloud-SDK init) | **+25** | `CONTEXT_USAGE_HINTS` |
| **File type** is a secret surface (BuildConfig / Config / Properties / Gradle) | **+15** | `CONTEXT_STRONG_KINDS` |
| Unambiguous provider/structured format | **+20** | record `kind` |
| **Dead constant** — a `static final` / `const` declaration with no credential name or usage | **−35**, `usage_referenced=False` | `CONTEXT_CONSTANT_DECL` |
| Generic value with **zero** positive signals | **−25** | — |

**Usage analysis.** A constant declaration with no credential name and no nearby
security-API use is reported as `usage_referenced = False` ("inert constant") and
penalized — dead constants do not earn high confidence.

**The decisive rule.** A value that *needs context* — generic/weak, **or** an
intrinsically ambiguous UUID-shaped "provider" format (e.g. the Heroku API key,
which is just a bare UUID) — and whose Context Score is ≤ 35 with an inspected
snippet is rejected as an **unreferenced generic** (`Status.FALSE_POSITIVE`). The
inverse: a generic value with Context Score ≥ 75 gets a validation bonus, so a real
`clientSecret = "<hex>"` used in an `Authorization` header survives. **Provider /
structured / validated secrets are never touched by this rule** — a recognized
format is a secret on its own.

---

## 5. Confidence model

Five explainable dimensions (each 0–100) feed a weighted overall
(`0.30·detection + 0.35·validation + 0.15·ownership + 0.20·evidence`, all in
`config.py`). Context validation modulates the **generic** path only: it adds a
validation bonus when context is strong and forces the unreferenced-generic FP when
context is absent. Every assessment now also carries `context_score`,
`usage_referenced`, `recognized_format` (unambiguous provider/structured format),
and a single analyst-facing **`validation_reason`** string.

---

## 6. False-positive reduction (the wiring fix)

`secret_intel` now consumes the verdict at the visibility gate
(`_intelligence_rejected` / `_intelligence_supports`):

* **Suppress** (→ `suppressed_secrets`, reason `intelligence_fp`, **kept + counted,
  never dropped**) using the engine status, split by *certainty*:
  * **Definitive** non-secret classes — `Public Value` (the format *is* public) and
    `Documentation Example` (matched by an exact value hash) — suppress even a
    recognized format.
  * **Heuristic** classes — `False Positive` / `Generated Constant` (placeholder
    substring, crypto-constant, unreferenced-generic) — suppress **only** when the
    value carries no recognized provider/structured format.
  * Otherwise, overall confidence below `SUPPRESS_OVERALL_FLOOR` (45) suppresses a
    value with no recognized format. Probable/Validated secrets are never floored.

  "Recognized format" here is the engine's **`recognized_format`** flag — an
  *unambiguous* provider/structured/public format, deliberately distinct from
  `format_valid` (which is also true for an ambiguous bare-UUID "provider" like the
  Heroku key). This is what guarantees **item 13**: a real provider secret that
  merely happens to contain a placeholder substring (`deadbeef`, `1234567890`, …) is
  never hidden by a heuristic FP, while a bare UUID the engine rejected for lack of
  context still suppresses correctly.
* **Rescue** (the coverage half) — an application-specific secret detected only by a
  generic ("weak") detector, which legacy would hide as low-confidence, stays
  **visible** when the engine vouches for it (`Probable`/`Validated`, or `Possible`
  with Context Score ≥ 75).

This reduces false positives for UUIDs, hashes, crypto constants, public
certificates, library constants, Android framework values, BouncyCastle parameters
and RFC examples — *unless strong contextual evidence indicates a genuine secret.*

---

## 7. Vendor coverage (the cited gap)

`Artifactory API Token` (`AKC…`) and `Artifactory Password` (`AP[0-9A-Fa-f]…`) are
added to the APKLeaks catalog slice (`detection_sources/apkleaks_patterns.py`),
prefix-anchored with a length floor + entropy gate. They flow through the one
combined walk like every other catalog rule.

---

## 8. Report fields

The Secrets drawer (`workspace2/panels.jsx`) now shows the full per-secret picture:
**Type, Confidence, Detected By, Context Score, Entropy, Owner, Usage, Validation
Result, Validation Reason, Status** — plus the existing masked value, evidence and
pair/exposure cross-references.

---

## 9. Measured improvement

`backend/tests/test_secret_detection_v2.py` runs a mixed corpus (6 genuine secrets,
4 classic false-positive seeds with non-weak detector names so the *legacy* gate
keeps them visible) through the real pipeline with the Phase-1.91 verdict OFF
(pristine pre-phase behavior) then ON. `python -m tests.test_secret_detection_v2`:

```
Secret Detection v2 - measured improvement
====================================================
  genuine secrets:        6
  false-positive seeds:   4
----------------------------------------------------
  FP visible  BEFORE gate: 4
  FP visible  AFTER  gate: 0          ← 100% of seeded FPs suppressed
  genuine kept BEFORE/AFTER: 5/6      ← app-specific secret RECOVERED
  generic precision BEFORE:  55.6%   AFTER: 100.0%
====================================================
```

* **False positives:** 4 → **0** (UUID, MD5 hash, AES test vector, unreferenced
  base64 constant — all now suppressed, kept + counted).
* **Vendor secret detection:** Artifactory **0 → detected**; Facebook already
  covered.
* **Generic precision:** **55.6 % → 100 %** on the corpus, with the one
  application-specific generic secret moving from *hidden* to *visible*.

**Why it is objectively better.** The architecture already computed the right
answer; v2 makes that answer authoritative for visibility, in both directions —
rejecting non-secrets it had flagged and rescuing real app secrets it had vouched
for — and closes the one true vendor gap. No new pipeline, no duplicate matching, no
loss of a single genuine secret.

---

## 10. Testing

* `tests/test_secret_detection_v2.py` — 8 cases: context keeps app-specific
  generics, context rejects bare random constants, UUID/crypto-constant rejection,
  provider formats unaffected, Artifactory in catalog, gate suppresses FP / keeps
  genuine, and the before/after measurement.
* `tests/test_secret_intelligence.py` (additive-contract guard updated for the two
  new flat fields) and the full backend suite — **289 passed**.
* No regression: genuine secrets stay detected, known FPs are rejected, fusion /
  masking / downstream engines are unchanged.

# Detection Coverage Expansion & Benchmark Engine (Beetle 2.0 — Phase 1.98)

The MobSF comparison showed Beetle produces higher-quality reports but still *misses*
some legitimate detections (e.g. **AWS Cognito Identity Pool**). This phase makes
Beetle never silently miss findings that mature scanners surface — while preserving
its analyst-first experience — by adding a **capability catalog**, closing the real
gaps, and giving developers a **benchmark engine** to measure coverage over time.

> Detection philosophy: maximize *useful* coverage while minimizing false positives
> and duplicate detections. Coverage is not "more findings" — it is "no missed
> legitimate findings, each flowing through the existing Intelligence Pipeline with
> Beetle's explainability and evidence quality intact."

## Architecture

A new `analyzers/detection_coverage/` package — a catalog + benchmark layer, **not a
second detection engine**.

```
analyzers/detection_coverage/
  registry.py    CoverageEntry + the machine-readable record of EVERY detection
  catalog.py     the data: documents existing detectors + adds the genuine gaps
  benchmark.py   compare Beetle vs MobSF vs APKLeaks (common/beetle-only/missing/…)
  corpus.py      regression baselines (DVIA, InsecureShop, OWASP MSTG, GoatDroid, …)
```

### Coverage registry

Every detector is one `CoverageEntry`: `id, category, name, kind, source, platform,
pattern?, detector_ref, severity, confidence, cwe/masvs/owasp, references, …`. The
registry is the single source of truth for "what Beetle detects," queryable by kind,
category or platform, with a `summary()` rollup.

It is a *catalog*, not a matcher. Entries route to the EXISTING engines:

- **`kind="secret"`** entries that carry a `pattern` are contributed to the unified
  `analyzers.secret_catalog` under provenance **`"coverage"`**, so they are matched
  by the ONE combined secret walk and flow through Secret Intelligence → masking →
  fusion → evidence selection. `secret_catalog.combined()` now returns
  `beetle_native + apkleaks + coverage`. **No duplicate scanning, no second matcher.**
- **`kind="crypto"`** gaps are added to `code_rules.CODE_RULES` (the SAST pipeline
  already runs them) and referenced by `detector_ref`.
- **`kind="manifest"`/`"platform"`** entries document the existing
  Android/iOS analyzer checks (the registry records them for benchmarking).

## What this phase added (the gaps)

**Secrets** (contributed to the unified catalog; deliberately excluding anything
already covered to avoid duplicates):

| Detection | Why it was missing |
|---|---|
| **AWS Cognito Identity Pool** (`region:uuid`) | the named MobSF gap |
| **AWS Cognito User Pool** (`region_id`) | companion Cognito identifier (recon / enumeration) |
| Google OAuth Client Secret (`GOCSPX-`) | not patterned |
| OpenAI Project key (`sk-proj-`) | newer format past `sk-…48` |
| Slack app-level token (`xapp-`) | distinct from `xox*` |
| Telegram bot token | not patterned |
| Stripe publishable (`pk_live_`) | recon signal |
| AWS ARN (account id) / Firebase App ID | recon / config |

**Crypto** (added to `code_rules`): RC4, **AES default mode (ECB)** via
`getInstance("AES")`, hardcoded salt, weak PBKDF iteration count, weak RSA keygen
(`initialize(512/1024)`).

Everything else in the brief's lists (DES/3DES, ECB-with-mode, MD5/SHA-1, weak IV,
allowBackup, cleartext, exported components, deep links, ATS, keychain, etc.) **was
already covered** and is now *documented* in the registry rather than re-implemented.

## Benchmark methodology

`benchmark.py` normalizes each engine's output to canonical **detection signatures**
(via an alias map + slugging) so superficial naming differences don't create false
gaps, then categorizes:

| Bucket | Meaning |
|---|---|
| `common` | Beetle AND another engine detected it |
| `beetle_only` | Beetle's edge |
| `missing` | another engine found it, Beetle did not — a gap to close |
| `duplicate` | same signature repeated within one engine's output |
| `better_evidence` | common detections where Beetle has file+line/selected evidence |

Adapters (`beetle_signatures`, `mobsf_signatures`, `apkleaks_signatures`) read each
tool's native shape. This complements the existing `backend/benchmark.py`
quality-gate runner — that one runs the pipeline over fixed APKs and gates on
regressions; this module is the pure, testable comparison core.

## Regression corpus

`corpus.py` declares the benchmark apps (DVIA, InsecureShop, OWASP MSTG Hacking
Playground, GoatDroid, Flutter/React-Native/iOS samples) and the detection
signatures each is known to exercise. Because we cannot ship the binaries, the
regression test asserts the **coverage surface still covers every expected
signature** (registry + secret catalog + SAST rules), so a future change can never
silently drop a capability the corpus depends on.

## Future extensibility

A new detector — or a whole new engine (Semgrep / MobSF module / YARA / an AI
detector) — registers `CoverageEntry`s as **data**:

- secret patterns → auto-matched via the unified catalog,
- rule-based detections → reference an existing/new SAST rule,
- the benchmark + corpus pick them up automatically.

No architecture change; the pipeline (ownership → confidence → evidence selection →
report accuracy) treats coverage detections exactly like any other finding.

## Consolidate-first audit (`audit.py`)

The philosophy is **consolidate first, expand second** — never add a second
implementation of a capability Beetle already has. `audit.py` enforces this
automatically by cross-referencing the registry against the REAL detectors:

| Check | Catches |
|---|---|
| `duplicate_rule_ids` | two SAST rules sharing an id (one silently shadows the other) |
| `duplicate_rule_patterns` | copy-pasted identical regexes |
| `orphan_crypto_refs` | a crypto entry whose `detector_ref` resolves to no rule |
| `unbacked_secret_entries` | a secret entry whose pattern isn't in the catalog |
| `secret_name_overlap` | names defined under >1 provenance (by-design native/apkleaks overlap — fusion merges them; informational) |

The audit immediately found a **pre-existing** bug: `android_runtime_exec` and
`android_dex_class_loader` were each defined **twice** in `code_rules` with
different patterns/metadata — in the id-keyed match aggregation one shadowed the
other. Both were **consolidated into a single rule** carrying the union of coverage
(`runtime_exec` gained `ProcessBuilder`; `dex_class_loader`'s broad pattern already
covered the constructor form). `audit.report()["ok"]` is now `True` and a regression
test keeps it that way.

## Reachability consolidation (single secret source feeding all paths)

The audit also exposed a **reachability gap**: Beetle had three secret-scanning
paths — the main evidence walk (unified catalog), the `common` scanner
(`scan_text_for_secrets`, used for JS bundles / DEX strings / no-JADX fallback), and
APKLeaks. New coverage patterns lived only in the catalog, so AWS Cognito et al. were
**not reachable on the bundle/DEX paths where React-Native/Flutter secrets actually
live**. Fix: `common._get_compiled_secret_patterns()` now also compiles the unified
catalog's `apkleaks`+`coverage` SECRET-kind patterns it lacks (deduped by name),
preserving `common`'s false-positive filtering. One change routes the **single
catalog** into every secret path — consolidation, not a parallel matcher.

## Tests

`backend/tests/test_detection_coverage.py` (15 tests): registry record/extensibility,
AWS Cognito + the other new secrets matched through the unified walk, coverage
provenance (no duplicate matcher), existing-secret regression, the five new crypto
rules (+ no-collision / strong-RSA negatives), benchmark aliasing/categorization/
adapters/duplicates/better-evidence, and full corpus coverage. Run:

```
cd backend && python -m tests.test_detection_coverage
```

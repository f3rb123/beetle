# Rule-ID Stabilization (Beetle v1.3)

Final stabilization step before Priority 2. Every detector finding now carries a
**stable, deterministic `rule_id`**. This is the last of the v1.3 stabilization
checklist (SourceCorpus, workspace evidence fix, adaptive jadx timeout, regex
prefilter, ownership improvements, profiling were already complete).

## Root cause

Before v1.3 only the regex detectors (SAST `CODE_RULES`, custom rules, taint,
`elf_unsafe_libc_imports`) emitted a `rule_id`. Roughly 90 other finding
producers — the manifest checks, certificate analysis, ELF/Mach-O hardening,
network-security-config, live checks, cloud config, framework detection, iOS
plist/entitlement/crypto/webview/binary checks, OSV, VirusTotal, domain intel,
the rule-table detectors (Flutter, React Native, iOS SAST, secret patterns) and
the attack-chain finding — identified themselves only by their **title**.

That mattered because four subsystems key on `rule_id` (falling back to a title
slug): ownership attribution, the collaboration layer (triage state / comments /
assignment that must survive rescans, keyed `(app_id, finding_key)` where
`finding_key = rule_id or title-slug`), suppression matching (`suppressions.rule_id`),
and in-memory dedupe. A title-only finding silently degrades all four: renaming a
title detaches its triage history and its suppressions, and it cannot be
suppressed by rule at all. `finding_model.data_quality_warnings()` already
flagged "missing rule_id" — this phase closes those warnings for every detector.

## Engineering approach

A finding's `rule_id` must be a function of the **detector**, never of the
matched value or a per-instance count, or it would change every scan and detach
triage state. Two mechanisms:

* **Inline detectors** (fixed title per branch) get a hand-assigned snake_case id
  with a domain prefix: `manifest_*`, `cert_*`, `nsc_*` (network security
  config), `elf_*`, `ios_macho_*` / `ios_binary_*`, `ios_ats_*`, `permissions_*`,
  `framework_*`, `sdk_*`, `cloud_*`, `firebase_db_*`, `assetlinks_*`,
  `domain_*`, `chain_*`. Cross-platform detectors share one id
  (`hardcoded_jwt_token`, `hardcoded_public_ips`, `framework_flutter_detected`)
  so an Android and iOS hit fuse rather than diverge.

* **Rule-table detectors** (Flutter, React Native, iOS SAST, secret patterns —
  where the title comes from a rule tuple) derive the id from the rule's **static
  title** via `common.rule_slug(prefix, title)` — e.g. `secret_*`, `flutter_*`,
  `react_native_*`, `ios_sast_*`. Behaviour findings derive from the rule
  **category** (`rule_slug("behavior", category)`); iOS entitlements from the
  entitlement **key**; OSV from a single `osv_vulnerable_dependency` (the
  vulnerable package lives in `package`/`vuln_id`, not the id); cloud config from
  `cloud_<type>`; the attack-chain finding from its detector slug (`chain_<id>`).

The regex producers additionally declare `evidence_type: "regex_match"`
explicitly, matching the convention `finding_model._evidence_type` adopted when
`rule_id` presence stopped doubling as a discovery-method hint.

## Dedupe correctness (the one behavioural change)

`common.dedupe_findings` previously keyed on `(rule_id or id or title, file, line)`.
Once **every** finding has a `rule_id`, that key would fold distinct per-instance
findings that share a rule — e.g. one `manifest_exported_service` per exported
component, or multiple `TAINT-<cat>` flows at the same class/line — into a single
row, losing findings. The key now includes the **title**:
`(rule_id or title, title, file, line)`. Because a title is unique per detector
branch and `rule_id` is a deterministic function of it, this is identical to the
old key for every previously-untagged finding, and strictly **non-lossy** for
tagged ones: it can only *preserve* a finding the old key wrongly merged.

## Files modified

Detectors (rule_id + evidence_type where regex): `android_analyzer.py` (manifest,
permissions, framework, NSC, exported components, SDK, behaviour, IP/JWT, meta),
`ios_analyzer.py` (plist/ATS, entitlements, frameworks, storage, crypto, webview,
Mach-O/binary hardening, provisioning, SAST, embedded keys, IP/JWT),
`cert_analyzer.py`, `elf_analyzer.py`, `lief_analyzer.py`, `live_checks.py`,
`domain_analyzer.py`, `cloud_config.py`, `virustotal.py`, `osv_scanner.py`,
`evidence_scanner.py`, `flutter_analyzer.py`, `react_native_analyzer.py`,
`js_bundle_analyzer.py`, `chain_analyzer.py`. Shared helper + dedupe:
`common.py` (`rule_slug`, dedupe key). New tests:
`tests/test_rule_id_coverage.py`.

## Validation

* **Unit/integration suite:** `440 passed` (was 438 before the two new tests;
  404 at the start of the v1.3 SourceCorpus work). No failures, no skips.
* **Static coverage guard** (`test_rule_id_coverage.py`): an AST walk over the 13
  primary detector modules asserts every dict literal appended to a findings list
  (excluding attack-chain steps and derived summaries) declares a `rule_id`. It
  fails the instant a new finding is added without one — a durable guard, no
  fixture needed. Passing.
* **Dedupe regression:** asserts two `manifest_exported_service` findings at
  different components stay separate, and true duplicates still collapse with a
  `duplicates` counter.
* **Production scan** — real `InsecureShop.apk` via jadx (`CORTEX_DISABLE_LIVE_CHECKS=1`):
  31 findings, **0 without a rule_id** (critical 1 / high 3 / medium 6 / low 16 /
  info 5). apktool was not installed in this bare-metal env, which suppresses
  smali/resource secret extraction — an environment limitation identical before
  and after the change, orthogonal to detection code.

## Regression analysis

Zero regression, proven on the real app: the scan was run twice — current code
vs. the pre-v1.3 dedupe key monkeypatched back — yielding **identical 31-finding
sets** (0 findings gained, 0 lost). The rule_id/evidence_type edits are additive
dict keys and provably cannot alter detection; the only behavioural variable is
the dedupe key, which reasoning shows is non-lossy and the A/B run confirms.

## Performance impact

None. `rule_slug` is an O(len(title)) regex substitution run once per emitted
finding (dozens per scan); the dedupe key adds one tuple element. No new file
I/O, no new pass over the source tree. Scan wall-clock is unchanged.

## Remaining technical debt (unchanged from prior phases)

* `common.SECRET_PATTERNS` still physically overlaps the unified catalog.
* Framework-only SAST findings are flagged, not suppressed (triage-policy call).
* The static rule-id guard covers inline dict-literal detectors; findings built
  through factories (`make_finding`, `_meta_finding`, the Flutter/RN `_finding`
  helpers) get their id inside the factory and are covered by the live scan's
  "0 without rule_id" assertion rather than the AST guard.

Stabilization is complete. Priority 2 (manifest detector improvements, signing
scheme correctness, Janus detection, secret precision, Flutter ELF awareness,
additional Android detections) has NOT been started and awaits go-ahead.

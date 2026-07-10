# Beetle vs MobSF — Engineering Improvement Blueprint

Evidence-based, derived from reading both codebases (MobSF 4.4.6, Beetle current `main`).
No Beetle code was modified. Every claim below cites concrete source.

---

## Executive verdict

Beetle is **not behind MobSF on detection**. On most axes Beetle is already ahead:
richer secret catalog (~140 provider patterns vs MobSF's entropy + key-name heuristic),
live CVE/KEV mapping (MobSF static has none), contextual exported-component severity,
taint analysis, evidence with file+line+snippet+View-Code, ownership/confidence/triage,
attack chains, and far better reports.

Beetle is **behind MobSF on three things that matter**:

1. **Speed.** MobSF reads the decompiled tree **once** and reuses it; Beetle re-walks
   and re-reads the same tree **15–20 times** per Android scan. This is the single
   largest, most fixable performance gap.
2. **A few high-value manifest detections** MobSF has and Beetle lacks (StrandHogg
   task-hijacking, launchMode/taskAffinity, grant-uri, dialer secret-code, intent
   priority, the full exported×protectionLevel matrix).
3. **Signing-scheme correctness** (MobSF uses apksigner; Beetle guesses via byte-magic).

Secret detection's real problem is **not coverage** — it is **precision + pipeline
complexity** (broad generic patterns, many overlapping dedup/fusion passes).

Detection-per-detector classification and the prioritized roadmap are at the end.

---

## PERFORMANCE

### Category: Redundant filesystem traversal (THE bottleneck)

**Current Beetle Behaviour**
The Android pipeline performs ~48 `os.walk` invocations across analyzers
(`grep -rc os.walk analyzers` = 48). On a single APK, the same jadx/apktool tree is
independently walked and re-read by, at minimum: `evidence_scanner` (secret walk),
`endpoint_intel`, `api_analyzer` (3 separate walks — APIs, emails, apkid features),
`string_analyzer`, `network_intel.extract_ips`, `cloud_config.scan`,
`scan_directory_for_jwts`, `code_analyzer._collect_android_files` (SAST),
`semgrep_runner` (own subprocess + walk), `cve_mapper.scan_maven_packages`,
`_collect_package_hints`, `_detect_session_recording_sdk_issues`, `osv_scanner`,
the `.so` walk for lief, and `js_bundle_analyzer`. A large app's tree (tens of
thousands of smali/java files) is therefore read from disk on the order of 15–20 times.
A shared-walk cache already exists (`common.build_file_index`) but **has zero callers**.

**MobSF Behaviour**
`sast_engine.py` + `code_analysis.py`: `sast.read_files()` reads all source file
contents **once** into `file_data`, then `run_rules(file_data, …)` is invoked repeatedly
for code rules, API rules, permission mappings, behaviour rules, and SBOM — all over the
same in-memory content. libsast runs the pattern matcher on a multiprocessing worker pool.

**Root Cause**
Beetle grew by adding first-class analyzers, each self-contained with its own walk+read.
There was never a shared "read the tree once" contract, and the one cache built for it
was never wired in.

**Engineering Recommendation**
Introduce a single `SourceCorpus` built once immediately after decompile: one walk that
loads `{rel_path: content}` (with the existing skip-prefix / size-cap / file-cap rules,
which are already duplicated verbatim in `evidence_scanner` and `code_analyzer`). Pass
the corpus to every text-scanning analyzer (`evidence_scanner`, `endpoint_intel`,
`string_analyzer`, `network_intel`, `cloud_config`, JWT scan, `api_analyzer`, SAST,
`cloud`/RN/Flutter, package-hint collection). Analyzers that need bytes (elf/lief, dex,
cve native) keep targeted walks. Do it incrementally: adopt `build_file_index` for the
already-parallel strings/emails/apkid/ips/cloud/jwt block first (biggest cluster, lowest
risk), measure, then migrate the rest.

**Expected Benefit** — Speed (large; likely the biggest single win — I/O and per-file
`splitlines()`/decode collapse from ~15–20× to 1×). Lower memory churn. Better
maintainability (one skip/cap policy instead of N copies).

**Estimated Complexity** — Medium (interface change across ~12 callers, but each is a
mechanical "walk → iterate corpus" swap; behavior preserved).

**Priority** — Critical.

---

### Category: Serial finalize pipeline

**Current Beetle Behaviour**
~25 finalize engines run strictly sequentially (`android_analyzer.py` finalize block,
fusion → … → source_explorer → score). Several are independent (e.g. `analyst_intel`,
`masvs_intel`, `workspaces`, `source_explorer`, `report_summaries` mostly read prior
state and annotate disjoint keys).

**MobSF Behaviour**
MobSF has far fewer post-processing passes; its cost is dominated by JADX + SAST, not by
a long annotate chain.

**Root Cause**
Each engine was added as its own additive phase with an explicit ordering comment; genuine
data dependencies (ownership → confidence → evidence → triage → chains → bug_bounty) are
real, but the leaf annotators at the end are not interdependent.

**Engineering Recommendation**
Keep the dependency spine serial. Group the terminal independent annotators
(`analyst_intel`, `masvs_intel`, `workspaces`, `source_explorer`) into one
`ThreadPoolExecutor` batch. Add a lightweight dependency assertion so future engines
declare what they read/write. Do **not** parallelize the spine — correctness > speed there.

**Expected Benefit** — Speed (modest, single-digit % of scan; the walks dominate). Better
maintainability (explicit dependency contract).

**Estimated Complexity** — Low.

**Priority** — Medium.

---

### Category: Decompile — already good, one tuning lever

**Current Beetle Behaviour**
jadx + apktool already run **in parallel** (`decompiler.py`, ThreadPoolExecutor
max_workers=2) — this is correct and matches best practice. jadx runs `--no-res`, so
`resources.arsc` strings are reconstructed separately via androguard.

**MobSF Behaviour**
JADX synchronous; **baksmali runs in a fire-and-forget daemon thread** and is never waited
on (smali is not needed for MobSF results). apktool is only invoked to decode the manifest
+ NSC xml, not full smali.

**Root Cause**
Beetle needs apktool's full smali as a SAST fallback and for the code viewer, so it pays
the full apktool cost (120s cap) even when jadx succeeded.

**Engineering Recommendation**
When jadx produced usable Java output, downgrade apktool to manifest+resources-only decode
(`-s` / no-src equivalent, or skip baksmali) instead of full smali — you already reconstruct
the manifest and arsc strings via androguard. Keep full apktool only as the jadx-failure
fallback. This mirrors MobSF's insight: full smali is rarely needed when Java exists.

**Expected Benefit** — Speed (meaningful on medium/large apps: apktool full-smali decode is
often 30–90s that overlaps jadx today but still gates the ThreadPool join).

**Estimated Complexity** — Medium (must confirm nothing downstream hard-depends on smali when
jadx exists — SAST skip-prefixes already prefer jadx).

**Priority** — High.

---

## SECRET DETECTION

### Category: Precision of broad patterns (the real weakness)

**Current Beetle Behaviour**
Coverage is excellent (~52 native + ~44 apkleaks + coverage patterns, unified in
`secret_catalog.combined()`). The false-positive load comes from two intentionally broad
rules — "Generic API Key" (`(?:api[_-]?key|…)[…]+([a-zA-Z0-9\-_.]{20,})`) and "Hardcoded
Password". They are guarded by ascii-ratio, entropy≥3.0, length caps, crypto-prefix skips,
and `_looks_like_ui_password_false_positive`, but generic key/password shapes still fire on
config keys, resource identifiers, and library constants.

**MobSF Behaviour**
MobSF deliberately does **not** ship a broad generic-key regex. Its secrets come from (a)
entropy over quoted strings (2 charset/threshold patterns) and (b) `is_secret_key(key)` —
a **key-name** heuristic applied to `resources.arsc` key/value pairs (endswith/contains/
not-contains word lists) that only flags a value when its *key name* looks secret and the
value has no spaces. Fewer detections, but far less generic noise.

**Root Cause**
Beetle matches on **value shape**; MobSF pairs **key-name context** with value. Value-shape
matching is inherently noisier for the "generic" tail.

**Engineering Recommendation**
Adopt MobSF's key-name pairing as a **confidence signal, not a gate**: when a generic hit's
surrounding context contains a secret-ish assignment key (`token`, `secret`, `apikey`,
`password`, …) raise confidence; when the key is a known-benign UI/resource identifier or the
value matches a library constant, demote to LOW (already hidden by confidence suppression).
Split "Generic API Key" into "Generic API Key (key-named)" high-confidence vs
"High-entropy string" low-confidence. Keep the rich provider catalog as-is — it is Beetle's
advantage.

**Expected Benefit** — Lower false positives (targeted at the exact noisy rules), without
losing the provider-specific true positives. Better analyst signal ratio.

**Estimated Complexity** — Medium.

**Priority** — High.

---

### Category: Secret-pipeline complexity / maintainability

**Current Beetle Behaviour**
A secret traverses: catalog walk → routing split (native/apkleaks) → fusion merge →
JWT cross-dedup (run **twice**, before and after JS-bundle scan) → `secret_intelligence`
→ `secret_intel` masking/partition → secret→finding bridge → later reconcile+remove the
bridged copies. Powerful, but a lot of moving parts with subtle ordering constraints
(documented heavily in comments).

**MobSF Behaviour**
Linear: extract strings → entropy/keyname → dedupe (`list(set(...))`) → dashboard.

**Root Cause**
Each capability (fusion, masking, bridge, validation) was added as an independent phase.

**Engineering Recommendation**
Not a rewrite — a consolidation. Collapse the two JWT cross-dedups into one post-all-producers
pass. Document the secret lifecycle as a single state diagram in `internal/`. Add a unit test
asserting the invariant "no raw value survives `secret_intel.process_secrets`" (the module
already promises this; lock it with a test). This reduces the risk that a future producer
added after masking leaks a raw value.

**Expected Benefit** — Maintainability, safety (masking invariant enforced), lower regression
risk. No detection change.

**Estimated Complexity** — Low–Medium.

**Priority** — Medium.

---

## MANIFEST / ANDROID CHECKS

### Category: Missing high-value manifest detections

**Current Beetle Behaviour**
Strong, contextual manifest analysis (`_check_app_flags`, `_process_component`,
`_exported_severity`): debuggable (3-state), allowBackup, cleartext, testOnly, minSdk
tiers, exported activity/service/receiver/provider, custom-scheme deeplink hijack,
weak-permission protection level, dangerous-perm combos. Its exported severity is
**contextual** (URL/deeplink/sensitive-name → high; plain → low) — better than MobSF's flat
template severity.

**MobSF Behaviour** (`manifest_analysis.py`, `kb/android_manifest_desc.py` — 53 templates)
Has several checks Beetle lacks:
- **StrandHogg 1.0** (targetSdk<28 + launchMode singleTask) and **StrandHogg 2.0**
  (targetSdk<29 + exported + not singleInstance/taskAffinity) — task-hijacking.
- **launchMode singleTask/singleInstance** with minSdk<21, and **taskAffinity set**.
- **grant-uri-permission** pathPrefix=`/` / path=`/` / pathPattern=`*` (over-broad provider grants).
- **android_secret_code** dialer scheme, **SMS receiver port**, **intent/action priority > 100**.
- **directBootAware**.
- Full **exported × protectionLevel matrix** (normal/dangerous/signature/signatureOrSystem,
  distinguishing component-level vs application-level permission, and legacy content-provider
  default-export for targetSdk<17).
- "Application installable on obsolete/vulnerable Android version" framed via an API→version map.

**Root Cause**
Beetle implemented the common, high-signal manifest issues first; the long tail of
task-hijacking / IPC-grant / legacy-provider checks was not ported.

**Engineering Recommendation**
Port the missing detectors as new inline checks in `_process_component` / `_check_app_flags`,
reusing Beetle's **contextual severity** philosophy (don't copy MobSF's flat levels). Priority
order by real-world value: (1) StrandHogg 1.0/2.0 + launchMode/taskAffinity, (2) grant-uri
over-broad grants, (3) intent/action priority, dialer secret-code, SMS port, directBootAware,
(4) formalize "installable on obsolete Android" as its own finding with the API→version map.
Each must carry `manifest_evidence_spec` so it passes Beetle's manifest-evidence enforcement.

**Expected Benefit** — Lower false negatives (real, exploitable gaps closed), stronger parity/lead
on the manifest surface analysts care about.

**Estimated Complexity** — Medium (well-scoped, evidence spec pattern already exists).

**Priority** — High.

---

### Category: Exported×permission protection matrix depth

**Current Beetle Behaviour**
`_process_component` flags exported components without permission, and "weak permission
protection" when a declared permission is normal/dangerous/unknown. It does not fully
distinguish app-level vs component-level permission inheritance, nor the
signatureOrSystem nuance, nor legacy provider default-export.

**MobSF Behaviour**
Exhaustively enumerates the matrix (the ~600-line Esteve block): component vs application
permission, each protection level, and provider default-export by targetSdk.

**Root Cause**
Beetle's model is "exported + weak/none permission = finding"; it does not walk application-
level permission fallback.

**Engineering Recommendation**
Extend `_permission_protection_level` / `_process_component` to consider the `<application
android:permission>` fallback when a component has none, and emit the signatureOrSystem case.
Keep it lean — MobSF's version is famously unmaintainable (1000 lines, nested); implement the
same coverage as a small decision table, not a copy of the branch tree.

**Expected Benefit** — Lower false negatives on permission-protected-but-still-reachable
components; better accuracy without inheriting MobSF's maintainability debt.

**Estimated Complexity** — Medium.

**Priority** — Medium.

---

## CERTIFICATE ANALYSIS

### Category: Signature-scheme detection correctness

**Current Beetle Behaviour**
`cert_analyzer.analyze_certificate` detects schemes by **byte-magic scanning** the raw APK
(`b"APK Sig Block 42"` → v2, a 4-byte magic → v3), v1 from META-INF PKCS7 presence, v4 from
`.idsig` file presence. Cert fields parsed via `cryptography`/androguard. Debug-cert, expired,
self-signed, sha1/md5 algo, key size.

**MobSF Behaviour**
`cert_analysis.py` shells out to **apksigner.jar verify --verbose** (authoritative v1–v4),
with an apksigtool fallback that parses the APK signing block properly. Models the **Janus**
vulnerability precisely (v1 present AND api<27, downgraded to warning if v2/v3 also present),
and downgrades the SHA1 finding to warning when `MANIFEST.MF` shows `SHA-256-Digest`.

**Root Cause**
Beetle avoided a Java subprocess dependency for cert parsing; byte-magic is a heuristic that
misclassifies (e.g. v3.1, or block ordering) and cannot see per-signer min-sdk.

**Engineering Recommendation**
Use androguard's signing-block APIs (`get_certificates_der_v2/v3`, `is_signed_v1/v2/v3`) as the
authoritative scheme source (androguard is already a dependency and already loaded in
`_parse_manifest`), falling back to byte-magic only if androguard fails. Add the **Janus**
finding (v1-only or v1+api<27) and the SHA-256-Digest downgrade — these are concrete,
well-defined, and currently absent.

**Expected Benefit** — Accuracy (correct scheme flags, Janus detection = a real high finding
Beetle misses today), lower false positives on SHA1.

**Estimated Complexity** — Medium (androguard cert API is already in the tree via cert_analyzer's
fallback path).

**Priority** — High.

---

## MALWARE / THREAT INTELLIGENCE

### Category: APKiD-equivalent depth

**Current Beetle Behaviour**
`api_analyzer.detect_apkid_features` is a **regex heuristic** over DEX strings mimicking
APKiD (anti-VM/anti-debug/obfuscation/packer). `tracker_db` has ~55 SDK signatures matched
by package hints. 9 `BEHAVIOR_RULES`.

**MobSF Behaviour**
Runs **real APKiD** (YARA rules — packer/compiler/anti-analysis with far more coverage),
**exodus** trackers with a live-updating DB and code-signature regex over the class list,
**maltrail** malware-domain DB, IP2Location geo + OFAC, and **211 behaviour rules**
(`behaviour_rules.yaml`) executed via the same reused `file_data`.

**Root Cause**
Beetle chose dependency-light heuristics over bundling YARA + large signature DBs.

**Engineering Recommendation**
This is a deliberate trade-off, not a bug — but two cheap wins: (1) expand `BEHAVIOR_RULES`
from 9 toward MobSF's behaviour set (it is just data — port the highest-signal rules into
`code_rules`/behaviour with Beetle's evidence model, they run on the shared corpus for free
once the corpus refactor lands). (2) Optionally gate real APKiD behind an env flag for
operators who want it (as MobSF does), keeping the heuristic as the default.

**Expected Benefit** — Lower false negatives on malware behaviour; optional depth parity for
malware-focused operators.

**Estimated Complexity** — Low (behaviour rules = data) / High (bundling YARA APKiD).

**Priority** — Medium (behaviour rules) / Low (YARA).

---

## NATIVE LIBRARIES

### Category: Dart/Flutter-aware binary hardening

**Current Beetle Behaviour**
`elf_analyzer` + `lief_analyzer` compute NX/PIE/canary/RELRO/RPATH/etc. and CVE-map native
libs — a genuine lead over MobSF (MobSF has no native CVE mapping).

**MobSF Behaviour**
`elf.py` ELFChecksec is **Dart-aware**: for Flutter/Dart libs it returns canary=True and
RELRO=Not-Applicable rather than flagging them as vulnerable (they legitimately lack these).

**Root Cause**
Beetle's ELF checks don't special-case Dart snapshots, so Flutter apps likely get false
"no stack canary / no RELRO" highs on `libapp.so`/`libflutter.so`.

**Engineering Recommendation**
Add MobSF's Dart detection (`_kDartVmSnapshotInstructions` / `Dart_Cleanup` string or symbol)
to `elf_analyzer`/`lief_analyzer` and suppress/soften canary+RELRO findings for Dart libs.
Beetle already detects Flutter at the framework level — reuse that signal.

**Expected Benefit** — Lower false positives on every Flutter app (a large, growing app class).

**Estimated Complexity** — Low.

**Priority** — Medium.

---

## DEPENDENCY / SUPPLY CHAIN  *(Beetle already ahead — protect the lead)*

**Current Beetle Behaviour**
`osv_scanner` (live OSV.dev) + `cve_mapper` (native .so + Maven AAR → CVE + KEV catalog) with
`components` + `cve_stats`. MobSF static has **no** CVE mapping — SBOM only (`*.version` files
+ package-name prefixes). This is a clear Beetle advantage.

**Engineering Recommendation**
No change needed to close a gap — but the OSV path is a **network** dependency inside the scan.
Ensure it is time-boxed and cached (it appears to be via `cve_cache`) so a slow OSV endpoint
never dominates scan latency. Consider making OSV/CVE optional-but-default like the live checks,
so offline/air-gapped runs (Beetle's "offline-first" positioning) degrade cleanly.

**Expected Benefit** — Scalability, predictable latency, honors offline-first promise.

**Estimated Complexity** — Low.

**Priority** — Medium.

---

## REPORTS / UX  *(Beetle already ahead)*

Beetle's evidence (file+line+snippet+View Code), ownership, trust, reachability, attack chains,
MASVS coverage, workspaces, source/security explorer, SARIF/SBOM/PDF, and CISO+developer
summaries substantially exceed MobSF's appsec dashboard + PDF. Scoring is more principled
(`scoring.py` weighted + diminishing caps + chain penalty) than MobSF's crude
`100-((h+.5w-.2s)/total)*100`. **Recommendation: no catch-up work; keep as differentiator.**
One small parity item: MobSF performs **live AssetLinks digital-asset-links verification**
(status codes, sha256 fingerprint presence) — Beetle's `check_assetlinks` is simpler; enriching
it to verify the fingerprint would harden the deeplink-hijack findings.

---

## Detection-per-detector classification

| Subsystem | Beetle vs MobSF | Why (evidence) |
|---|---|---|
| Secret **coverage** | **Better** | ~140 provider patterns + apkleaks + coverage vs entropy+keyname |
| Secret **precision** | **Worse** | broad Generic-Key/Password rules noisier than MobSF keyname pairing |
| Manifest common issues | **Better** | contextual exported severity vs flat templates |
| Manifest task-hijack / IPC-grant / priority | **Worse** | StrandHogg, launchMode, grant-uri, dialer, intent-priority absent |
| Exported×permission matrix | **Worse** | no app-level fallback / signatureOrSystem / legacy provider |
| Crypto rules | **Better** | 18 crypto rules vs ~10 |
| Certificate scheme + Janus | **Worse** | byte-magic vs apksigner; no Janus/SHA-256-Digest nuance |
| Network Security Config | **Equal** | both parse base/domain/debug, pins, user-CA |
| Native binary hardening | **Equal**, minus Dart-awareness | both lief; MobSF handles Dart canary/RELRO |
| Native CVE mapping | **Better** | Beetle maps CVE+KEV; MobSF static has none |
| Dependency/SBOM CVEs | **Better** | OSV live + Maven; MobSF SBOM-only |
| Malware behaviour / APKiD | **Worse** | 9 rules + regex heuristic vs 211 rules + real YARA APKiD + exodus/maltrail |
| Taint analysis | **Better** | androguard call-graph BFS; MobSF has none in static |
| Evidence / View Code | **Better** | file+line+snippet+resolver vs flat text |
| Ownership / confidence / triage | **Better** | none in MobSF |
| Attack chains | **Better** | v1+v2 engines vs none |
| Reports (PDF/SARIF/SBOM/exec) | **Better** | richer + audience summaries |
| Scan speed | **Worse** | 15–20× tree re-reads vs read-once |

---

## Prioritized roadmap (by engineering impact)

**Phase A — Performance (Critical)**
1. `SourceCorpus`: read the decompiled tree once, share to all text analyzers (adopt the
   dormant `build_file_index`). *Biggest single win.*
2. apktool: manifest+resources-only decode when jadx succeeds; full smali only as fallback.
3. Parallelize the terminal independent finalize annotators.

**Phase B — Detection gaps (High)**
4. Port StrandHogg 1.0/2.0, launchMode/taskAffinity, grant-uri, intent/action priority,
   dialer secret-code, SMS port, directBootAware — with contextual severity + evidence specs.
5. Certificate: androguard-authoritative scheme detection + Janus + SHA-256-Digest downgrade.
6. Secret precision: key-name context as a confidence signal; split Generic-Key into
   key-named (high) vs high-entropy (low).

**Phase C — Accuracy polish (Medium)**
7. Exported×permission app-level fallback + signatureOrSystem.
8. Dart-aware ELF hardening (suppress canary/RELRO FPs on Flutter libs).
9. Expand `BEHAVIOR_RULES` toward MobSF's behaviour set (free once the corpus lands).
10. Enrich AssetLinks live verification (fingerprint check).

**Phase D — Hygiene (Medium/Low)**
11. Consolidate secret pipeline (single JWT dedup, masking-invariant test, lifecycle doc).
12. Time-box/cache OSV; make CVE/live-checks cleanly optional for offline-first runs.

**Guardrails:** every change is measured through the existing `benchmark.py` gate
(trust/evidence/source-resolution/view-code/PDF, no-regression ratchet). Performance work
must not drop any detection metric; detection work must not regress the FP/signal ratio.

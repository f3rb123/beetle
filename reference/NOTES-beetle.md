# Beetle — Evidence Notes

## Architecture
- FastAPI + SQLite (raw sqlite3, results_json blob per scan). ThreadPoolExecutor scan queue, _MAX_CONCURRENT_SCANS=3.
- Decompile (decompiler.py): jadx + apktool run IN PARALLEL (ThreadPoolExecutor max_workers=2). jadx flags: --no-debug-info --no-res --threads-count 4 --show-bad-code. jadx timeout scales ~4s/MB floor90 cap420. apktool 120s. Because --no-res, resources.arsc strings reconstructed via androguard fallback (_persist_decoded_resource_strings) → apktool/res/values/strings.xml.
- android_analyzer.analyze_apk: 2618-line orchestrator. ~40 modules + ~25 finalize "intelligence engines" (fusion→canonical→manifest-evidence→chain-correlation→ownership diag→refine(FP suppress)→posture→reachability→trust→ownership→confidence→evidence→triage→evidence_selection→attack_chains_v2→bug_bounty→analyst_intel→masvs→workspaces→source_explorer→score).

## Performance ROOT CAUSE (why MobSF faster)
- ~48 os.walk calls across analyzers; on Android path ~15-20 FULL-TREE re-reads: evidence_scanner secret walk, endpoint_intel, api_analyzer (analyze_android_apis + extract_emails + detect_apkid = 3 walks), string_analyzer, network_intel.extract_ips, cloud_config.scan, scan_directory_for_jwts, code_analyzer SAST (own file_map), semgrep (own process+walk), cve_mapper.scan_maven_packages, react_native/flutter, _collect_package_hints (tmpdir), _detect_session_recording_sdk_issues (tmpdir), osv_scanner, elf/lief (.so walk), js_bundle. Each re-opens+re-reads same jadx/apktool tree.
- CONTRAST MobSF: SastEngine.read_files() reads all source ONCE → run_rules reused for code/api/perm/behaviour/sbom. libsast uses multiprocessing worker pool.
- common.build_file_index() shared-walk cache EXISTS but is UNUSED (only defined, no callers) — the fix is already scaffolded but not adopted.
- Beetle parallelizes SOME (strings/emails/apkid/ips/cloud/jwt in one ThreadPoolExecutor max_workers=5; lief 6-way) but each still does its own walk; and heavy engines (taint, semgrep, cve, ~25 finalize passes) are serial.
- Beetle runs MANY things MobSF does not (taint androguard call-graph, semgrep subprocess, OSV network, 25 finalize engines, live secret validators, VT) → deeper but slower. dex2smali: MobSF fire-and-forget daemon thread; Beetle apktool produces smali (blocking, 120s).

## Secret detection — Beetle is RICHER than MobSF, weakness = precision/noise
- Catalog: evidence_scanner SECRET_PATTERNS_EVIDENCE ~52 named provider patterns + apkleaks ~44 + coverage (Cognito etc.) + common.SECRET_PATTERNS ~24. Unified secret_catalog.combined() single walk. vs MobSF: entropy(2 patterns)+is_secret_key keyname heuristic + a few regex in android_rules.
- FP controls: scan_text_for_secrets (ascii-ratio<0.5 drop, crypto-prefix skip, hex>40 skip, len>200 skip, entropy>=3 gate, UI-password FP filter _looks_like_ui_password_false_positive), evidence_scanner per-match entropy+maxlen+redact_context. Ownership suppression (THIRD_PARTY_LIBRARY/FRAMEWORK hidden but counted). Confidence suppression (LOW hidden).
- secret_intel.py (Phase 9.1): canonical model + MASKING (raw value overwritten in place before any sink), provider/type tagging, evidence gate (file+line+snippet else drop), primary-category partition. secret_intelligence engine = validation (format/checksum/entropy/FP), secret_validators/ = LIVE probes (aws/azure/firebase/github/google/stripe/twilio). MobSF has firebase live + entropy only.
- WEAKNESS: Generic API Key / Hardcoded Password patterns are broad → main FP source; many overlapping engines/dedup passes (fusion, cross-dedup JWT twice, bridge) = complexity/maintenance risk. No per-key contextual assignment like MobSF is_secret_key keyname pairing on arsc (Beetle relies on regex value shapes).

## Manifest / Android checks
- Inline Python in android_analyzer (_check_app_flags, _analyze_permissions, _process_component). Contextual exported severity (_exported_severity: url/deeplink/sensitive-name → high, plain → low) — BETTER than MobSF flat template severity.
- Covers: debuggable(true/false/missing 3-state), allowBackup, usesCleartextTraffic, testOnly, minSdk<21/<24, exported activity/service/receiver/provider matrix w/ permission protection level, custom-scheme deeplink hijack, weak exported perm, excessive dangerous perms, SMS+calllog combo, session-recording SDK.
- MISSING vs MobSF: no vulnerable_os_version with API→version table finding phrased as "installable on obsolete Android" (has low-minSdk but less framed); no StrandHogg 1.0/2.0 task-hijacking; no taskAffinity finding; no launchMode singleTask; no grant-uri-permission pathPrefix=/; no android_secret_code dialer; no sms-port; no intent/action priority>100; no directBootAware; NSC debug-overrides only partial; no LIVE assetlinks digital-asset-links verification depth (has check_assetlinks but simpler). MobSF exported×protectionLevel matrix (normal/dangerous/signature/sigOrSystem, app-level vs component-level) is more exhaustive.

## Crypto — Beetle STRONGER
- code_rules.py: 81 rules, 18 Cryptography category (vs MobSF ~10 crypto in android_rules). Also 10 Data Storage, 9 WebView, 9 Platform, 7 Resilience, 6 Network.

## Cert — MobSF more robust
- Beetle: scheme detection by BYTE-MAGIC scan ("APK Sig Block 42", v3 magic bytes) + v1 from META-INF PKCS7 + androguard fallback; cryptography lib parse; debug cert (CN/O contains debug/test), expired, self-signed, sha1/md5 algo, key size. v4 = .idsig file presence.
- MobSF: apksigner.jar subprocess (authoritative v1-v4), Janus nuance (v1 & api<27, downgrade if v2/v3), SHA1 downgrade if MANIFEST.MF SHA-256-Digest, apksigtool fallback. More correct scheme + Janus modeling.

## Malware — MobSF STRONGER breadth
- MobSF: real APKiD (yara packer/anti-vm/anti-debug), exodus trackers (live DB, code signature regex over classes), maltrail malware domains, IP2Location geo + OFAC, 211 behaviour_rules.yaml, VirusTotal, malware permission set.
- Beetle: tracker_db (~55 SDK sigs, package-hint based), detect_apkid_features (REGEX heuristic mimic, NOT yara), 9 BEHAVIOR_RULES (vs 211), VirusTotal, malware_perms overlap, domain_analyzer geo/OFAC. APKiD-equivalent is weaker (no yara rules).

## Deps/CVE — Beetle STRONGER
- osv_scanner (OSV.dev live), cve_mapper (native .so + Maven AAR → CVE + KEV catalog), components + cve_stats. MobSF static has NO CVE mapping (SBOM only: *.version files + package prefixes; no OSV in static path).

## Native libs — comparable
- Beetle: elf_analyzer + lief_analyzer (parallel 6-way, up to 30-40 .so) + CVE. MobSF: lief ELFChecksec (NX/PIE/canary/RELRO/RPATH/fortify/stripped), Dart-aware canary+RELRO NA. Beetle lief_analyzer adds instrumentation detection. MobSF's Dart-awareness is a nice touch Beetle may lack.

## Reports/UX — Beetle STRONGER
- SARIF, SBOM (CycloneDX?), PDF (pdf_generator, compliance_pdf), report_summaries (CISO+dev). Evidence file+line+snippet+View Code, ownership, trust score, reachability, attack chains v2, MASVS coverage, workspaces, source/security explorer. MobSF: PDF, SARIF, appsec dashboard (crude score), simpler evidence.
- Beetle scoring.py: severity weights crit15/high8/med3/low1, diminishing 3x cap per severity, secret deductions, chain penalty, bonuses. vs MobSF crude 100-((h+.5w-.2s)/total)*100.

## Concurrency
- Beetle _MAX_CONCURRENT_SCANS=3 (whole scans). MobSF async django_q workers=2, dedup 60-min, queue 100. Within-scan: Beetle threads some phases; MobSF libsast multiprocess for SAST.

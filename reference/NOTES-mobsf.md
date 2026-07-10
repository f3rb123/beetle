# MobSF 4.4.6 — Evidence Notes (paths relative to mobsf/ package root)

## Architecture
- Django monolith; scans keyed by MD5 checksum; results persisted as one big row per scan (StaticAnalyzerAndroid model) with context dict pickled/JSON columns; rescan reuses DB entry (get_context_from_db_entry) — instant re-open.
- Async mode: `common/async_task.py` (django-q / queue with mark_task_started/completed); sync mode default. ASYNC_ANALYSIS setting.
- Progress: `append_scan_status(checksum, msg)` writes status rows — coarse phase-level progress.

## Android pipeline (StaticAnalyzer/views/android/apk.py: apk_analysis_task)
Order: hashes → unzip (custom safe unzip w/ zipslip, encrypted-file skip, size caps, reserved-name conflict dirs) → androguard_parse → aapt_parse → hardcoded cert/keystore file scan → manifest parse+extract+analysis → playstore lookup → malware permission check → icon → ELF library_analysis → cert_info → apkid → trackers → apk_2_java (JADX) → dex_2_smali (background daemon thread, non-blocking!) → code_analysis → get_strings_metadata → firebase → malware domain check → save ctx.
- MANIFEST PARSED ONCE into DOM; passed via app_dic['manifest_parsed_xml'].
- baksmali runs in daemon thread (fire and forget) — smali not needed for scan results.
- JADX: single subprocess for whole APK, `-ds` out, `--show-bad-code`, timeout JADX_TIMEOUT; fallback per-dex decompile.

## SAST engine (views/sast_engine.py + libsast)
- KEY PERF DESIGN: `sast.read_files()` reads ALL source file contents ONCE → `run_rules(file_data, rules)` executed for: android_rules.yaml (findings), android_apis.yaml (api), android_permissions.yaml (perm mappings, dynamically filtered to only-declared perms via temp yaml), behaviour_rules.yaml, SBOM analysis reuses same file_data.
- Multiprocessing: libsast worker pool (processpool default / billiard for async / thread on Windows), cpu_core count; SAST_TIMEOUT wrapper.
- Rules are declarative YAML (libsast pattern types: regex/string 'and/or' etc.). Findings = rule metadata + file:line map.

## Code analysis (android/code_analysis.py)
- URL/email extraction: rglob over .java/.kt AGAIN (2nd read of all files) — url_n_email_extract per file.
- NIAP choice engine separate read (only if enabled).

## Secret detection (surprisingly simple)
- common/shared_func.py `strings_and_entropies`: rglob src, STRINGS_REGEX (quoted strings) per file; filters: len>=4, excludes '\u0','com.google.', L-slash smali refs, first char alnum. Then get_entropies over set.
- common/entropy.py: 2 patterns (base64 charset len>=20 entropy>4.5; hex len>=20 entropy>3.0); excludes: starts L + '/', contains 'abcdefghi'/'kotlin/', >1 '/', isalpha.
- strings_from_apk: resources.arsc strings via androguard; `is_secret_key(key)` heuristic on res string KEY names (endswith/contains/not-contains lists) + value has no space → "possible secret". Firebase creds: google_api_key regex match on res keys.
- ELF strings → entropy secrets too.
- NO structured secret regex catalog (no AWS key patterns etc. beyond entropy) — MobSF secrets = entropy hits + key-name heuristics. Hardcoded-secret code findings come from android_rules.yaml regex rules too.

## Manifest analysis (android/manifest_analysis.py)
- ~1000-line legacy nested if/else (Esteve 2016 comments); rules emitted as (key, args) → templates in kb/android_manifest_desc.py (MANIFEST_DESC dict).
- Checks: vulnerable_os_version (<26 high / <29 warn) w/ API-level→version map; cleartext traffic; directBootAware; networkSecurityConfig; debuggable; allowBackup true/not-set; testOnly; taskAffinity; launchMode singleTask/singleInstance w/ minSdk<21; StrandHogg 1.0 (targetSdk<28 + singleTask); StrandHogg 2.0 (targetSdk<29 + exported + not singleInstance/taskAffinity); exported component matrix × permission protectionLevel (normal/dangerous/signature/signatureOrSystem, component & app level) incl. legacy provider default-export (targetSdk<17); grant-uri pathPrefix=/;path=/;pathPattern=*; android_secret_code dialer; sms port; intent/action priority >100; browsable activities + LIVE assetlinks.json verification over network (ThreadPoolExecutor, digital asset links check w/ status codes).
- Exported counts per component type; permission dict w/ protection levels from <permission> tags.

## Rule inventory (counts)
- android_rules.yaml: 51 rules (code findings, regex/RegexAnd/RegexOr/RegexAndOr, metadata: cvss/cwe/owasp/masvs/ref). Crypto rules: aes_ecb, aws_ecb_default, rsa_no_oaep, weak_hash, weak_ciphers, cbc_padding_oracle, md5, sha1, weak_iv, insecure_random, hardcoded (secret).
- android_apis.yaml: 54 API-usage rules; android_permissions.yaml: 296 permission→code mappings (dynamically filtered to declared perms); android_niap.yaml: 25; behaviour_rules.yaml: 211 (malware behaviour). iOS: objc 25, swift 39, ios_apis 13, ipa_rules (binary strings/symbols matcher).
- Manifest KB: 53 templated finding types (android_manifest_desc.py).

## Other subsystems
- cert_analysis.py: androguard cert parse (fallback apksigtool), apksigner.jar subprocess for v1-v4 versions; findings: unsigned, Janus (v1 & api<27 nuance), debug cert (CN=Android Debug), SHA1 (downgraded to warning if MANIFEST.MF shows SHA-256-Digest), MD5. Hardcoded cert/keystore file-extension scan.
- network_security.py: full NSC parse — base-config/domain-config/debug-overrides, cleartext (incl. SECURE for false), trust-anchors (@raw bundled=INFO, system=WARNING, user=HIGH, overridePins=HIGH), pin-set expiry (INFO if expires, SECURE if not), debug-overrides only flagged if app debuggable. Reads config from apktool_out (runs apktool just for this).
- firebase.py: LIVE checks — open firebase DB (GET /.json), Firebase Remote Config dump via API key+app id (POST firebaseremoteconfig.googleapis.com). Creds from res strings.
- appsec.py dashboard: security_score = 100 - ((high*1 + warn*0.5 - secure*0.2)/total)*100 where total=high+warn+secure. Crude. Sections: cert, NSC, manifest, code, perms (dangerous→hotspot), cert files, malicious domains + OFAC geo (IP2Location local DB), firebase, trackers (>4 high), secrets (>1 → warning 'may contain hardcoded secrets').
- ELF checksec (lief): NX, PIE/DSO, canary (Dart-aware!), RELRO (Dart NA), RPATH/RUNPATH, fortify, stripped. Per-.so findings + strings + symbols. run_with_timeout wrapper.
- SBOM: weak — *.version files + java package name prefixes from decompiled sources. NOT CycloneDX. No CVE mapping in static (no OSV).
- Trackers: exodus signatures (~code_signature regex compiled once, run over smali class list), live DB update from exodus; network signature check on domains.
- APKiD (yara-based packer/anti-vm/anti-debug detection) on APK/DEX; behaviour_rules 211 malware behaviour rules via same SAST file_data.
- Malware domain check: maltrail DB on extracted URLs + IP2Location geo + OFAC.
- Async: django_q queue, dedup within 60-min window, queue cap 100, timeout detection via signal. Sync default.
- iOS: ipa/dylib/a analysis; Mach-O checksec, classdump, plist/ATS analysis, binary rule matcher over strings/symbols.
- Progress reporting: append_scan_status per phase → scan logs endpoint.

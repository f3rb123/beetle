# Beetle — Feature Inventory

Every subsystem is documented with: Purpose, Dependencies, Strengths, Weaknesses, Confidence.

---

## 1. Authentication & Authorization

**Purpose:** Gate all API access behind JWT or API key authentication; enforce admin vs analyst role separation.

**Dependencies:** `auth.py`, `python-jose[cryptography]`, `passlib[bcrypt]`, `bcrypt`

**Strengths:**
- bcrypt password hashing (cost factor from passlib defaults)
- JWT HS256 with 24-hour expiry
- API keys are bcrypt-hashed in the DB (`ck_` prefix, only the hash stored)
- Automatic admin account seeding from env vars on first run
- Role enforcement via FastAPI dependency injection (`get_admin_user`, `get_current_user`)
- 401 responses trigger automatic client-side token clear and redirect to `/login`

**Weaknesses:**
- JWT stored in `localStorage` — accessible to any JavaScript on the page (XSS risk)
- No token refresh mechanism — users must re-login after 24 hours
- No brute-force protection (no account lockout, no rate limiting on `/api/auth/login`)
- API key validation is O(n) scan of all keys — bcrypt comparison on every key
- No per-user session revocation (only token expiry)
- Webhook secrets stored plaintext (inconsistent with bcrypt-hashed API keys)

**Confidence:** High — `auth.py` and the FastAPI dependency wiring in `main.py` were fully read.

---

## 2. Scan Upload & Queue Management

**Purpose:** Accept APK/IPA file uploads, validate them, and queue them for background processing with concurrency limits.

**Dependencies:** `main.py`, `python-magic`, `ThreadPoolExecutor(max_workers=3)`

**Strengths:**
- MIME type validation via `python-magic` before accepting the file
- Bounded concurrency (max 3 concurrent scans) prevents resource exhaustion
- Platform auto-detection from MIME + file extension
- SHA-256 hash computed and stored per scan
- Scan metadata persisted to SQLite immediately so status is queryable
- Upload files stored in tmpfs (/tmp) — ephemeral, never on named volumes

**Weaknesses:**
- Max 3 concurrent scans is hardcoded with no admin-facing config knob
- No queue depth limit — if 100 scans are submitted, 97 wait in memory
- No file deduplication — same APK submitted twice runs as two full scans
- MIME can be spoofed; androguard / ZIP validation is the real gate
- Upload size validated by nginx (250MB) but no backend-level size check
- No per-user scan quotas

**Confidence:** High.

---

## 3. Real-Time Progress (SSE)

**Purpose:** Push scan progress events to the browser via Server-Sent Events so users see live status without polling.

**Dependencies:** `main.py`, FastAPI's `StreamingResponse`, nginx `proxy_buffering off`

**Strengths:**
- 400ms polling interval for responsive feedback
- 5-second heartbeat prevents proxy timeouts
- Nginx configured with `proxy_buffering off` — SSE works through the reverse proxy
- Progress events carry human-readable step descriptions
- Hard 6-minute timeout prevents zombie connections

**Weaknesses:**
- 6-minute hard cap fails for large APKs with full Semgrep + taint analysis (can exceed 6 min)
- After the SSE cap, the scan continues in the background but the client gets no further updates and must poll `/api/scans/{id}` manually
- No reconnect logic in the frontend's EventSource handling
- SSE state is per-connection only; if the browser tab is closed, progress is lost until the next page load

**Confidence:** High.

---

## 4. Android Decompilation

**Purpose:** Produce human-readable source code from APK binaries for downstream SAST and source viewer.

**Dependencies:** `decompiler.py`, JADX v1.5.0 (external binary at `/opt/jadx/bin/jadx`), apktool 2.9.3 (JAR), `default-jre-headless`

**Strengths:**
- JADX + apktool run in parallel (ThreadPoolExecutor(2)) — saves clock time on large APKs
- JADX timeout scales with APK size: `min(420, max(90, size_mb * 4))` — 4 seconds per MB
- Partial JADX output on timeout is kept and used (graceful degradation)
- `CORTEX_JADX_MAX_MB` env var lets operators skip JADX on very large APKs
- apktool produces smali + resource files, jadx produces Java
- Both outputs persisted to named subdirs via `scan_storage.py`

**Weaknesses:**
- JADX and apktool are JVM-based — cold-start JVM overhead on every scan
- No caching of decompilation results between scans of the same APK hash
- Partial JADX output (on timeout) is silently used — analyst may not know coverage is incomplete
- apktool 2.9.3 may fail on APKs using newer resource formats (Android 14+)
- JADX Java decompilation quality degrades significantly for heavily obfuscated apps

**Confidence:** High.

---

## 5. SAST Engine (Code Analyzer)

**Purpose:** Apply regex-based rules to decompiled source to detect security-relevant code patterns.

**Dependencies:** `code_analyzer.py`, `code_rules.py`, `custom_rules.py`

**Strengths:**
- 100+ built-in `CODE_RULES` covering WebView, crypto, SQL injection, intent injection, data storage, IPC, network, permissions, and more
- Separate `IOS_CODE_RULES` for Swift/ObjC source
- Full OWASP Mobile Top 10 + MASVS v2 mapping on every rule
- CWE mapping on every rule
- Custom rules admin-managed in SQLite, merged at scan time with `"source": "CUSTOM_RULE"` tag
- Per-file line attribution — findings link to exact file + line number
- Multi-file evidence: same pattern match across multiple files is aggregated

**Weaknesses:**
- Pure regex — no AST, no dataflow — high false positive rate for context-dependent findings (e.g., `setJavaScriptEnabled(true)` in a test helper)
- Regex rules run against decompiled/smali output, not original source — obfuscated apps produce poor matches
- No inter-procedural analysis at the SAST layer (taint analysis is separate and slower)
- No confidence scoring at the rule level — all pattern matches carry equal weight
- Rule performance not bounded per file — a pathological file could trigger many rules

**Confidence:** High.

---

## 6. Semgrep Integration

**Purpose:** Run Semgrep CLI against decompiled source to complement the regex SAST engine with semantic rules.

**Dependencies:** `semgrep_runner.py`, `semgrep>=1.70.0` (pip package, needs CLI binary in PATH)

**Strengths:**
- Uses Semgrep's curated rulesets: `p/android`, `p/java`, `p/kotlin`
- Per-file 10-second timeout prevents single pathological file from blocking scan
- SARIF output parsed and deduplicated against existing findings by title+file+line
- Memory cap (1000MB) and job count (4) are tuned for the 6GB container budget
- Degrades gracefully — if Semgrep is not installed, returns empty metrics

**Weaknesses:**
- Semgrep is in `requirements.txt` but is NOT installed as a system binary in the Dockerfile — it needs to be in PATH for the CLI invocation to work. As shipped, Semgrep silently produces no results
- Semgrep rule sets require network access on first run to fetch from the registry
- 90-second total timeout may not be enough for large decompiled Java source trees
- OWASP/MASVS tags on Semgrep findings rely on category tags in the rule metadata, which is inconsistent across community rules

**Confidence:** High on the implementation; medium on whether it actually works in the shipped Docker image.

---

## 7. Evidence Scanner (Secrets, IPs, JWTs)

**Purpose:** Find secrets, hardcoded IPs, and JWTs embedded in all source files across the decompiled output.

**Dependencies:** `evidence_scanner.py`, entropy check (Shannon)

**Strengths:**
- 36+ secret patterns covering AWS, GCP, Azure, GitHub, Stripe, Slack, Twilio, SendGrid, OpenAI, JWT, PEM, Firebase, S3, Mapbox, and more
- Shannon entropy check filters low-entropy false positives
- Priority ordering: jadx output searched first, then apk_extract, then apktool (smali)
- Deduplication by value + file combination
- Code context capture (±2 lines) for finding presentation
- 15,000 file cap + 2MB per-file cap prevents scan stall on pathological inputs
- Skips Kotlin/kotlinx stdlib smali paths (major FP reduction)

**Weaknesses:**
- Regex patterns without entropy checks can produce false positives for example strings in documentation or test fixtures embedded in production code
- The skip list for high-FP paths is short — legitimate secrets in non-obvious directories may be missed
- No secret de-duplication across multiple secret types (same string matching two patterns creates two findings)
- IPv4 extraction skips smali to avoid version-number FPs, but this means IPs in smali bytecode annotations are missed

**Confidence:** High.

---

## 8. Secret Validator (Live API Probing)

**Purpose:** Validate extracted secrets by making live API calls to determine if they are active credentials.

**Dependencies:** `secret_validator.py`, `httpx`, `ThreadPoolExecutor(8)`, network access

**Strengths:**
- 13 named validators: GitHub PAT, Stripe, SendGrid, Slack OAuth, Slack Webhook, OpenAI, HuggingFace, npm, Mailchimp, AWS, Shopify, Databricks
- 8 concurrent probe threads with 6-second timeout each
- "live" result → severity bumped to critical, `severity_bumped=True` flag added
- Clear result taxonomy: `"live"` | `"invalid"` | `"unknown"` | `"skipped"`
- CORTEX_DISABLE_LIVE_CHECKS=1 skips probing

**Weaknesses:**
- AWS, Shopify, and Databricks validators return `"unknown"` for structural reasons (AWS needs secret key, Shopify needs shop domain, Databricks needs workspace URL) — three of 13 validators are effectively stubs
- Live probing uses discovered secrets against real production services — if the app belongs to a customer's production environment, this constitutes active credential use outside the app context (legal/ethical risk)
- No per-service rate limiting — multiple scans in parallel could trigger rate limits or lockouts
- Validation results are stored in results_json but are not easily visible in the audit log

**Confidence:** High.

---

## 9. Taint Analysis

**Purpose:** Inter-procedural data-flow analysis to trace user-controlled inputs to sensitive sinks.

**Dependencies:** `taint_analyzer.py`, `androguard` (DEX call graph), `ThreadPoolExecutor` for timeout enforcement

**Strengths:**
- Uses real androguard DEX call graph — not just pattern matching
- 17 sources (Intent extras, EditText, Clipboard, Location, Camera, GPS, SMS, Accounts, ContentResolver, SharedPreferences)
- 27 sinks (Log.*, network I/O, SQLite execSQL/rawQuery, FileOutputStream, Cipher.init, Runtime.exec, WebView.loadUrl, startActivity/sendBroadcast, SharedPreferences.putString)
- BFS traversal with MAX_DEPTH=6 and MAX_PATHS=200 per sink
- Hard 60-second threading timeout prevents runaway analysis
- Severity stratification: critical for SQL injection and RCE sinks
- Full call chain preserved in each finding

**Weaknesses:**
- Taint analysis only applies to Android (androguard is not used for iOS)
- 60-second timeout produces incomplete results on large or obfuscated apps without any indication to the analyst
- MAX_DEX_MB=30 skips apps with large DEX files (many production apps exceed 30MB of DEX)
- BFS from each sink builds `sink_reachable` set independently — no cross-sink path sharing — O(sinks × graph_size)
- Polymorph dispatch and reflection are not modeled — many real taint paths are missed
- No context-sensitivity — a path from source A to sink B is reported regardless of whether a meaningful data dependency exists

**Confidence:** High.

---

## 10. Attack Chain Synthesis

**Purpose:** Identify sequences of individual findings that together constitute an exploitable attack chain, and generate a pentest playbook.

**Dependencies:** `chain_analyzer.py`

**Strengths:**
- 6 chain detectors: WebView RCE, Debug/Backup exfil, Hardcoded secret exfil, Permission data leak, Intent injection, Crypto failure, Firebase exposure
- Each chain has exploitability score (out of 100), prerequisites, impact statement, OWASP/MASVS mapping, exploitation steps
- Chains sorted by severity rank then exploitability descending
- `_build_pentest_playbook()` generates up to 10 concrete actionable steps
- Firebase chain checks for confirmed live access (exploitability=99 when open)

**Weaknesses:**
- `_chain_hardcoded_secret_exfil` is **intentionally disabled** with a comment citing high FP rate — missing a significant attack class
- Chain detection is heuristic (presence of co-occurring finding categories) — no actual exploit path verification
- Only 6 chain types — does not cover: deeplink injection, SQL injection via intent, clipboard sniffing, accessibility service abuse, backup API abuse, man-in-the-middle via custom CA
- Pentest playbook steps are static templates parameterized with app-specific values — not dynamically reasoned
- Chains cannot be suppressed or tuned by the analyst (no false-positive management)

**Confidence:** High.

---

## 11. Certificate Analysis (Android)

**Purpose:** Analyze APK signing certificates for security issues including debug certs, weak algorithms, and old signing schemes.

**Dependencies:** `cert_analyzer.py`, androguard, `cryptography` library, struct (pure Python PKCS#7 parser)

**Strengths:**
- Detects v1/v2/v3/v4 signing schemes via magic byte search in raw APK
- Identifies Janus vulnerability (CVE-2017-13156) for v1-only signed APKs
- Flags SHA-1 signature algorithm (CWE-327)
- Debug certificate detection (CN/O matching "android debug"/"test"/"debug")
- Expired certificate detection
- RSA key size check (< 2048 → high finding)
- Both SHA-1 and SHA-256 fingerprints computed

**Weaknesses:**
- v2/v3/v4 cert extraction falls back through multiple androguard APIs (try v3 → v2 → v1 → generic) — parsing reliability depends on androguard compatibility with the specific APK variant
- The pure Python PKCS#7 parser for v1 certs is minimal (custom implementation) and may fail on non-standard encodings
- v4 detection is sidecar (`.idsig` file) — not present in uploaded APK, always reported as absent

**Confidence:** High.

---

## 12. ELF Binary Hardening Analysis

**Purpose:** Check native `.so` libraries for binary protection flags without requiring LIEF.

**Dependencies:** `elf_analyzer.py` (pure Python struct — no external tool dependency)

**Strengths:**
- Zero external dependency — works even when LIEF is unavailable
- Checks PIE, NX, stack canary (`__stack_chk_guard`/`fail`), RELRO (full vs partial), RPATH/RUNPATH, FORTIFY (`__*_chk` symbols), stripped
- Dangerous libc imports detected (strcpy, strcat, sprintf, gets, scanf, system, popen, execve, dlopen, memcpy)
- Cap at 20 .so files per scan — prevents runaway on apps with many native libs
- Aggregate summary finding ("N/M fully hardened") for at-a-glance posture

**Weaknesses:**
- Pure byte-pattern matching (searching raw bytes for symbol names) is fragile — stripped binaries may defeat canary detection
- `memcpy` flagged as dangerous is a frequent false positive — it's in virtually every C binary and not inherently unsafe
- Cap at 20 .so files means large apps (game engines, ML runtimes) get partial coverage — no indication of which files were skipped
- No version information extracted from ELF binaries (see cve_mapper.py for that)

**Confidence:** High.

---

## 13. LIEF Deep Binary Analysis

**Purpose:** Perform deep Mach-O and ELF binary analysis using the LIEF library, including instrumentation dylib detection.

**Dependencies:** `lief_analyzer.py`, `lief>=0.14.0` (optional)

**Strengths:**
- FAT binary handling — automatically selects ARM64 slice
- Detects instrumentation dylibs: Frida (critical), FridaGadget (critical), Substrate (critical), Objection (critical), libhooker/libellekit (high), libcycript (high)
- ObjC class enumeration (LIEF ≥0.13)
- Entitlement extraction from code signature XML
- Import/export symbol analysis (up to 2000 symbols)
- RPATH detection
- Scans entire .app bundle, cap 40 binaries

**Weaknesses:**
- LIEF is in `requirements.txt` but not explicitly installed as a system library in the Dockerfile — may fail to install or have missing native dependencies on `python:3.11-slim`
- Graceful degradation is silent — if LIEF fails, no notification to the analyst
- The function-level attribute approach (`getattr(parsed, attr, None)`) makes LIEF API changes hard to detect
- Cap at 40 binaries may miss dylibs in deeply nested framework directories

**Confidence:** High on implementation; medium on runtime availability in Docker.

---

## 14. CVE Mapping (Native Libraries)

**Purpose:** Detect bundled OSS native libraries by version strings in binary data and look up CVEs via OSV.dev.

**Dependencies:** `cve_mapper.py`, LIEF (optional), `httpx`, OSV.dev API, CISA KEV JSON feed

**Strengths:**
- 24 supported libraries: OpenSSL, libcurl, zlib, libpng, SQLite, nghttp2, libjpeg-turbo, libwebp, freetype, libsodium, FFmpeg, libxml2, c-ares, Flutter, React Native, protobuf, SQLCipher, Realm, gRPC, ICU4C, Conscrypt, libssh2, libwebsockets, OpenCV
- Symbol cross-check for 19 of 24 libraries (prevents false positive from quoted version strings in unrelated code)
- CISA KEV integration — severity bumped to high for known-exploited CVEs
- 24-hour OSV response cache in SQLite
- Parallel OSV queries (10 concurrent) with 45-second total budget
- Confidence scoring: "high" when LIEF sections + symbols available, "medium" otherwise
- Also covers: Maven AAR packages (pom.properties), CocoaPods frameworks (Info.plist)

**Weaknesses:**
- Version string matching is regex-based — obfuscated or statically linked libraries may not expose version strings
- OSV `/v1/query` endpoint is used per-component (individual requests), while `osv_scanner.py` uses `/v1/querybatch` — inconsistent and less efficient
- CISA KEV is fetched at scan time — cold scan with no cache requires a live KEV download
- Flutter and React Native version detection via binary strings is approximate
- No version normalization — `1.1.1k` and `1.1.1K` would be treated as different versions

**Confidence:** High.

---

## 15. OSV Dependency Scanner

**Purpose:** Parse build system files to extract declared dependencies and query OSV.dev for known vulnerabilities.

**Dependencies:** `osv_scanner.py`, `httpx`, OSV.dev batch API (`/v1/querybatch`)

**Strengths:**
- Supports: `build.gradle`, `build.gradle.kts`, `libs.versions.toml` (with version catalog ref resolution), `pom.xml`, `package.json`, `pubspec.yaml`
- Version catalog ref resolution (`libs.versions.toml` `[versions]` section)
- Batch API — one HTTP request for up to 60 dependencies
- Up to 5 CVEs reported per library to avoid overwhelming output
- Fixed version extracted from OSV `affected.ranges.events`
- 8-second request timeout

**Weaknesses:**
- MAX_DEPS_TO_QUERY=60 cap means large apps (common in enterprise) get truncated dependency coverage
- No caching of OSV responses (unlike `cve_mapper.py`) — repeated scans of same app re-query OSV
- Groovy vs Kotlin DSL parsing is regex-based — complex multi-line dependency declarations may be missed
- `pubspec.yaml` parsing may miss Flutter indirect dependencies in `pubspec.lock`
- No support for Gradle version catalogs with complex substitution rules

**Confidence:** High.

---

## 16. Tracker Detection

**Purpose:** Identify third-party SDK integrations that have privacy or security implications.

**Dependencies:** `tracker_db.py` (TRACKER_SIGNATURES), string matching against package names in decompiled source

**Strengths:**
- 55+ tracker signatures covering: Analytics (Firebase, Amplitude, Mixpanel, Segment, Heap), Crash Reporting (Sentry, Bugsnag, Crashlytics, Instabug), Advertising (AdMob, Facebook, AppLovin, IronSource, Unity Ads, Vungle), Attribution (AppsFlyer, Adjust, Branch, Kochava), Social (Facebook, Twitter, Google Sign-In, Auth0), Payments (Stripe, PayPal, Braintree, Square, Razorpay), Messaging (Sendbird, Twilio, Zendesk), Maps (Google Maps, Mapbox, HERE), Debug (Stetho, LeakCanary, Flipper), ML (ML Kit, TensorFlow Lite)
- Categorized by type for clear reporting
- Detection via package path matching (robust against renaming)

**Weaknesses:**
- MoPub is included but has been **shut down** (Twitter acquired + killed it in 2022) — any detection is a historical artifact, not an active privacy risk
- Twitter SDK (`com.twitter`) is effectively deprecated since X API v2 transition — detection signal is stale
- No severity assignment per tracker — all trackers are equal in the output
- No regulatory context (GDPR, CCPA) per tracker category
- Detection is package presence only — no usage frequency or data category analysis

**Confidence:** High.

---

## 17. Domain Analyzer

**Purpose:** Enrich extracted domains with geographic, reputational, and sanctions intelligence.

**Dependencies:** `domain_analyzer.py`, `httpx`, ip-api.com (free, no key), DNS resolution

**Strengths:**
- OFAC sanctions country check (13 countries: Cuba, Iran, North Korea, Russia, Syria, Venezuela, Belarus, Myanmar, Libya, Somalia, Sudan, Yemen, Zimbabwe)
- Suspicious keyword scoring (dev/stage/staging/qa/uat/test/debug/internal)
- Suspicious TLD scoring (.ru=25, .su=20, .click=15, .top=10, .xyz=8)
- Dynamic DNS hint detection (duckdns.org, no-ip., dynu., etc.)
- Private IP detection
- Risk score thresholds with OFAC → finding (severity: high)
- No API key required

**Weaknesses:**
- 30-domain cap — apps with many endpoints get incomplete analysis
- ip-api.com is a free third-party service with no SLA and rate limits (45 req/min)
- DNS resolution happens during scan — DNS failures produce silent gaps
- OFAC country check is by IP geolocation, not registry data — IPs can be geolocated incorrectly (CDN edge nodes, VPNs, etc.)
- No caching of geo results between scans

**Confidence:** High.

---

## 18. VirusTotal Integration

**Purpose:** Check APK and DEX file hashes against VirusTotal's 70+ AV engine database.

**Dependencies:** `virustotal.py`, `httpx`, `VIRUSTOTAL_API_KEY` environment variable

**Strengths:**
- Checks main file SHA-256 + up to 5 DEX file hashes
- 0.25s delay between requests (basic rate limiting)
- Verdict taxonomy: "malicious", "suspicious", "clean"
- Critical finding generated if main file is flagged malicious (CWE-506)
- Threat family name extracted from `popular_threat_classification`

**Weaknesses:**
- Rate delay (0.25s) is per-process, not shared between concurrent scan threads — parallel scans can easily hit VT's 4 req/min free tier
- VT hash lookups return "not found" for new/unique APKs — most internal enterprise apps will never appear in VT
- Requires paid API key for meaningful throughput
- The `_RATE_DELAY` is not adaptive (no exponential backoff on 429 responses)

**Confidence:** High.

---

## 19. JS Bundle Analyzer

**Purpose:** Analyze JavaScript bundles in React Native and Cordova apps for secrets and dangerous API usage.

**Dependencies:** `js_bundle_analyzer.py`

**Strengths:**
- Detects React Native, Capacitor, Cordova bundles by filename and content markers
- 6 dangerous API rules: eval(), new Function(), dangerouslySetInnerHTML, document.write, cleartext HTTP fetch, sensitive localStorage.setItem
- 9 secret patterns for JS context (Google API key, AWS AKIA, Stripe sk_live_, Slack xox*, JWT, PEM, GitHub ghp_, Firebase/S3 URLs)
- 15MB per-bundle cap
- Extracts API base URL patterns from RN bundles

**Weaknesses:**
- JavaScript minification defeats all pattern matching — production RN bundles are typically minified
- Source map files (`.map`) are not analyzed — they would provide much better coverage
- No AST-based analysis — pure regex on JS text
- `localStorage.setItem` rule would trigger on any localStorage write, not just sensitive data

**Confidence:** High.

---

## 20. Network Security Config Parser

**Purpose:** Parse Android's Network Security Config XML to detect cleartext, user CA trust, and certificate pinning issues.

**Dependencies:** `android_analyzer.py::_analyze_network_security_config()`, `xml.etree.ElementTree`

**Strengths:**
- Full coverage of NSC schema: base-config, domain-config, debug-overrides, pin-sets
- Generates findings for: global cleartext (high), per-domain cleartext (medium), user CA trust (high), pin override in debug config (medium), missing pinning (medium), expired pin (high), missing backup pin (low), correct pinning (info)
- Handles nested domain configs and inheritance

**Weaknesses:**
- Only analyzes `network_security_config` referenced in the manifest — apps using OkHttp/TrustManager overrides in code are not detected here (covered by SAST rules separately)
- Pin expiry check is date-string comparison — no timezone handling
- No analysis of whether pinned domains match the domains actually contacted

**Confidence:** High.

---

## 21. AI Enrichment

**Purpose:** Use Claude Haiku to generate contextual explanations and remediation guidance for findings.

**Dependencies:** `ai_enrichment.py`, `anthropic>=0.40.0`, `ANTHROPIC_API_KEY` environment variable

**Strengths:**
- 7-day SQLite cache keyed on finding content hash — avoids redundant API calls
- Graceful degradation — if API key is absent or call fails, finding is unchanged
- Model: `claude-haiku-4-5-20251001` (fast, low-cost)
- Per-finding enrichment maintains scan granularity

**Weaknesses:**
- `ai_enrichment_cache` table is created by `ai_enrichment.py` itself, outside the main schema migration in `database.py` — schema fragmentation
- No retry logic on API rate limits
- No batching — findings are enriched individually
- Enrichment runs per finding, not per scan — cannot synthesize cross-finding context
- The ANTHROPIC_API_KEY is required at scan time, not at startup — failures are silent

**Confidence:** High.

---

## 22. Report Generation

### 22a. PDF Reports

**Purpose:** Produce A4 PDF reports (executive and technical) from scan results.

**Dependencies:** `report/pdf_generator.py`, `reportlab==4.1.0`, `Pillow`

**Strengths:**
- Two themes: light and dark
- Executive summary with score, grade, and severity chart
- Full findings detail with code snippets, recommendations, MASVS/OWASP references
- ReportLab PDF generation is server-side — no client dependency

**Weaknesses:**
- No timeout on PDF generation — large scans with hundreds of findings could OOM or time out the HTTP request
- PDF rendering is synchronous in the HTTP request handler — blocks the FastAPI worker
- No pagination: a 500-finding scan produces an extremely long PDF
- No customizable cover page or company branding

**Confidence:** High.

### 22b. Compliance PDF

**Purpose:** Map detected issues to MASVS v2, PCI-DSS v4.0, and OWASP Mobile Top 10 compliance frameworks.

**Dependencies:** `report/compliance_pdf.py`, `reportlab`

**Strengths:**
- Three framework mappings: MASVS v2, PCI-DSS v4.0, OWASP Mobile Top 10
- Pass/fail per control based on finding severity

**Weaknesses:**
- Mapping is static — a finding in category X is always mapped to the same controls regardless of context
- No gap analysis: controls with zero findings are shown as "pass" even if the analyzer never checked the relevant behavior

**Confidence:** High.

### 22c. SBOM (CycloneDX 1.5)

**Purpose:** Generate a Software Bill of Materials in CycloneDX 1.5 JSON format.

**Dependencies:** `report/sbom_generator.py`

**Strengths:**
- CycloneDX 1.5 schema compliance
- Includes detected native libraries, Maven AARs, and CocoaPods frameworks
- CVE references in component entries

**Weaknesses:**
- SBOM completeness is limited by what the analyzers detect — obfuscated or dynamically loaded code is invisible
- No SPDX format support
- No component license information

**Confidence:** High.

### 22d. SARIF Export

**Purpose:** Export findings in SARIF 2.1.0 format for GitHub Code Scanning and other SAST toolchain integrations.

**Dependencies:** `sarif_exporter.py`

**Strengths:**
- SARIF 2.1.0 compliant
- Severity mapping: critical/high → error, medium → warning, low/info → note
- CWE relationships via `rule["relationships"]`
- `file_evidence` → `relatedLocations` (up to 3)
- Recommendations → `fixes[].description`
- Compatible with GitHub Code Scanning

**Weaknesses:**
- Secrets are converted to finding-like objects — no SARIF-native secret type
- Rule slugs are uppercase-with-hyphens — not in a stable namespace

**Confidence:** High.

---

## 23. Webhook Engine

**Purpose:** Send HTTP notifications to configured endpoints when scans complete.

**Dependencies:** `webhooks.py`, `httpx`, HMAC-SHA256

**Strengths:**
- HMAC-SHA256 payload signature (`X-Beetle-Signature`)
- SSRF protection: DNS resolution + RFC-1918 + loopback + link-local blocklist
- DNS-rebinding defense: re-resolves hostname in blocklist check
- Per-event filtering (webhook can subscribe to specific event types)
- Delivery log stored in SQLite
- Configurable via admin UI

**Weaknesses:**
- Webhook secrets stored **plaintext** in SQLite — inconsistent with bcrypt-hashed API keys
- No retry logic — a delivery failure is final (no exponential backoff)
- Webhook delivery is synchronous within the post-scan callback — slow endpoints block the background worker
- SSRF protection checks DNS at webhook creation time and delivery time, but not between them (DNS-rebinding window exists if TTL is short)

**Confidence:** High.

---

## 24. CI/CD Policy Gate

**Purpose:** Provide a pass/fail API endpoint for CI/CD pipelines to block deployments based on scan findings.

**Dependencies:** `policy.py`

**Strengths:**
- Per-severity thresholds (`max_critical`, `max_high`, `max_medium`, `max_low`)
- Returns `{ pass: bool, violations: [...] }` — machine-readable
- Minimal implementation — easy to integrate via curl in CI pipelines

**Weaknesses:**
- Policy thresholds are per-API-call parameters, not stored configurations — no named policies
- No finding-type exclusion (cannot say "ignore info findings in category X")
- No finding suppression / false-positive management — every finding counts toward the threshold
- No comparison against previous scan ("no regressions" policy not possible)

**Confidence:** High.

---

## 25. Custom SAST Rules

**Purpose:** Allow admins to define additional regex-based SAST rules that augment the built-in rule set.

**Dependencies:** `custom_rules.py`, SQLite `custom_rules` table

**Strengths:**
- Full OWASP/MASVS/CWE metadata support on custom rules
- Regex validated on create/update — bad patterns rejected before they crash a scan
- Auto-generated rule ID (`custom_<hex8>`) if not provided
- Platform scoping: android, ios, or both
- Enable/disable per rule
- Source-tagged findings (`"source": "CUSTOM_RULE"`)

**Weaknesses:**
- No rule testing sandbox — analysts can't test a rule against a sample before saving
- No rule versioning or changelog
- No import/export of rule sets (no JSON import for sharing across Beetle instances)
- Regex engine is Python `re` — no PCRE features, no lookahead performance limiting

**Confidence:** High.

---

## 26. Audit Log

**Purpose:** Record all privileged actions with user, IP, and timestamp for compliance and forensic purposes.

**Dependencies:** `audit.py`, SQLite `audit_log` table

**Strengths:**
- Records: login, user CRUD, scan operations, webhook CRUD, rule CRUD, report downloads, API key operations
- Includes IP address, username, resource type, resource ID, and action details

**Weaknesses:**
- API returns a maximum of 500 entries — older entries are not accessible via the API
- No log export (no CSV/JSON download of audit log)
- No log rotation — the table grows indefinitely
- No alerting on suspicious events (repeated failed logins, bulk download)

**Confidence:** High.

---

## 27. Source File Browser

**Purpose:** Allow analysts to browse decompiled source files and view code with syntax highlighting in the browser.

**Dependencies:** `main.py` (`/api/scans/{id}/file`), `scan_storage.resolve_source_file()`, frontend `CodeBlockViewer.jsx`

**Strengths:**
- Searches jadx → apktool → apk_extract → ipa_extract in priority order
- Handles binary files via `.txt` printable-strings sidecars
- Basename-walk fallback handles path normalization issues across platforms
- Supports both direct path and legacy `tmpdir`-style paths

**Weaknesses:**
- 50,000-file basename-walk limit can be hit on large apps — fallback fails silently
- 24-hour TTL means source files from older scans are unavailable
- No search-within-file functionality
- No link between a finding's file/line and the source viewer (requires manual navigation)
- Binary sidecar (.txt) files contain raw printable strings without context, making them hard to read

**Confidence:** High.

---

## 28. Frontend Application

**Purpose:** React SPA providing upload, scan management, and results workspace UI.

**Dependencies:** React 18, React Router 6, Vite, Tailwind CSS, Recharts, Lucide React

**Strengths:**
- ~30 distinct result sections covering every analyzer output
- Scan comparison (diff view) built into the Compare section
- Error boundary prevents full app crash on rendering errors
- Severity normalization in `scan-data.js` handles backend casing inconsistencies
- `apiFetch()` wrapper handles 401 redirects and network failures uniformly
- Admin-only routes (`/settings/webhooks`, `/settings/rules`) guard with role check

**Weaknesses:**
- JWT stored in `localStorage` — XSS-accessible
- No loading state management library — each section likely has ad-hoc loading state
- No offline support
- The `probeAuthEnabled()` function (in auth.js) returns `false` on network error — could be misinterpreted as auth disabled
- No pagination in the findings list — large scans load all findings into the browser at once

**Confidence:** High (frontend source fully read).

---

## Confidence Summary

| Area | Confidence |
|------|-----------|
| Backend auth + DB schema | High — every file read |
| Scan pipeline orchestration | High — main.py + all analyzers read |
| Android analysis | High — android_analyzer.py read fully (both halves) |
| iOS analysis | High — ios_analyzer.py read fully (both halves) |
| Binary analysis (ELF + Mach-O) | High |
| CVE scanning (OSV + native) | High |
| SAST rules coverage | High (code_rules.py structure confirmed) |
| Report generation | High |
| Docker / deployment | High |
| Frontend architecture | High |
| Semgrep + LIEF runtime availability | Medium — known gap between requirements.txt and Dockerfile |

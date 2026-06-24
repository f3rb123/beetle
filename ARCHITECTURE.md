# Beetle — Architecture

---

## System Topology

```
┌─────────────────────────────────────────────────────────────┐
│ Docker Compose                                              │
│                                                             │
│  ┌──────────────────┐        ┌────────────────────────────┐ │
│  │  frontend        │        │  backend                   │ │
│  │  nginx:alpine    │──/api/→│  python:3.11-slim          │ │
│  │  port 9005:80    │        │  uvicorn port 9005         │ │
│  │  mem: 256MB      │        │  mem: 6GB, cpus: 4         │ │
│  └──────────────────┘        │  read_only=true            │ │
│                              │  cap_drop: ALL             │ │
│                              │  tmpfs /tmp 2GB            │ │
│                              └────────────┬───────────────┘ │
│                                           │                 │
│                    ┌──────────────────────┼──────────┐      │
│                    │ named volumes        │          │      │
│                    │ cortex-data:/data    │          │      │
│                    │ cortex-uploads       │          │      │
│                    └──────────────────────┘          │      │
│                                                      │      │
│                              ┌───────────────────────┘      │
│                              ↓                              │
│                    /data/cortex.db  (SQLite WAL)            │
│                    /tmp/cortex/uploads  (tmpfs)             │
│                    /tmp/cortex/scans   (tmpfs)              │
└─────────────────────────────────────────────────────────────┘
```

---

## Backend Architecture

### Entry Point

`backend/main.py` (1276 lines) — FastAPI application. Defines all routes, owns the `ThreadPoolExecutor` scan queue, and orchestrates the scan pipeline. The module is the single largest file and acts as the controller layer.

### API Layer

FastAPI with automatic OpenAPI docs. All routes under `/api/`. Authentication is checked via dependency injection (`get_current_user()`). There are no versioned API prefixes — all routes are at `/api/...`.

**Route groups:**
| Prefix | Purpose |
|--------|---------|
| `/api/auth/*` | Login, token refresh, user management |
| `/api/scans/*` | Upload, status, results, reports, file viewer, compare |
| `/api/webhooks/*` | CRUD for webhook endpoints |
| `/api/rules/*` | Admin custom SAST rule management |
| `/api/audit` | Audit log retrieval (admin) |
| `/api/health` | Health check (unauthenticated) |

### Authentication Model

```
POST /api/auth/login
  → verifies bcrypt(password) against users.password_hash
  → returns JWT (HS256, 24h) signed with SECRET_KEY

Subsequent requests:
  Authorization: Bearer <token>
  OR
  X-API-Key: ck_<random>     (admin-provisioned, bcrypt-hashed in DB)
```

JWT payload contains `sub` (username) and `role`. The `get_current_user()` FastAPI dependency decodes and validates the JWT on every protected request. API key auth does a bcrypt comparison against all stored `api_key_hash` values — O(n) where n is the number of API keys, acceptable for typical small key sets.

Role enforcement is per-route:
- `get_admin_user()` dependency on admin-only routes
- Analyst-level routes accept any authenticated user

### Database Layer

Single SQLite file at `/data/cortex.db` in WAL journal mode. No ORM — raw `sqlite3` module throughout. Each module that needs DB access opens its own connection:

| Module | What it writes |
|--------|---------------|
| `database.py` | Schema init, scan CRUD, `compare_scans()` |
| `auth.py` | User CRUD, API key storage |
| `custom_rules.py` | Custom SAST rule CRUD |
| `webhooks.py` | Webhook CRUD, delivery log |
| `audit.py` | Audit log inserts |
| `ai_enrichment.py` | `ai_enrichment_cache` table (self-managed) |
| `cve_mapper.py` | `cve_cache` table (self-managed) |

**Schema tables:**

```sql
users           (id, username, password_hash, role, created_at, api_key_hash)
scans           (id, filename, platform, status, submitted_at, completed_at,
                 score, grade, results_json, file_path, sha256, file_size)
webhooks        (id, url, secret, events, enabled, created_at, created_by)
custom_rules    (rule_id, platform, title, pattern, severity, category,
                 cwe, masvs, owasp, description, recommendation, enabled, created_by)
audit_log       (id, user_id, username, action, resource_type, resource_id,
                 details, ip, timestamp)
ai_enrichment_cache  (cache_key, response, created_at)   -- created by ai_enrichment.py
cve_cache            (key, response, fetched_at)          -- created by cve_mapper.py
```

The entire scan result (all findings, metadata, enriched data) is stored as a single `results_json` blob in the `scans` table. There is no normalized findings table.

---

## Scan Pipeline

### Lifecycle

```
1. POST /api/scans/upload
   └─ Validate MIME type (python-magic)
   └─ Save to /tmp/cortex/uploads/<scan_id>.<ext>
   └─ Insert scan row (status=queued)
   └─ Submit to ThreadPoolExecutor (max_workers=3)
   └─ Return {scan_id}

2. GET /api/scans/{id}/stream  (SSE)
   └─ 400ms poll on scan status
   └─ 5s heartbeat
   └─ Hard cap: 6 minutes
   └─ Emits progress events as scan runs

3. Background worker: run_scan(scan_id)
   └─ status → "running"
   └─ Detect platform (APK or IPA from MIME/extension)
   └─ Call android_analyzer.analyze() or ios_analyzer.analyze()
   └─ Store results_json in scans table
   └─ status → "complete" or "failed"
   └─ Fire webhooks asynchronously
```

### Android Scan Pipeline

The `android_analyzer.analyze()` function orchestrates all sub-analyzers in a defined sequence:

```
APK file
├─ Extract ZIP → /tmp/cortex/scans/<scan_id>/apk_extract/
├─ Decompile (parallel):
│   ├─ JADX v1.5.0 → /tmp/cortex/scans/<scan_id>/jadx/
│   └─ apktool 2.9.3 → /tmp/cortex/scans/<scan_id>/apktool/
├─ Persist extracted trees (scan_storage.py)
│
├─ Core static analysis:
│   ├─ AndroidManifest.xml parse (permissions, components, flags)
│   ├─ Network Security Config parse (cleartext, pins, user CA)
│   ├─ Certificate analysis (cert_analyzer.py — v1-v4 schemes)
│   ├─ SAST via code_analyzer.py (CODE_RULES + custom_rules)
│   ├─ String analysis (string_analyzer.py — 28 categories)
│   ├─ Evidence scanner (evidence_scanner.py — secrets, IPs, JWTs)
│   ├─ JS bundle analysis (js_bundle_analyzer.py — RN/Cordova)
│   ├─ APKiD detection (api_analyzer.detect_apkid_features)
│   └─ Framework detection (RN, Flutter, Xamarin, Cordova)
│
├─ Binary analysis:
│   ├─ ELF hardening (elf_analyzer.py — up to 20 .so files)
│   └─ CVE mapping (cve_mapper.analyze_native_libs — up to 40 binaries)
│
├─ Third-party intelligence:
│   ├─ Tracker detection (tracker_db.TRACKER_SIGNATURES — 55+ SDKs)
│   ├─ SDK detection (tracker_db.SDK_SIGNATURES)
│   ├─ API usage analysis (api_analyzer.analyze_android_apis — 35 categories)
│   ├─ Email extraction (api_analyzer.extract_emails_from_app)
│   └─ OSV dependency scan (osv_scanner.py — build.gradle, pom.xml, etc.)
│
├─ Supply chain (Maven AARs from apk_extract):
│   └─ cve_mapper.scan_maven_packages + cve_mapper.analyze_packages
│
├─ Advanced analysis:
│   ├─ Taint analysis (taint_analyzer.py — BFS on DEX call graph)
│   ├─ Semgrep (semgrep_runner.py — p/android, p/java, p/kotlin)
│   ├─ Attack chain synthesis (chain_analyzer.py — 6 detectors)
│   └─ Domain enrichment (domain_analyzer.py — geo/intel, OFAC)
│
├─ Live checks (network):
│   ├─ Firebase probe
│   ├─ S3 bucket probe
│   ├─ AssetLinks.json check
│   ├─ Secret validator (13 API probers)
│   └─ VirusTotal hash lookup
│
└─ AI enrichment (optional, Claude Haiku with 7-day cache)
```

### iOS Scan Pipeline

`ios_analyzer.analyze()` follows the same pattern:

```
IPA file
├─ Extract ZIP → find Payload/*.app
├─ Extract to /tmp/cortex/scans/<scan_id>/ipa_extract/
│
├─ Core analysis:
│   ├─ Info.plist parse (bundle ID, version, SDK versions, capabilities)
│   ├─ Entitlements extraction (from embedded.mobileprovision or binary)
│   ├─ Secret detection (evidence_scanner.py — same 36+ patterns)
│   ├─ IP extraction
│   ├─ JWT extraction
│   ├─ iOS data storage analysis (Keychain, UserDefaults, CoreData, Realm, FileProtection)
│   ├─ Crypto usage analysis (CommonCrypto, CryptoKit, weak algorithms)
│   └─ WebView analysis (UIWebView, WKWebView, JS bridge handlers)
│
├─ Binary analysis:
│   ├─ Mach-O parse (ios_analyzer._analyze_macho_deep — PIE, NX, canary, ARC, FairPlay)
│   ├─ LIEF deep analysis (lief_analyzer.analyze_all_macho — instrumentation detection)
│   └─ ELF hardening for any .so files
│
├─ Third-party:
│   ├─ Embedded frameworks (Frameworks/*.framework Info.plist)
│   ├─ CocoaPods CVE scan
│   ├─ OSV dependency scan (Package.swift / Podfile.lock when present)
│   └─ Tracker detection (common tracker packages in code)
│
├─ Advanced:
│   ├─ File inventory (suspicious extensions: .pem, .p12, .key, .realm)
│   ├─ SAST via ios code rules (IOS_CODE_RULES)
│   ├─ Domain enrichment
│   └─ Attack chain synthesis
│
└─ Live checks (same as Android)
```

### Scoring Model

`scoring.py` computes a 0–100 score and A–F grade:

```
Base score: 100
Deductions (by severity):
  critical: -20 per finding
  high:     -10 per finding
  medium:   -5  per finding
  low:      -2  per finding
  info:     -0.5 per finding

Bonus (applied after deductions):
  +5  ELF binaries fully hardened
  +5  NSC configured properly
  +5  Certificate valid + modern scheme
  +5  No dangerous permissions

Grade thresholds: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F < 40
Score is clamped to [0, 100].
```

---

## Frontend Architecture

### Stack

- **React 18.3.1** (class components for ErrorBoundary, functional everywhere else)
- **React Router 6** (client-side SPA routing)
- **Vite 5** (build tool, ESM-first)
- **Tailwind CSS 3.4** (utility-first styling)
- **Recharts 2.12** (charts on dashboard)
- **Lucide React** (icons)

### Route Structure

```
/login                       — Login.jsx (no auth required)
/                            — Home.jsx (scan list + upload)
/scans/:scanId/:sectionId    — Results.jsx (the workspace)
/settings/webhooks           — Webhooks.jsx (admin only)
/settings/rules              — CustomRules.jsx (admin only)
```

`RequireAuth` wrapper redirects unauthenticated users to `/login` with `state.from` preserved for post-login redirect. Auth state lives in `localStorage` (`cortex_token`, `cortex_user`).

### Results Workspace Sections (~30 total)

The `Results.jsx` page is the main workspace. `scan-data.js` defines the full section inventory in `SECTION_GROUPS`:

| Group | Sections |
|-------|---------|
| Overview | Dashboard, Findings, Compare, App Info |
| Evidence | Source Files, Code Analysis, Manifest, Strings, Secrets, JWTs, IPs |
| Attack Surface | Permissions, Attack Surface, Browsable, Endpoints, Domains, Android API |
| Hardening | Binaries, Certificate, APKiD, MASVS/OWASP, Vulnerable Components |
| Intelligence | Trackers, SDKs, Emails, VirusTotal |
| Data Flow | Taint Flows |
| iOS Deep Analysis | Entitlements, Frameworks, Data Storage, Cryptography, WebView/Bridges |

### API Communication

`auth.js` exports `apiFetch()` — a `fetch()` wrapper that:
- Injects `Authorization: Bearer <token>` header automatically
- On 401: clears localStorage and redirects to `/login`
- On 5xx or network failure: returns a synthetic 503 `Response` with `.cortexServerError = true`

---

## Nginx Configuration

```nginx
# /api/ → backend:9005
proxy_read_timeout 600s;
proxy_send_timeout 600s;
client_max_body_size 250M;
proxy_buffering off;          # Required for SSE

# Static / SPA fallback
try_files $uri $uri/ /index.html;

# Cache headers
# Static assets: 1-year immutable
# HTML: no-cache
```

The 600-second proxy timeout accommodates large APK scans. `proxy_buffering off` is required for the SSE progress stream. File uploads up to 250MB are permitted.

---

## Data Flow: Upload to Report

```
Browser                Nginx               FastAPI              SQLite
  │                      │                    │                    │
  │── POST /api/scans ──▶│── proxy ──────────▶│                    │
  │   (multipart, APK)   │                    │── INSERT scan ────▶│
  │                      │                    │   status=queued    │
  │◀── {scan_id} ────────│◀───────────────────│                    │
  │                      │                    │                    │
  │── GET /stream ───────│── SSE ────────────▶│                    │
  │   (EventSource)      │   proxy_buffering  │                    │
  │                      │   off              │                    │
  │                      │                    │──[background]──────│
  │                      │                    │  run_scan()        │
  │                      │                    │  → analyze()       │
  │                      │                    │  → UPDATE results  │
  │                      │                    │  status=complete   │
  │◀── SSE complete ─────│◀───────────────────│                    │
  │                      │                    │                    │
  │── GET /api/scans/{id}│── proxy ──────────▶│── SELECT ─────────▶│
  │◀── results JSON ─────│◀───────────────────│◀── results_json ───│
```

---

## File System Layout

```
/data/
  cortex.db          — SQLite database (WAL mode)
  reports/           — Generated PDF/SBOM reports

/tmp/cortex/         — tmpfs (ephemeral, 2GB)
  uploads/           — Uploaded APK/IPA files (cleaned after scan)
  scans/
    <scan_id>/
      jadx/          — JADX decompiled Java source
      apktool/       — apktool disassembled smali + resources
      apk_extract/   — Raw APK zip extraction
      ipa_extract/   — Raw IPA zip extraction
```

Scan directories are cleaned up after 24 hours by default (`CORTEX_SCAN_TTL`). The source file viewer resolves finding paths by searching `jadx/` → `apktool/` → `apk_extract/` → `ipa_extract/` in order, with basename-walk fallback.

---

## Inter-Module Dependencies

```
main.py
 ├─ auth.py                (authentication)
 ├─ database.py            (scan CRUD)
 ├─ audit.py               (audit log)
 ├─ webhooks.py            (webhook delivery)
 ├─ policy.py              (CI/CD gate)
 ├─ custom_rules.py        (custom rule fetch)
 ├─ ai_enrichment.py       (Claude Haiku)
 ├─ sarif_exporter.py      (SARIF export)
 ├─ json_utils.py          (JSON serialization)
 ├─ report/
 │   ├─ pdf_generator.py
 │   ├─ compliance_pdf.py
 │   └─ sbom_generator.py
 └─ analyzers/
     ├─ android_analyzer.py   (orchestrator)
     │   ├─ decompiler.py
     │   ├─ evidence_scanner.py
     │   ├─ code_analyzer.py + code_rules.py
     │   ├─ string_analyzer.py
     │   ├─ api_analyzer.py
     │   ├─ cert_analyzer.py
     │   ├─ elf_analyzer.py
     │   ├─ lief_analyzer.py
     │   ├─ taint_analyzer.py
     │   ├─ chain_analyzer.py
     │   ├─ osv_scanner.py
     │   ├─ cve_mapper.py
     │   ├─ semgrep_runner.py
     │   ├─ js_bundle_analyzer.py
     │   ├─ tracker_db.py
     │   ├─ domain_analyzer.py
     │   ├─ live_checks.py
     │   ├─ secret_validator.py
     │   ├─ virustotal.py
     │   ├─ scan_storage.py
     │   └─ path_utils.py
     └─ ios_analyzer.py       (orchestrator, shares most of the above)
```

---

## Security Posture of the Platform Itself

| Control | Implementation |
|---------|---------------|
| Authentication | JWT HS256 + bcrypt passwords + bcrypt API keys |
| Authorization | Role check per endpoint |
| Container isolation | `read_only=true`, `cap_drop: ALL`, `no-new-privileges: true` |
| Upload isolation | tmpfs only, MIME validation |
| Webhook SSRF | DNS resolution + RFC-1918 blocklist + DNS-rebinding protection |
| Webhook integrity | HMAC-SHA256 signature on payload |
| Audit trail | All privileged actions logged with IP and timestamp |
| Memory limits | Backend 6GB, frontend 256MB |
| JWT storage | localStorage (XSS-accessible — see TECH_DEBT.md) |
| Webhook secrets | Stored plaintext in SQLite (see TECH_DEBT.md) |

---

## Confidence

**High.** Architecture derived from reading every source file. Data flow verified by tracing route handlers in `main.py` and cross-checking with `database.py`, `auth.py`, and the nginx configuration. File system layout confirmed by `scan_storage.py` and `decompiler.py`.

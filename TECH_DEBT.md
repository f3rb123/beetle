# Cortex — Technical Debt

Issues are listed in rough priority order within each category.

---

## Critical / Security Issues

### TD-01: JWT Stored in localStorage
**File:** `frontend/src/lib/auth.js:5-6`  
`localStorage.setItem('cortex_token', token)` — any JavaScript executing on the page can exfiltrate the token. This is a textbook XSS escalation path.  
**Fix:** Use `HttpOnly` cookies with `SameSite=Strict` and `Secure`. The FastAPI backend would need to set the cookie on login and clear it on logout. The nginx reverse proxy would forward the cookie. This is a non-trivial refactor.

### TD-02: Webhook Secrets Stored Plaintext
**File:** `backend/webhooks.py` — the `secret` field is inserted directly into SQLite without hashing.  
API keys (`auth.py`) are bcrypt-hashed. Webhook secrets are not. A SQLite dump exposes all webhook secrets immediately.  
**Fix:** Hash webhook secrets with bcrypt on write; display the plaintext secret only at creation time (same pattern as API keys).

### TD-03: No Rate Limiting on Auth Endpoints
**File:** `backend/main.py` (login route), `backend/auth.py`  
There is no brute-force protection on `POST /api/auth/login`. An attacker can make unlimited login attempts. Bcrypt slows each attempt but doesn't stop automated attacks.  
**Fix:** Add `slowapi` (FastAPI rate limiter) or implement a per-IP attempt counter in Redis/SQLite.

### TD-04: Live Secret Probing Uses Real Credentials
**File:** `backend/analyzers/secret_validator.py`  
When the system validates a discovered secret, it actually calls the corresponding API (GitHub, Stripe, Slack, etc.) using that secret. If the scanned app belongs to a production environment, this is unilateral credential use that may violate the app owner's terms of service and could trigger account security alerts.  
**Fix:** Add an explicit consent flag to the scan submission, or limit live validation to explicitly non-production environments.

---

## Architecture Issues

### TD-05: No Shared SQLite Connection Pool
**Files:** `auth.py`, `custom_rules.py`, `ai_enrichment.py`, `cve_mapper.py`, `audit.py`, `webhooks.py`, `database.py`  
Every module opens its own SQLite connection with `sqlite3.connect()`. SQLite in WAL mode tolerates this, but there is no central connection lifecycle management. Schema changes in one module (e.g., `ai_enrichment_cache`) are invisible to `database.py`'s migration system.  
**Fix:** Consolidate all schema definitions into `database.py` migrations. Use a single connection factory or SQLAlchemy with connection pooling.

### TD-06: Fragmented Schema Management
**Files:** `ai_enrichment.py:_init_cache()`, `cve_mapper.py:_init_cache()`  
Both modules create their own SQLite tables using `CREATE TABLE IF NOT EXISTS` in module-level init functions, outside the central migration system in `database.py`. This means those tables won't be created if the module's init function isn't called (e.g., in tests), and they aren't tracked in any migration history.  
**Fix:** Move all `CREATE TABLE` statements into `database.py`'s migration function.

### TD-07: Scan Results Stored as a Single JSON Blob
**File:** `backend/database.py` — `scans.results_json` column  
The entire scan output — potentially thousands of findings, tracker lists, domain results, binary analysis — is stored as one JSON blob. This makes partial result queries, finding-level updates, and search impossible at the database layer. It also means every API call to view any part of a scan result deserializes and serializes the entire blob.  
**Fix:** Normalize findings into a separate `findings` table. This is a major schema migration but enables future features like suppression, tagging, and search.

### TD-08: Max Concurrent Scans Hardcoded
**File:** `backend/main.py` — `ThreadPoolExecutor(max_workers=3)`  
The scan queue depth is hardcoded. High-throughput environments cannot tune this without modifying source code. With 4 CPUs allocated to the backend, 3 concurrent scans is conservative (scan threads are I/O-bound during decompilation).  
**Fix:** Read from `CORTEX_MAX_CONCURRENT_SCANS` env var, defaulting to 3.

### TD-09: PDF Generation is Synchronous and Unbounded
**Files:** `backend/main.py` (PDF download route), `backend/report/pdf_generator.py`  
PDF generation runs in the HTTP request handler thread with no timeout and no memory limit. A scan with 500+ findings can produce a very large PDF and either exhaust memory or time out the client HTTP connection.  
**Fix:** Run PDF generation in a background thread (or the scan executor) and cache the output file. Return 202 Accepted + a download URL that becomes available when generation completes.

### TD-10: No Pagination on List Endpoints
**File:** `backend/main.py`  
`GET /api/scans` returns all scans. `GET /api/webhooks` returns all webhooks. `GET /api/rules` returns all rules. As data grows, these endpoints will serialize and transmit unbounded amounts of JSON.  
**Fix:** Add `?page=N&limit=M` parameters with a default page size (e.g., 50).

---

## Correctness Issues

### TD-11: Python Version Discrepancy
**Files:** `backend/Dockerfile` (line 1), inline app comments  
The Dockerfile uses `FROM python:3.11-slim` but various source comments and the app metadata reference Python 3.12. This is not a runtime failure (3.11 is compatible) but creates confusion about the intended runtime and may mask 3.12-specific features or deprecations.

### TD-12: Semgrep Not Available in Docker Image
**File:** `backend/requirements.txt`, `backend/Dockerfile`  
`semgrep>=1.70.0` is in `requirements.txt` and will be installed by `pip`. However, `semgrep_runner.py` invokes Semgrep as a CLI command (`subprocess.run(["semgrep", ...])`) and Semgrep's pip package does not always install a `semgrep` binary in PATH on all platforms. The Dockerfile does not `RUN which semgrep` or validate this. As shipped, Semgrep silently produces no findings.  
**Fix:** Add `RUN semgrep --version` as a Dockerfile build step to fail-fast if Semgrep is not functional.

### TD-13: LIEF May Not Be Available at Runtime
**File:** `backend/requirements.txt`, `backend/Dockerfile`  
`lief>=0.14.0` is in `requirements.txt` but `python:3.11-slim` may be missing native C++ libraries that LIEF requires. All LIEF-dependent code degrades gracefully to empty results — silently. The analyst has no indication that deep binary analysis was skipped.  
**Fix:** Add a startup health check that logs LIEF availability. Consider pinning LIEF to a known-working version and testing the Dockerfile build.

### TD-14: VirusTotal Rate Limiting is Per-Process Only
**File:** `backend/analyzers/virustotal.py:_RATE_DELAY`  
The 0.25s inter-request delay is a module-level sleep in a single thread. When 3 scans run concurrently, each running VirusTotal checks independently, the effective rate is 3× the expected rate with no coordination.  
**Fix:** Use a shared `threading.Lock` with a timestamp check to serialize VT requests across all concurrent scans.

### TD-15: Taint Analysis Timeout Produces Silent Incomplete Results
**File:** `backend/analyzers/taint_analyzer.py:TIMEOUT_S=60`  
The taint analysis has a 60-second threading timeout. When it fires, the analysis returns whatever was found so far, with no indication in the results that coverage was partial. Analysts may assume taint analysis is complete when it is not.  
**Fix:** Add a `"taint_timeout": true` field to the results dict when the timeout fires. Surface this in the frontend's Taint Flows section.

### TD-16: Audit Log API Caps at 500 Entries
**File:** `backend/audit.py`  
The `/api/audit` endpoint returns at most 500 rows ordered by timestamp DESC. Entries beyond 500 are inaccessible via the API. For compliance scenarios, this is a significant gap.  
**Fix:** Add cursor-based pagination to the audit log endpoint. Consider adding a log export route that streams all entries.

---

## Dependency Issues

### TD-17: androguard 4.1.3 Has No Known Replacement for Some APIs
**File:** `backend/requirements.txt`  
Androguard 4.x changed several APIs from 3.x. The codebase targets 4.1.3 specifically. If androguard 4.2+ breaks backward compatibility again, taint analysis and certificate extraction would fail silently.  
**Fix:** Pin androguard to `==4.1.3` (already done) and add integration tests that verify the androguard API contract.

### TD-18: No Test Suite
The repository contains zero test files. No unit tests, no integration tests, no smoke tests. There is no `pytest` in `requirements.txt` and no `tests/` directory.  
**Impact:** Every change carries full regression risk. The Semgrep and LIEF issues (TD-12, TD-13) would be caught immediately by a Docker build + integration test.  
**Fix:** Add pytest + at minimum: auth flow tests, scan submission tests, basic analyzer smoke tests with a known APK fixture.

### TD-19: Stale Tracker Signatures
**File:** `backend/analyzers/tracker_db.py`  
- **MoPub** (`com.mopub`): Shut down by Twitter in January 2023. Any detection is a historical artifact.
- **Twitter SDK** (`com.twitter.sdk.android`): Deprecated; Twitter's Fabric SDK was absorbed into Firebase. Detections are for apps that haven't updated.
- No mechanism to update tracker signatures without a code deployment.  
**Fix:** Move tracker signatures to a database table or versioned JSON file that can be updated without a code change.

---

## UX / API Design Issues

### TD-20: `probeAuthEnabled()` Returns False on Network Error
**File:** `frontend/src/lib/auth.js:106-118`  
If `fetch('/api/auth/me')` throws a network exception, `probeAuthEnabled()` returns `false` — which callers may interpret as "auth is disabled." This is the opposite of fail-secure behavior.  
**Fix:** Return `true` on network error (fail-closed: assume auth is required).

### TD-21: No File Deduplication
**File:** `backend/main.py` (upload handler)  
Uploading the same APK file twice creates two separate scans and runs the full analysis pipeline twice, wasting CPU, disk, and potentially VT/OSV API quota.  
**Fix:** On upload, check `sha256` against existing completed scans. If found, return the existing scan ID with a `"deduplicated": true` flag.

### TD-22: `compare_scans()` is O(n²)
**File:** `backend/database.py::compare_scans()`  
The scan comparison function compares two finding lists by iterating through all findings in scan B for each finding in scan A to find matches. For two scans with 200 findings each, this is 40,000 comparisons.  
**Fix:** Build a dict keyed on `(title, file_path, category)` for O(n) lookup.

---

## Minor Issues

### TD-23: `memcpy` Flagged as Dangerous in ELF Analysis
**File:** `backend/analyzers/elf_analyzer.py`  
`memcpy` is in the `dangerous_imports` list alongside `strcpy`, `gets`, and `system`. Unlike those functions, `memcpy` is not inherently unsafe — it requires a bounds error to be exploitable. This generates frequent false positives, especially for apps using any C++ STL containers.

### TD-24: Audit Log Grows Unbounded
**File:** `backend/audit.py`  
The `audit_log` table has no retention policy. `cleanup_expired()` does not touch audit logs. Over time, the table will grow indefinitely.  
**Fix:** Add a configurable audit log retention period (e.g., 90 days) with a cleanup job.

### TD-25: No Structured Logging Strategy
The codebase mixes `loguru`, Python's standard `logging`, and implicit `print()` calls across different modules. `loguru` is in requirements but standard `logging.getLogger()` is the dominant pattern in the analyzer files.  
**Fix:** Pick one logging strategy (loguru or standard logging) and apply it consistently.

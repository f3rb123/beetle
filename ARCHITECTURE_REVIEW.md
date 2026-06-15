# Cortex — Principal AppSec Architect Review

**Reviewer perspective:** Principal AppSec Architect with experience in security tooling, SaaS platforms, and enterprise deployment requirements.  
**Basis:** Full source code read across all backend modules, frontend, infrastructure, and configuration files.  
**Date of review:** 2026-06-15

---

## Executive Summary

Cortex is a technically ambitious tool with impressive coverage breadth for a single-developer or small-team project. The analyzer ecosystem is genuinely impressive — taint analysis, attack chain synthesis, CISA KEV integration, live secret validation, and SBOM generation in a single self-hosted Docker container is a compelling offering. However, the architecture has significant structural debt that limits both its security posture and its ability to scale beyond single-instance, low-volume usage. Several security issues in the platform itself would be disqualifying for enterprise deployment without remediation.

**Verdict:** Strong proof-of-concept / internal tooling. Not enterprise-ready without addressing the critical findings below.

---

## Architectural Flaws

### FLAW-1: Monolithic Single-File Controller (Critical)

`backend/main.py` is 1,276 lines and owns: all API routing, scan queue management, SSE streaming, report generation dispatch, webhook triggering, and file I/O. This is an anti-pattern at any scale. Changes to any one concern risk regressions in unrelated areas, and the module is untestable as a unit.

**Recommendation:** Decompose into:
- `routes/scans.py` — scan CRUD and upload
- `routes/auth.py` — auth endpoints  
- `routes/reports.py` — report generation
- `routes/admin.py` — user, webhook, rule management
- `services/scan_queue.py` — queue and worker management
- `services/sse.py` — SSE stream management

### FLAW-2: SQLite as the Sole Data Store (High)

SQLite in WAL mode supports concurrent reads and one writer, which is adequate for very low-volume single-instance deployments. It fails at:

- **Multi-instance deployment:** No shared state between replicas. Horizontal scaling is impossible.
- **High concurrency:** WAL write lock serializes all writes. Heavy scan result writes (large `results_json` blobs) block audit log writes, user auth, etc.
- **Operational visibility:** No standard metrics, no slow-query logging, no connection pool tuning.
- **Schema evolution:** No migration framework (Alembic, Flyway). Schema changes are raw `CREATE TABLE IF NOT EXISTS` scattered across 7 modules.

**Recommendation:** Migrate to PostgreSQL. Add Alembic for migrations. This is the single largest enabler of enterprise readiness.

### FLAW-3: All Scan Results in a Single JSON Blob (High)

`scans.results_json` stores the entire scan output — potentially thousands of findings, tracker lists, domain enrichment, binary analysis, and taint flows — as one serialized dict. Consequences:

- No server-side finding search, filter, or sort
- No partial result loading — every API call to view any section deserializes the full blob
- No finding-level operations (suppression, annotation, severity override) without rewriting the entire blob
- Blob size grows without bound — a complex APK produces 2–5MB of JSON

**Recommendation:** Normalize findings into a `findings` table with `(scan_id, rule_id, severity, category, file_path, line, title, description, ...)` columns. Store non-finding metadata (app_info, permissions, trackers) in separate typed tables or a JSON column. This enables pagination, suppression, search, and real-time partial result streaming.

### FLAW-4: No Queue Backend — In-Process ThreadPoolExecutor (High)

The scan queue is a Python `ThreadPoolExecutor` inside the FastAPI process. Consequences:

- **No persistence:** If the backend process dies, all queued and running scans are lost. Scans can't be restarted.
- **No horizontal scaling:** Scans can't be distributed across workers.
- **No prioritization:** All scans are FIFO with no priority or preemption.
- **Memory sharing:** A runaway scan (OOM in androguard, leaked file handles) can destabilize the entire FastAPI process including auth and API serving.

**Recommendation:** Introduce a task queue — Celery + Redis is the most pragmatic fit given the Python ecosystem. Workers can be scaled independently. Scan state is persisted. Celery's `soft_time_limit` provides proper scan timeout enforcement.

### FLAW-5: No API Versioning (Medium)

All routes are at `/api/...` with no version namespace. Any breaking change to the API contract requires all consumers (CI/CD integrations, webhook consumers, API key users) to update simultaneously. The `sarif_exporter.py` hardcodes version `3.2.0` as the tool version, but there is no API contract versioning.

**Recommendation:** Add `/api/v1/...` prefix now, before any external API consumer exists. Cheap now; expensive later.

### FLAW-6: PDF Generation Blocks HTTP Workers (Medium)

PDF generation (`report/pdf_generator.py`) runs synchronously inside the FastAPI HTTP handler. ReportLab is CPU-bound Python. For a scan with 500 findings, this can take 10–30 seconds, blocking an entire uvicorn worker during that time.

**Recommendation:** Generate reports asynchronously (background thread or task queue worker) and cache the output file. Return a `202 Accepted` with a polling URL or a `Location` header when the report is ready.

---

## Scalability Bottlenecks

### BOTTLENECK-1: Bounded Scan Queue With No Backpressure

Max 3 concurrent scans is a sensible default but the queue has no depth limit. If 100 scans are submitted, 97 pile up in the ThreadPoolExecutor's internal queue — in memory, in the API process, with no visibility and no rejection. Under load, the FastAPI process accumulates file handles and memory for all queued scans.

**Fix:** Implement queue depth limit with a `503 Service Unavailable` response when the queue is full.

### BOTTLENECK-2: JADX is a Cold JVM

Every scan cold-starts a JVM for JADX and another for apktool. JVM startup time on `python:3.11-slim` with `default-jre-headless` is 2–5 seconds per invocation. For 3 concurrent scans, that's 6 JVM startups happening simultaneously. There is no JVM warmup or reuse.

**Mitigation:** Cache decompilation results by SHA-256. The same APK scanned twice skips decompilation entirely.

### BOTTLENECK-3: OSV.dev and ip-api.com Are External Rate-Limited Services

Both external APIs are called at scan time:
- **ip-api.com:** Free tier, 45 requests/minute, no API key, no SLA.
- **OSV.dev:** No key required but undocumented rate limits apply.

At 3 concurrent scans, each hitting up to 30 domains via ip-api.com, the rate limit is hit within the first minute of concurrent usage.

**Fix:** Shared per-service rate limiter with jitter. Cache results by domain/package+version. Respect `Retry-After` headers.

### BOTTLENECK-4: The `results_json` Blob in High-Volume Scenarios

At high scan volumes, `scans.results_json` can easily reach 5–10MB per scan. SQLite's page cache becomes dominated by large blob reads. SELECT queries on the `scans` table (which SQLite must scan sequentially for the JSON blob column) degrade as the dataset grows.

**Fix:** Store `results_json` in a separate file on disk (or object storage) and keep only a reference in the `scans` table. Or normalize (see FLAW-3).

### BOTTLENECK-5: Taint Analysis and Semgrep Are Unbounded CPU

Within a single scan, taint analysis (60-second timeout) and Semgrep (90-second timeout) can run simultaneously with JADX decompilation. Three concurrent scans running taint + Semgrep simultaneously = 9 CPU-intensive workloads against a 4-CPU budget.

**Fix:** Introduce intra-scan phase gating: decompilation → static analysis → optional expensive analysis (taint, Semgrep). Allow configuration of which phases to enable.

---

## Security Weaknesses

See also `WEAKNESSES.md` for the comprehensive security finding list.

### Critical

**SW-01: JWT in localStorage**  
Any stored XSS vulnerability in the React frontend results in complete session hijack. The frontend uses React 18 with no known XSS issues today, but the risk is structural.

**SW-02: No Rate Limiting on Login**  
Brute-force attacks against admin credentials are unconstrained. Given that the default admin credentials are configured via environment variables and many deployments likely use weak defaults, this is a high-probability exploitation path.

**SW-03: Webhook Secrets in Plaintext**  
SQLite file is stored in a named Docker volume. Volume compromise exposes all webhook HMAC signing secrets.

### High

**SW-04: Scan Platform Lacks Input Sanitization**  
Decompiler invocations pass the uploaded file path to `subprocess.run()`. The path is a UUID-based temp path controlled by the server, not user input, so direct injection is not possible. However, the filename passed to jadx/apktool via subprocess is derived from the upload. If the MIME validation or file routing logic ever passes user-controlled path components, command injection becomes possible.

**SW-05: Live Secret Probing Without Explicit User Consent**  
The secret validator calls real external APIs (GitHub, Stripe, OpenAI, etc.) with secrets extracted from the scanned app. This is ethical and legal when the analyst owns the app, but the system provides no consent mechanism, audit trail for external API calls made, or opt-out for specific validators. For an MSSP scanning third-party apps, this is a liability.

**SW-06: Webhook SSRF Defense Is Incomplete**  
The SSRF defense checks whether the resolved IP is private, but does not handle:
- IPv6 addresses (::1, fc00::/7, fe80::/10 ranges)
- DNS CNAME chains (only the final A record is checked)
- HTTP redirects in the webhook response that point to private addresses (open redirect → SSRF)

### Medium

**SW-07: No CSRF Protection on Mutation Endpoints**  
JWT in localStorage means standard CSRF via cookies is not possible. However, if a victim is authenticated, a malicious site could make cross-origin POST requests using `fetch()` without CORS preflight for simple requests. FastAPI's default CORS configuration should be verified.

**SW-08: API Key Validation Is O(n) bcrypt**  
Every API key auth check iterates all API keys and runs bcrypt compare on each. At 100 API keys with bcrypt cost factor 12, each authentication takes ~100 × 200ms = 20 seconds. Practical, but a vector for DoS via excessive key provisioning. The fix is a lookup hint — store a fast hash (SHA-256) alongside the bcrypt hash for key lookup, use bcrypt only for the matched key.

---

## Missing Enterprise Features

### ENTERPRISE-01: Multi-Tenancy / Organization Support

There is a single user namespace. In a multi-team or MSSP context, Team A should not see Team B's scans. There is no concept of organization, project, or workspace isolation.

### ENTERPRISE-02: SSO / SAML / OIDC Authentication

The only supported auth is local username/password. Enterprise deployments require SSO integration (Okta, Azure AD, Google Workspace). This typically means SAML 2.0 SP-initiated flow or OIDC via `python-jose`.

### ENTERPRISE-03: Finding Suppression and False Positive Management

There is no mechanism to mark a finding as a known false positive, suppress it from future scans, or require analyst sign-off. Without suppression, the CI/CD policy gate cannot be tuned for an app's specific risk posture.

### ENTERPRISE-04: Scan Scheduling

There is no scheduler. All scans are on-demand (manual upload or API call). Enterprise CI/CD requires: automated re-scan on APK build, scheduled weekly re-scans, webhook trigger from artifact repository.

### ENTERPRISE-05: Report Branding

PDF reports are Cortex-branded. MSSPs or security teams delivering reports to clients need customizable cover pages, logos, and headers.

### ENTERPRISE-06: Finding Export to JIRA / Linear / GitHub Issues

There is no integration for creating tickets from findings. Analysts must manually copy findings into their defect tracker.

### ENTERPRISE-07: Differential Alerting via Webhook

The webhook fires on `scan.complete` but sends a generic payload. There is no "new critical finding compared to previous scan" event type, which is the most useful signal for CI/CD gates.

### ENTERPRISE-08: Audit Log Retention and Export

The audit log API caps at 500 entries and has no export. SOC 2, PCI-DSS, and GDPR all require durable, exportable audit trails with configurable retention periods.

### ENTERPRISE-09: Role Granularity

Two roles (admin/analyst) is insufficient for enterprise. Typical requirements: read-only role (view results, no upload), team lead (manage rules), security manager (view audit, manage users), API-only role (CI/CD integration, no UI access).

### ENTERPRISE-10: Air-Gapped Deployment

Live checks (VirusTotal, Firebase probing, CISA KEV, ip-api.com, OSV.dev) assume internet connectivity. There is no offline mode with bundled databases for air-gapped environments. The CISA KEV has no offline fallback.

---

## Features That Should Be Removed or Scoped Down

### REMOVE-01: Secret Validator Live Probing (Scope Down, Not Remove)

Live probing of extracted credentials is high-value but high-risk. It should be:
- **Opt-in per scan** (not on by default)
- **Logged explicitly** in the audit log with target service and result
- **Explicitly acknowledged** by the submitting user at upload time
- **Disabled for non-owner scenarios** with a flag

Keep the feature; add consent and governance around it.

### REMOVE-02: ip-api.com Dependency

The domain analyzer sends up to 30 domains per scan to a free, no-SLA, rate-limited third-party service. A single burst of scans can exhaust the rate limit for the entire deployment. For offline deployments it simply doesn't work. 

**Replace with:** MaxMind GeoLite2 database (free, no-SLA but offline-capable) bundled in the Docker image, updated on build. Keep OFAC check as a static country-code lookup from the GeoLite2 data.

### REMOVE-03: APKiD-Style Detection via DEX String Heuristics

`detect_apkid_features()` in `api_analyzer.py` mimics APKiD by looking for specific strings in DEX output. This approach produces:
- False negatives on packer/protector tools that don't embed recognizable strings
- False positives when code comments or documentation reference these strings
- No discrimination between protection at the class level vs the method level

Real APKiD (if installed in Docker) would be significantly more accurate. Either ship real APKiD or remove the heuristic detector and be explicit that APKiD analysis requires the external tool.

### REMOVE-04: memcpy as a Dangerous Import

`elf_analyzer.py` flags `memcpy` alongside `strcpy` and `system` as a dangerous import. `memcpy` is standard C library and its presence in a binary is not a meaningful security signal. It generates noise and dilutes the signal-to-noise ratio of binary hardening findings.

---

## Recommendations Prioritized by Impact

| Priority | Recommendation | Impact |
|----------|---------------|--------|
| P0 | Fix JWT → HttpOnly cookie | Eliminates XSS session hijack |
| P0 | Add rate limiting to login endpoint | Prevents brute force |
| P0 | Hash webhook secrets at rest | Eliminates credential exposure on DB compromise |
| P1 | Fix Semgrep in Docker (validate binary is in PATH) | Activates an entire SAST layer that is silently missing |
| P1 | Validate LIEF availability and log when degraded | Makes binary analysis gaps visible |
| P1 | Normalize findings into a DB table | Enables suppression, search, pagination, CI/CD tuning |
| P1 | Add audit log export and pagination | Unlocks compliance use cases |
| P2 | Migrate to PostgreSQL | Enables horizontal scaling, proper concurrency |
| P2 | Add Celery + Redis task queue | Enables persistent queue, multi-worker, proper timeout |
| P2 | Implement finding suppression | Makes the CI/CD gate usable in practice |
| P2 | Re-enable hardcoded secret exfil chain with type filter | Closes the most critical attack chain gap |
| P3 | Replace ip-api.com with MaxMind GeoLite2 | Eliminates rate-limit dependency, enables air-gapped use |
| P3 | Add SSO/OIDC authentication | Unlocks enterprise deployment |
| P3 | Add multi-tenancy | Enables MSSP and multi-team use |
| P3 | Add scan deduplication by SHA-256 | Reduces wasted compute and API quota |
| P4 | Add integration test suite | Enables safe iteration and prevents regressions |
| P4 | Decompose main.py | Enables maintainability and independent testing |
| P4 | Add API versioning | Prevents breaking change pain as the API evolves |

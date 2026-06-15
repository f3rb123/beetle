# Beetle 2.0 — Cortex Evolution Roadmap

**Document purpose:** Opinionated roadmap for evolving Cortex from a capable prototype into a production-grade mobile security platform.  
**Reviewer:** Principal AppSec Architect  
**Naming note:** "Beetle 2.0" is used as a codename for the next major version; the product name "Cortex" is retained.

---

## North Star

**Cortex 2.0 goal:** The most capable self-hosted mobile AppSec platform for security teams that need full CI/CD integration, dynamic analysis, enterprise-grade reliability, and supply chain intelligence — without sending data to a third-party SaaS.

**Success criteria:**
1. Analysts can assess any Android/iOS app in < 15 minutes with confidence that all major attack surfaces are covered.
2. CI/CD pipelines can block on Cortex policy without false positives degrading developer trust.
3. A 5-person security team can run Cortex at scale (500+ scans/month) without operational issues.
4. The platform's own security posture is defensible to a CISO.

---

## Phase 0 — Fix the Foundation (Before Anything Else)
*Target: 2–4 weeks. No new features until these are done.*

These are security and correctness issues that make the current version unsuitable for production use. They block Phase 1.

### P0-01: Fix JWT Storage (Security Critical)
Migrate from `localStorage` to `HttpOnly` cookie.

**Backend changes:**
- `POST /api/auth/login` → set `Set-Cookie: cortex_session=<jwt>; HttpOnly; Secure; SameSite=Strict; Path=/api`
- `POST /api/auth/logout` → clear the cookie
- `GET /api/auth/me` → read from cookie

**Frontend changes:**
- Remove all `localStorage.getItem/setItem('cortex_token')` calls
- `apiFetch()` uses credentials: 'include' instead of Authorization header
- Update `RequireAuth` to probe `/api/auth/me` for auth state

**Estimated effort:** 2 days.

---

### P0-02: Add Login Rate Limiting
Add `slowapi` to the FastAPI app. Configure: 5 attempts per IP per 60 seconds on `POST /api/auth/login`. Log failed attempts (with IP and attempted username) to the audit log.

**Estimated effort:** 4 hours.

---

### P0-03: Hash Webhook Secrets
On webhook creation/update: encrypt the secret with AES-256-GCM using `SECRET_KEY` as the key. Store the ciphertext. Decrypt for HMAC signing at delivery time. Return plaintext only in the creation response.

**Estimated effort:** 1 day.

---

### P0-04: Validate SECRET_KEY at Startup
Fail-fast if `SECRET_KEY` is absent or shorter than 32 characters.

**Estimated effort:** 1 hour.

---

### P0-05: Fix Semgrep in Docker
Add `RUN semgrep --version` to the Dockerfile as a build-time validation. If Semgrep isn't properly installed as a CLI binary, the build fails — forcing the issue to be resolved rather than silently degrading.

**Estimated effort:** 2 hours.

---

### P0-06: Add HTTP Security Headers to Nginx
Add `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy` headers to `nginx.conf`.

**Estimated effort:** 2 hours.

---

### P0-07: Add Integration Tests (Smoke Suite)
Add pytest with a minimal fixture APK and IPA. Tests must verify:
- Auth (login, token, role enforcement)
- Scan upload and completion (mock-heavy is fine)
- PDF/SARIF/SBOM generation returns 200
- Webhook delivery (with mock endpoint)

**Estimated effort:** 3 days.

---

## Phase 1 — Platform Reliability (Weeks 4–12)
*Goal: Make Cortex reliable for a team running 50–100 scans/month.*

### P1-01: Migrate to PostgreSQL

Replace SQLite with PostgreSQL as the primary data store. Add Alembic for schema migrations.

**Migration steps:**
1. Create `alembic.ini` + `migrations/` directory
2. Generate initial migration from current schema
3. Add `DATABASE_URL` env var (default to SQLite for backward compat via short-term adapter)
4. Replace all `sqlite3.connect()` calls with SQLAlchemy session factory
5. Consolidate all table creation into Alembic (remove self-managing `CREATE TABLE` in `ai_enrichment.py`, `cve_mapper.py`)
6. Update Docker Compose to add a `postgres:16-alpine` service

**Estimated effort:** 2 weeks.

---

### P1-02: Normalize Findings into a Database Table

Create a `findings` table:

```sql
CREATE TABLE findings (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id       UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id       TEXT,
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    category      TEXT,
    file_path     TEXT,
    line          INTEGER,
    snippet       TEXT,
    description   TEXT,
    recommendation TEXT,
    cwe           TEXT,
    masvs         TEXT,
    owasp         TEXT,
    source        TEXT,
    confidence    INTEGER,
    exploitability INTEGER,
    suppressed    BOOLEAN DEFAULT FALSE,
    suppressed_by TEXT,
    suppressed_at TIMESTAMPTZ,
    suppression_reason TEXT,
    created_at    TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
```

This enables: server-side pagination, severity filtering, suppression, search, and CI/CD gate accuracy.

**Estimated effort:** 1 week (schema + API endpoint changes).

---

### P1-03: Replace ThreadPoolExecutor with Celery + Redis

Add Celery for scan task management. Redis as broker and result backend.

**Architecture:**
```
FastAPI → Redis broker → Celery worker(s)
                      ↑
              scan_task.apply_async()
```

Benefits:
- Queued scans persist across restarts
- Worker count configurable (env var)
- Task result storage for scan status
- Proper timeout enforcement via `soft_time_limit`
- Worker health monitoring

**Docker Compose additions:**
```yaml
redis:
  image: redis:7-alpine
  
worker:
  build: ./backend
  command: celery -A tasks worker --loglevel=info --concurrency=3
  depends_on: [backend, redis]
```

**Estimated effort:** 1 week.

---

### P1-04: Implement Finding Suppression

Build on P1-02 (findings table). Add:
- `PATCH /api/scans/{scan_id}/findings/{finding_id}` — suppress/unsuppress
- `POST /api/suppressions/bulk` — suppress by `(rule_id, sha256)` for app-level suppression
- `suppressions` table: `(rule_id, app_sha256, created_by, reason, expires_at)`
- Frontend: "Suppress" action button on each finding
- CI/CD gate: suppressed findings do not count toward thresholds

**Estimated effort:** 1 week.

---

### P1-05: Add Scan Deduplication by SHA-256

On upload: check `sha256` against completed scans. If match found, return existing scan ID with `"deduplicated": true`. Optional: allow forcing a re-scan with `?force=true`.

**Estimated effort:** 4 hours.

---

### P1-06: Replace ip-api.com with MaxMind GeoLite2

Bundle MaxMind GeoLite2-City and GeoLite2-Country databases in the Docker image (updated on build via MaxMind API key). Domain enrichment becomes fully offline. OFAC check becomes a country-code lookup against a static list.

```dockerfile
RUN wget -q "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz" \
    | tar -xz --strip-components=1 -C /opt/maxmind/
```

**Estimated effort:** 3 days.

---

### P1-07: Audit Log Pagination and Export

- Add cursor-based pagination to `GET /api/audit?cursor=<timestamp>&limit=100`
- Add `GET /api/audit/export` → streams full log as NDJSON
- Add 90-day retention policy with scheduled cleanup

**Estimated effort:** 1 day.

---

### P1-08: Fix API Key Auth to O(1) Lookup

Store a SHA-256 "lookup hash" alongside the bcrypt hash. On auth: compute `SHA-256(submitted_key)`, look up by that hash, then bcrypt-verify only the matched row.

```sql
ALTER TABLE users ADD COLUMN api_key_lookup_hash TEXT;
CREATE UNIQUE INDEX idx_users_api_key_lookup ON users(api_key_lookup_hash);
```

**Estimated effort:** 4 hours.

---

## Phase 2 — Dynamic Analysis (Months 3–6)
*Goal: Add runtime analysis to close the largest capability gap versus MobSF.*

### P2-01: Android Emulator Dynamic Analysis

Integrate with Android emulator for runtime behavior capture.

**Architecture:**
```
Cortex backend
  └─ dynamic_analyzer.py
      └─ adb_client.py  — ADB wrapper (push APK, start activity, collect logs)
      └─ frida_client.py — Frida RPC (inject hooks, capture API calls)
      └─ traffic_capture.py — mitmproxy integration (HTTPS interception)
```

**Capabilities to implement:**
- Auto-install and launch APK in emulator
- Capture Logcat output during execution
- Capture network traffic via mitmproxy
- Frida hooks for: `SharedPreferences`, `SQLite`, `KeyStore`, `Crypto`, `WebView`
- Screenshot capture at key events
- Runtime permission grant/deny recording

**Infrastructure:** Add an Android emulator container (e.g., `budtmo/docker-android`) to Docker Compose. Gate dynamic analysis on `CORTEX_DYNAMIC_ENABLED=1`.

**Estimated effort:** 6–8 weeks.

---

### P2-02: iOS Dynamic Analysis (Jailbroken Device)

Add Frida-based iOS dynamic analysis for connected jailbroken devices. Requires:
- libimobiledevice for device communication
- Frida server on the device
- SSL kill switch for traffic capture

**Estimated effort:** 4–6 weeks (after P2-01 establishes the dynamic analysis framework).

---

### P2-03: Differential Alerting Webhook Events

Add event type `scan.new_critical` — fires when a scan has critical findings not present in the previous scan of the same app (by sha256-based history). This is the most actionable CI/CD webhook signal.

**Estimated effort:** 1 day (after P1-02 finding normalization).

---

## Phase 3 — Enterprise Features (Months 6–12)

### P3-01: Multi-Tenancy (Organization / Workspace Isolation)

Add `organizations` table. Each user belongs to one org. Scans, webhooks, custom rules are org-scoped. Admins see only their org. Super-admins (new role) see all orgs.

```sql
CREATE TABLE organizations (
    id    UUID PRIMARY KEY,
    name  TEXT NOT NULL,
    slug  TEXT UNIQUE NOT NULL
);
ALTER TABLE users ADD COLUMN org_id UUID REFERENCES organizations(id);
ALTER TABLE scans ADD COLUMN org_id UUID REFERENCES organizations(id);
```

**Estimated effort:** 2–3 weeks.

---

### P3-02: SSO via OIDC

Add `python-authlib` OIDC integration. Support:
- Google Workspace
- Azure Active Directory
- Okta (any OIDC provider)

**Configuration:**
```
CORTEX_OIDC_PROVIDER_URL=https://accounts.google.com
CORTEX_OIDC_CLIENT_ID=xxx
CORTEX_OIDC_CLIENT_SECRET=xxx
```

Auto-provision user on first OIDC login. Map group membership to Cortex roles.

**Estimated effort:** 1 week.

---

### P3-03: Advanced Role System

Expand from 2 roles to 5:
- `super_admin` — multi-org management
- `admin` — org management, user management
- `security_lead` — manage rules, view audit, approve suppressions
- `analyst` — upload scans, view results, suppress findings
- `readonly` — view results only (for developers, product managers)

**Estimated effort:** 1 week.

---

### P3-04: JIRA / GitHub Issues Integration

Add `integrations` table. Admin-configured per-org. Allow analysts to create a JIRA ticket or GitHub issue from a finding with one click:
- Finding title, description, severity, CWE, MASVS mapping pre-filled
- Link back to Cortex finding
- Bidirectional: ticket ID stored in the finding, status synced

**Estimated effort:** 2 weeks.

---

### P3-05: Scheduled Scans

Add a scan scheduler. Admin can configure "re-scan this app every Monday at 08:00" with a webhook trigger from an artifact repository (Nexus, Artifactory, GitHub Releases). Requires Celery beat for scheduling.

**Estimated effort:** 1 week (after P1-03 Celery).

---

### P3-06: Report Branding

Allow admins to upload a logo and set a report title/organization name. Applied to PDF cover page and report headers. Useful for MSSPs delivering reports to clients.

**Estimated effort:** 3 days.

---

### P3-07: Air-Gap / Offline Mode

Bundle offline datasets:
- CISA KEV snapshot (updated on Docker build)
- MaxMind GeoLite2 (P1-06)
- OSV offline database subset for common libraries
- Disable all external API calls when `CORTEX_OFFLINE=1`

**Estimated effort:** 1 week.

---

## Phase 4 — Intelligence Platform (Month 12+)

### P4-01: App Comparison Across Time (Trend Dashboard)

Store finding counts and scores per scan. Build a time-series view showing how an app's security posture changes across releases. Identify regressions automatically.

### P4-02: Cross-App Intelligence

When an organization has scanned 50+ apps, surface insights: "This tracker appears in 80% of your apps", "This CVE appears in 12 apps — prioritize fixing the shared library." Requires finding normalization (P1-02) and multi-app queries.

### P4-03: Custom AI Models for Finding Enrichment

Allow the AI enrichment model to be configured (replace Claude Haiku with a local model via Ollama, or GPT-4, or a custom fine-tuned model). The 7-day cache means the cost per finding is low regardless of model.

### P4-04: Threat Intelligence Feed Integration

Subscribe to threat intelligence feeds (AlienVault OTX, MISP) to correlate discovered IoCs (IPs, domains) with known threat actors. Surface "this domain is used by APT-XX" in the domain analysis section.

### P4-05: Frida Script Library

Build a curated library of Frida scripts for mobile security testing, accessible from the Cortex UI. Scripts can be launched against a connected device or emulator directly from the Cortex findings workspace.

---

## Removed Features (Deprecated in 2.0)

### DEPRECATE-01: ip-api.com Dependency

Replaced by MaxMind GeoLite2 (P1-06). Remove all `ip-api.com` API calls. The `domain_analyzer.py` module is rewritten to use the local MaxMind database.

### DEPRECATE-02: APKiD Heuristic Detection via DEX Strings

`detect_apkid_features()` in `api_analyzer.py` is removed. Replace with:
- If APKiD is installed in the Docker image: run real APKiD and parse its output
- If not: omit the section entirely rather than show unreliable heuristics

The Dockerfile should attempt to install APKiD (`pip install apkid`) and emit a build warning if unavailable.

### DEPRECATE-03: `memcpy` as a Dangerous Import in ELF Analysis

Removed from the dangerous imports list in `elf_analyzer.py`. The remaining list (`strcpy`, `strcat`, `sprintf`, `gets`, `scanf`, `system`, `popen`, `execve`, `dlopen`) is sufficient and accurate.

---

## Technical Dependency Upgrades

| Component | Current | Target | Reason |
|-----------|---------|--------|--------|
| Python | 3.11 | 3.12 | Match declared intent; 3.12 perf gains |
| FastAPI | 0.111.0 | 0.115+ | Active development, Pydantic v2 improvements |
| androguard | 4.1.3 | 4.x latest | Bug fixes, APK format support |
| ReportLab | 4.1.0 | 4.x latest | PDF rendering improvements |
| React | 18.3.1 | 18.x / 19 | React 19 concurrent features |
| Vite | 5.2.12 | 6.x | Build tooling improvements |
| nginx | alpine | 1.27-alpine | Latest stable |

---

## Team and Resource Estimates

| Phase | Duration | Primary Effort Areas |
|-------|----------|---------------------|
| Phase 0 (Security fixes) | 2–4 weeks | 1 backend engineer |
| Phase 1 (Platform reliability) | 8–12 weeks | 2 backend engineers |
| Phase 2 (Dynamic analysis) | 12–16 weeks | 2 backend + 1 mobile/security engineer |
| Phase 3 (Enterprise) | 12–16 weeks | 2 backend + 1 frontend engineer |
| Phase 4 (Intelligence) | Ongoing | Full team |

**Phase 0 and 1 are prerequisites for commercial use. Phase 2 is the capability gate for enterprise sales against MobSF. Phase 3 is the gate for MSSP and large-enterprise deployment.**

---

## Key Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Dynamic analysis infrastructure complexity | High | High | Start with emulator-only (no real device), use existing Docker Android images |
| PostgreSQL migration introduces regression | Medium | High | Comprehensive integration tests before migration |
| Celery operational complexity | Medium | Medium | Use managed Redis (ElastiCache, etc.) in production; document Docker Compose setup thoroughly |
| LIEF/androguard API changes breaking analyzers | Medium | Medium | Pin versions strictly; add CI tests against known APK fixtures |
| Legal exposure from live secret probing | High | High | Make it opt-in with consent (P0 candidate) |

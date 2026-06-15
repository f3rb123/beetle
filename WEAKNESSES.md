# Cortex — Security Weaknesses

**Scope:** Security issues in the Cortex platform itself (not in analyzed apps).  
**Methodology:** Static analysis of all source code. No dynamic testing performed.  
**Rating system:** Critical / High / Medium / Low / Info  

---

## Critical

### WEAK-01: JWT Stored in Browser localStorage

**File:** `frontend/src/lib/auth.js:5`  
**CWE:** CWE-922 (Insecure Storage of Sensitive Information)

```js
const TOKEN_KEY = 'cortex_token'
// ...
localStorage.setItem(TOKEN_KEY, token)
```

`localStorage` is accessible to all JavaScript in the same origin. Any XSS vulnerability — in a third-party npm dependency (Recharts, Lucide React, React Router), in a future UI feature that renders unsanitized scan data, or in a browser extension — can silently exfiltrate the JWT and hijack the session.

**Exploit path:** Inject JS into a scan result's app name or package name → rendered by the frontend → `localStorage.getItem('cortex_token')` → exfiltrate token → full authenticated access.

**Remediation:** Issue the JWT as an `HttpOnly; Secure; SameSite=Strict` cookie from the `/api/auth/login` endpoint. Remove all localStorage token handling. FastAPI supports cookie-based auth via `Response.set_cookie()`.

---

### WEAK-02: No Brute Force Protection on Login

**File:** `backend/main.py` (login route), `backend/auth.py`  
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)

The `POST /api/auth/login` endpoint has no:
- Rate limiting
- Account lockout
- CAPTCHA
- Login attempt logging (attempts aren't in the audit log if auth fails before the user is identified)

bcrypt slows individual attempts to ~200ms but does not prevent parallelized attacks. At 10 concurrent requests, an attacker can test 3,000 passwords per minute against a single account.

**Exploit path:** Dictionary attack against admin credentials. Common targets: `admin/admin123`, `admin/cortex`, `admin/password`.

**Remediation:** Add `slowapi` rate limiter to the login endpoint (e.g., 5 attempts per IP per minute). Log failed attempts in the audit log with the attempted username and IP. Consider exponential backoff after N failures.

---

## High

### WEAK-03: Webhook Secrets Stored Plaintext in SQLite

**File:** `backend/webhooks.py`  
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information)

```python
# webhooks.py — INSERT webhook with secret column
cursor.execute("INSERT INTO webhooks (url, secret, ...) VALUES (?, ?, ...)", 
               (url, secret, ...))
```

The HMAC-SHA256 signing secret for each webhook is stored as-is in the `webhooks` table. API keys (by contrast) are bcrypt-hashed. If the SQLite database file is compromised (volume mount access, backup exposure, path traversal in a hypothetical future endpoint), all webhook secrets are immediately usable for HMAC forgery.

**Remediation:** Hash secrets with bcrypt on write. Return the plaintext secret only in the creation response (same UX as API key creation). On delivery, the current plaintext secret stored in DB must be replaced with the hash; the actual HMAC signing value would need to be stored separately (e.g., in an env var or key management service) — or accept that bcrypt-hashed secrets cannot be re-used for HMAC and instead derive the HMAC key from a master secret + webhook ID.

Simpler alternative: Use a server-side master encryption key (`SECRET_KEY` already exists) to encrypt webhook secrets at rest using AES-GCM.

---

### WEAK-04: Live Secret Probing Without User Consent or Audit Trail

**File:** `backend/analyzers/secret_validator.py`  
**CWE:** CWE-668 (Exposure of Resource to Wrong Sphere)

The secret validator calls real external APIs (GitHub, Stripe, Slack, OpenAI, etc.) using credentials extracted from the scanned app. This occurs:
- Without an explicit user consent prompt
- Without logging the external API calls in the audit trail
- By default on every scan where secrets are found

**Scenarios where this is problematic:**
1. **MSSP scanning a client app:** The MSSP's Cortex instance uses client credentials to make API calls without explicit authorization. Depending on jurisdiction and contract terms, this may constitute unauthorized access.
2. **Continuous scanning in CI/CD:** Every build triggers live probing of the same secrets, generating unnecessary API authentication events in the target service's logs.
3. **Secret owner notification:** Some services notify account holders of unusual login activity. An analyst scanning a prod APK could trigger a security alert to the app team.

**Remediation:** Add an explicit `"enable_live_validation": bool` field to the scan submission request. Default to `false`. Require admin enablement in settings. Log every external API call made (service, endpoint, timestamp, result) in the audit trail.

---

### WEAK-05: Webhook SSRF Defense Has Gaps

**File:** `backend/webhooks.py`  
**CWE:** CWE-918 (Server-Side Request Forgery)

The SSRF defense resolves the webhook URL's hostname and checks if the IP is in a private/loopback/reserved range. Gaps:

**Gap 1 — IPv6 not checked:**  
The blocklist is IPv4-only. `http://[::1]/internal` or `http://[fc00::1]/` bypasses the check.

**Gap 2 — HTTP redirect following:**  
If the webhook endpoint responds with a `3xx` redirect to `http://169.254.169.254/` (AWS metadata), httpx follows redirects by default. The SSRF check only applies to the original URL, not the redirect target.

**Gap 3 — DNS CNAME chains:**  
The check resolves the final A record but does not follow CNAME chains independently. A carefully crafted CNAME chain that ultimately resolves to `127.0.0.1` at a different TTL may succeed.

**Gap 4 — HTTP 301 to internal after successful first call:**  
If an attacker controls the webhook endpoint, they can respond with `301 Moved Permanently` to `http://10.0.0.1/` — subsequent deliveries hit the internal address.

**Remediation:**
1. Add IPv6 private range checks (::1, fc00::/7, fe80::/10, 2002::/16).
2. Pass `follow_redirects=False` to httpx and fail webhook delivery on any redirect response.
3. Re-validate the resolved IP immediately before the TCP connection (httpx's `transport` hook can enforce this).

---

### WEAK-06: API Key Authentication Is O(n) bcrypt

**File:** `backend/auth.py`  
**CWE:** CWE-400 (Uncontrolled Resource Consumption)

API key validation iterates all API keys in the DB and runs `bcrypt.verify()` on each until one matches. bcrypt verification takes ~200ms per call. With 50 API keys and a malicious actor sending many concurrent API requests:
- Each request triggers 50 bcrypt verifications: ~10 seconds of CPU per request
- 10 concurrent invalid requests = 100 seconds of CPU = the backend is effectively DoS'd

**Remediation:** Store a fast hash (SHA-256 with a site-specific prefix) alongside the bcrypt hash. On API key auth: compute the fast hash of the submitted key, look up by fast hash (O(1) index lookup), then run bcrypt only on the matched row. This reduces 50 bcrypt calls to 1 in the happy path and 0 in the "no match" path.

---

### WEAK-07: No Output Sanitization on Scan Metadata Rendered in Frontend

**File:** `frontend/src/pages/Home.jsx`, `Results.jsx`  
**CWE:** CWE-79 (Cross-Site Scripting)

The frontend renders scan metadata including `filename`, `package_name`, `app_name`, and finding `title` / `description` strings extracted from analyzed APKs. A maliciously crafted APK can inject strings into these fields. If any rendering path uses `dangerouslySetInnerHTML` or equivalent without sanitization, XSS is achievable.

The `js_bundle_analyzer.py` even has a rule that checks for `dangerouslySetInnerHTML` in app code — suggesting awareness of the risk.

**Assessment:** React's default JSX rendering (text interpolation with `{}`) is XSS-safe for plain strings. Risk is low unless `dangerouslySetInnerHTML` is used somewhere in `Results.jsx` or `SectionViews.jsx` for rendering finding descriptions. Full audit of all `SectionViews.jsx` render paths would be needed to confirm.

**Recommendation:** Grep for `dangerouslySetInnerHTML` in the frontend source and verify it is not used with unsanitized scan data. If finding descriptions need to render markdown, use a sanitized markdown renderer (e.g., `marked` with DOMPurify).

---

## Medium

### WEAK-08: CORS Policy Not Explicitly Configured

**File:** `backend/main.py`  
**CWE:** CWE-942 (Overly Permissive Cross-Origin Resource Sharing Policy)

FastAPI does not add CORS headers by default, but there is no explicit `CORSMiddleware` configuration in the application. This means the backend either:
1. Rejects all cross-origin requests (acceptable, but blocks API consumers from browser contexts)
2. Has a permissive CORS configuration added by a middleware not visible in the files read

**Recommendation:** Explicitly configure `CORSMiddleware` with an allowlist of permitted origins. Do not use `allow_origins=["*"]` if JWT-based authentication is in use.

---

### WEAK-09: File Upload MIME Validation Is Bypassable

**File:** `backend/main.py`  
**CWE:** CWE-434 (Unrestricted Upload of Dangerous File Type)

The upload handler validates MIME type via `python-magic` (libmagic under the hood). libmagic inspects the file header — it is more robust than extension checking but can still be defeated by:
- Crafting a file with valid ZIP/APK headers followed by malicious content
- Exploiting libmagic signature ambiguities

However, the real validation gate is downstream: androguard will fail to parse a non-APK, and the scan will complete with an error result. The risk is not code execution but resource exhaustion (a crafted file that libmagic accepts but is designed to trigger worst-case behavior in the decompiler).

**Recommendation:** After MIME validation, add a secondary gate: verify the ZIP central directory contains `AndroidManifest.xml` for APK uploads (using Python's `zipfile` module). This is a fast, cheap check that prevents non-APK ZIPs from reaching the full analysis pipeline.

---

### WEAK-10: No Content Security Policy (CSP) Header

**File:** `frontend/nginx.conf`  
**CWE:** CWE-693 (Protection Mechanism Failure)

The nginx configuration does not set a `Content-Security-Policy` header. Without CSP:
- Any stored XSS in scan data can load external scripts
- Inline script injection is unrestricted
- `script-src 'unsafe-eval'` is the browser default (not restricted)

**Remediation:** Add CSP header in nginx.conf:
```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';" always;
```

Adjust `style-src` / `img-src` as needed for Tailwind and chart rendering.

---

### WEAK-11: No HTTP Security Headers

**File:** `frontend/nginx.conf`  
**CWE:** CWE-693

The nginx configuration is missing standard security headers:
- `X-Frame-Options: DENY` (clickjacking)
- `X-Content-Type-Options: nosniff` (MIME sniffing)
- `Referrer-Policy: no-referrer` (info leakage)
- `Permissions-Policy: camera=(), microphone=(), geolocation=()` (feature restriction)
- `Strict-Transport-Security` (HSTS — if TLS is terminated at nginx)

**Remediation:** Add these headers to the nginx server block. This is a 5-minute change.

---

### WEAK-12: Docker Container Runs Without TLS Termination

**File:** `docker-compose.yml`  
**CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)

The nginx frontend serves HTTP on port 9005 with no TLS configuration. All traffic — JWT tokens, uploaded APKs, scan results, admin credentials — transits in cleartext if the service is accessed over a network.

**Remediation:** The Docker Compose setup should accept TLS certificates (via Let's Encrypt / Certbot sidecar, or volume-mounted certs) and serve HTTPS. Redirect HTTP → HTTPS. Add HSTS.

---

### WEAK-13: Hardcoded Tool Versions Without Signature Verification

**File:** `backend/Dockerfile`  
**CWE:** CWE-494 (Download of Code Without Integrity Check)

```dockerfile
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip
RUN wget -q https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar
```

Both downloads happen over HTTPS, which provides transport security. However, neither download verifies a SHA-256 checksum or GPG signature of the artifact. A compromised CDN, GitHub Release, or bitbucket download could substitute a malicious binary.

**Remediation:** Add `sha256sum --check` after each download:
```dockerfile
RUN echo "EXPECTED_HASH jadx-1.5.0.zip" | sha256sum --check
```
Pin the expected hash in the Dockerfile comment so it's visible and reviewable.

---

## Low

### WEAK-14: Audit Log Does Not Record Failed Authentication Attempts

**File:** `backend/auth.py`  
Failed login attempts (wrong password, invalid JWT, unknown username) are not recorded in the audit log. Only successful operations generate audit entries.

**Impact:** Unable to detect brute-force attacks, credential stuffing, or unauthorized access attempts post-incident.

---

### WEAK-15: Scan File Retained in tmpfs After Scan Completion

**File:** `backend/main.py` — upload flow  
The uploaded APK/IPA file is saved to `/tmp/cortex/uploads/<scan_id>.<ext>`. Whether it is deleted after scan completion is not explicit in the code — the cleanup in `scan_storage.cleanup_scan()` removes the extracted scan directory but not the original upload file. The tmpfs mount means it vanishes on container restart, but within a long-running container, old upload files accumulate.

**Remediation:** Explicitly delete the upload file after scan completion (success or failure).

---

### WEAK-16: No Secrets in Environment Variable Validation at Startup

**File:** `backend/main.py`  
If `SECRET_KEY` is not set (or is an empty string), the FastAPI app starts successfully and issues JWTs signed with an empty string. This is a trivially forgeable JWT.

**Remediation:** Add startup validation:
```python
if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError("SECRET_KEY must be set and at least 32 characters")
```

---

### WEAK-17: Debug Certificate Finding Misses Common Patterns

**File:** `backend/analyzers/cert_analyzer.py`  
Debug certificate detection checks if CN/O contains "android debug", "test", or "debug". This misses:
- Certificates with `O=Unknown` / `OU=Unknown` / `L=Unknown` (common in default keystore generation)
- Certificates generated by Gradle's auto-signing for debug builds with custom Distinguished Names

**Impact:** Some debug-signed APKs are reported as non-debug, giving a false sense of security for release verification.

---

## Informational

### WEAK-18: Admin Password Seeded From Environment Variable at Startup

The initial admin password comes from `CORTEX_ADMIN_PASS`. If this environment variable is logged by the container runtime (e.g., `docker inspect`, `docker-compose logs`), the password is exposed in plaintext.

**Recommendation:** Use Docker secrets (`docker secret create`) rather than plain environment variables for the admin password in production deployments. Document this in the deployment guide.

### WEAK-19: No Subresource Integrity on Frontend Assets

Frontend static assets (JS bundles, CSS) are served from nginx with 1-year immutable caching. If an attacker could replace a cached asset at the CDN layer (not currently applicable since there is no CDN), they could inject malicious JavaScript. Not a current risk but worth noting for future CDN deployments.

---

## Summary Table

| ID | Title | Severity | File |
|----|-------|----------|------|
| WEAK-01 | JWT in localStorage | Critical | `frontend/src/lib/auth.js` |
| WEAK-02 | No brute-force protection on login | Critical | `backend/main.py` |
| WEAK-03 | Webhook secrets in plaintext | High | `backend/webhooks.py` |
| WEAK-04 | Live secret probing without consent | High | `backend/analyzers/secret_validator.py` |
| WEAK-05 | SSRF defense incomplete (IPv6, redirects) | High | `backend/webhooks.py` |
| WEAK-06 | API key auth is O(n) bcrypt | High | `backend/auth.py` |
| WEAK-07 | Frontend renders unsanitized scan metadata | High | `frontend/src/pages/Results.jsx` |
| WEAK-08 | CORS policy not explicitly configured | Medium | `backend/main.py` |
| WEAK-09 | File upload MIME validation bypassable | Medium | `backend/main.py` |
| WEAK-10 | No Content-Security-Policy header | Medium | `frontend/nginx.conf` |
| WEAK-11 | No HTTP security headers | Medium | `frontend/nginx.conf` |
| WEAK-12 | No TLS on the Docker Compose service | Medium | `docker-compose.yml` |
| WEAK-13 | Tool downloads without hash verification | Medium | `backend/Dockerfile` |
| WEAK-14 | Failed auth attempts not audited | Low | `backend/auth.py` |
| WEAK-15 | Upload files not deleted post-scan | Low | `backend/main.py` |
| WEAK-16 | Empty SECRET_KEY not rejected at startup | Low | `backend/main.py` |
| WEAK-17 | Debug cert detection misses common patterns | Low | `backend/analyzers/cert_analyzer.py` |
| WEAK-18 | Admin password in environment variable | Info | `backend/Dockerfile` |
| WEAK-19 | No SRI on frontend assets | Info | `frontend/nginx.conf` |

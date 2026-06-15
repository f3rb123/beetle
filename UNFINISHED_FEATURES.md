# Cortex — Unfinished Features

This document catalogs features that are explicitly disabled, partially implemented, or contain structural stubs indicating intended-but-unrealized functionality.

---

## 1. Hardcoded Secret Exfil Attack Chain (Explicitly Disabled)

**File:** `backend/analyzers/chain_analyzer.py` — `_chain_hardcoded_secret_exfil()`  
**Status:** Code present, function implemented, but **deliberately not called from the chain runner**.

The function body is complete: it would match apps that have both hardcoded secrets and outbound network permissions and synthesize an exfiltration chain. A comment explicitly disables it, citing: Google API keys are client-side by design and the false positive rate was too high.

**What's missing:** A per-finding category filter to restrict the chain to genuinely dangerous secret types (AWS keys, Stripe secret keys, private keys) rather than all secrets. The function uses the entire `secrets` list, which includes client-side Google API keys that are not exfil risks.

**Impact:** The attack chain system has 6 detectors but the most directly exploitable scenario (live credential leakage) produces no chain output.

---

## 2. AWS / Shopify / Databricks Secret Validators — Always Return "unknown"

**File:** `backend/analyzers/secret_validator.py`  
**Status:** All three validators are registered and will run, but are structurally incapable of returning "live" or "invalid".

- **AWS:** Validates the access key format but cannot determine validity without the secret key. Returns `"unknown"`.
- **Shopify:** Requires a shop domain that is not available from the key string alone. Returns `"unknown"`.
- **Databricks:** Requires the workspace URL from the environment. Returns `"unknown"`.

**What's missing:** For AWS — implementing [STS GetCallerIdentity with HMAC-SHA256 signing](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html) which works with access key alone. For Shopify — extracting the shop domain from the surrounding code context (e.g., from a nearby string in the same file). For Databricks — scanning for the workspace URL as a companion to the PAT.

---

## 3. Scan Comparison in the Frontend (Partially Implemented)

**File:** `backend/database.py::compare_scans()`, `frontend/src/lib/scan-data.js` (Compare section ID defined)  
**Status:** Backend `compare_scans()` function is fully implemented. The Compare section is registered in the frontend section map. Whether the frontend `SectionViews.jsx` component renders a full diff UI is not confirmed from the code read.

**What's certain:** The section ID `'compare'` exists in `SECTION_GROUPS` and `QUICK_SECTION_IDS`, and `compare_scans()` returns structured diff data. The API endpoint for comparison is present in `main.py`.

**Potential gap:** If `SectionViews.jsx` does not have a corresponding `case 'compare':` renderer, the section would display nothing.

---

## 4. No Pagination Anywhere

**Files:** `backend/main.py` (all list endpoints), `frontend/src/pages/Home.jsx`, `Results.jsx`  
**Status:** All list endpoints (`/api/scans`, `/api/webhooks`, `/api/rules`, findings within a scan) return unbounded results. No `?page=` parameter exists.

**Impact:** This is less a future feature and more a missing baseline. As scans accumulate, the `GET /api/scans` response size will grow proportionally. Finding lists inside large scans are fully loaded into the browser.

---

## 5. Audit Log Export

**File:** `backend/audit.py`, `backend/main.py`  
**Status:** The audit log is queryable up to 500 entries. There is no endpoint that streams or exports the full audit log.

**Impact:** Cannot satisfy compliance requirements that require full audit trail export (GDPR Article 30, SOC 2 evidence, PCI-DSS Requirement 10).

---

## 6. Custom Rule Testing Sandbox

**File:** `backend/custom_rules.py`, `frontend/src/pages/CustomRules.jsx`  
**Status:** Admins can create rules with regex patterns, which are validated syntactically on save. There is no endpoint that tests a rule against a sample input or against an existing scan's source tree.

**What's missing:** A `POST /api/rules/test` endpoint that accepts a `{pattern, sample_text}` body and returns matches.

---

## 7. Custom Rule Import/Export

**File:** `backend/custom_rules.py`  
**Status:** Rules are managed one-at-a-time via the API. There is no bulk import (JSON/YAML) or export endpoint.

**Impact:** Rules cannot be shared between Cortex instances or version-controlled outside of the database.

---

## 8. Source Map Analysis for JS Bundles

**File:** `backend/analyzers/js_bundle_analyzer.py`  
**Status:** The analyzer processes minified JS bundles directly. Source maps (`.map` files) that ship alongside production React Native bundles would dramatically improve pattern matching quality, but are not parsed.

**What's missing:** Detection of `.map` files alongside bundles and parsing of source locations for better finding attribution.

---

## 9. Scan Deduplication by Hash

**File:** `backend/main.py` (upload handler)  
**Status:** SHA-256 is computed and stored per scan, but no deduplication check is performed at upload time. The `sha256` column exists in the schema, suggesting deduplication was considered.

---

## 10. CISA KEV Offline Fallback

**File:** `backend/analyzers/cve_mapper.py::load_kev_set()`  
**Status:** If the CISA KEV JSON feed is unavailable at scan time and the 24-hour cache is cold (first run, or cache expired), `load_kev_set()` returns an empty set. No bundled KEV snapshot is included.

**Impact:** A Cortex instance without internet access (air-gapped deployment) never gets KEV data, silently producing lower-severity findings for known-exploited CVEs.

**What's missing:** A bundled `kev_snapshot.json` file (updated on Docker build) used as fallback when the live feed is unavailable.

---

## 11. iOS Taint Analysis

**File:** `backend/analyzers/taint_analyzer.py`  
**Status:** The taint analyzer uses androguard's DEX call graph, which is Android-only. iOS IPA analysis has no equivalent inter-procedural data-flow analysis.

**Impact:** iOS scans have no taint flow section. The "Taint Flows" section in the frontend would be empty for IOS scans.

**What's missing:** An iOS-specific taint engine — likely a static call graph built from Swift/ObjC symbol tables (LIEF can extract these) — or integration with a tool like inabox/libimobiledevice.

---

## 12. Suppression / False Positive Management

**Files:** All — no suppression mechanism exists anywhere  
**Status:** There is no way to mark a finding as a false positive, suppress it from future scans of the same app, or add analyst notes to a finding.

**Impact:** Repeated scans of the same app show the same known-benign findings every time. CI/CD policy gate counts them toward thresholds.

**What's missing:** A `finding_suppressions` table keyed on `(sha256, rule_id, file_path)`, a `PATCH /api/scans/{id}/findings/{id}` endpoint for suppression, and a "suppress" button in the frontend.

---

## 13. Tracker Signature Update Mechanism

**File:** `backend/analyzers/tracker_db.py`  
**Status:** Tracker signatures are hardcoded in Python. There is no mechanism to update them without a code change and Docker image rebuild. Some signatures (MoPub, Twitter SDK) are already stale.

**What's missing:** A versioned signature database (JSON file or SQLite table) with an admin update endpoint or periodic pull from an upstream source.

---

## 14. Scan Queue Depth Visibility

**File:** `backend/main.py`  
**Status:** There is no `/api/queue` or `/api/health/detailed` endpoint that exposes how many scans are queued or running. The only queue signal is the per-scan `status=queued` field.

**Impact:** Operators cannot see system utilization or predict wait times without querying all scan records.

---

## 15. API Versioning

**File:** `backend/main.py`  
**Status:** All routes are at `/api/...` with no version prefix. There is no `v1` or `v2` namespace.

**Impact:** Any breaking API change requires all API consumers and CI/CD integrations to update simultaneously. As the project grows, this becomes increasingly difficult to manage.

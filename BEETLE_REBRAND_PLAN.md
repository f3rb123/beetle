# Beetle Rebrand Plan

**Goal:** Migrate the product formerly known as **Cortex** to its public name **Beetle**, classifying every reference by risk class and sequencing the change so that no external contract (API keys, env vars, persisted data, webhook signatures, downstream tooling) breaks during the transition.

**Status:** Planning only. No code modified. This document is the source of truth for the migration; nothing in the repo has been renamed.

**Scope of inventory:** 329 `Cortex`/`cortex`/`CORTEX` occurrences across 57 files (excluding `frontend/node_modules/`). The nine `*.md` analysis docs at the repo root are excluded from migration scope — they are deliverables, not product surface, and will be addressed last.

---

## Classification Framework

Every reference falls into one of six classes, ordered here from **safest to change** to **most dangerous**:

| Class | What it is | Breaks if changed? | Migration risk |
|-------|-----------|--------------------|----------------|
| 1. Branding | Visible product identity (logo, titles, marketing copy) | No external contract | **Low** |
| 2. Documentation | Comments, docstrings, module headers, README-class text | Nothing | **Low** |
| 3. UI text | User-facing strings rendered in the SPA | Cosmetic only | **Low** |
| 4. Internal implementation | Logger names, internal vars, CSS namespace, package name, code identifiers | Self-contained; compile-time | **Medium** |
| 5. Environment variables | `CORTEX_*` config keys | Breaks every `.env`, CI pipeline, deploy manifest | **High** |
| 6. Database / storage | `cortex.db`, API key prefix `ck_`, HTTP headers, localStorage keys, report/SBOM/SARIF identifiers, persisted filenames | Breaks live data, issued credentials, signed payloads, downstream tool dedup | **Critical** |

The guiding principle: **Classes 1–4 are free to rename. Classes 5–6 require dual-support shims and cannot be flipped atomically.**

---

## Class 1 — Branding

Pure product identity. Safe to change in a single pass.

| Location | Reference | New value |
|----------|-----------|-----------|
| `frontend/src/components/BrandLogo.jsx:12` | `brand-lockup__title` → `Cortex` | `Beetle` |
| `frontend/src/pages/Login.jsx:51` | `<h1>Cortex</h1>` | `Beetle` |
| `frontend/index.html:6` | `<title>Cortex — Mobile Recon Framework</title>` | `Beetle — Mobile Security Platform` |
| `frontend/src/pages/Results.jsx:1060` | sidebar footer `Cortex v3.3 · Security Analysis` | `Beetle v3.3 · …` |
| `frontend/src/pages/Home.jsx:434` | marketing copy "Cortex turns mobile package analysis…" | `Beetle …` |

**Note:** A logo asset/wordmark may also exist as an image — verify `BrandLogo.jsx` and any SVG/PNG in `frontend/src/` or `frontend/public/` before considering Class 1 complete.

---

## Class 2 — Documentation

Comments, docstrings, module headers. No runtime effect. Bulk-renameable.

Representative locations (not exhaustive):
- `backend/scoring.py:1` — `# Cortex Security Scoring Engine`
- `backend/ai_enrichment.py:13,18` — docstring references to `cortex.db`
- `backend/webhooks.py:11` — schema comment
- `backend/policy.py` — module docstring
- `backend/analyzers/code_rules.py:1` — `# Cortex SAST Rules Engine`
- `backend/analyzers/cve_mapper.py:60` — `# Cache lives next to the main cortex.db`
- `backend/analyzers/__init__.py:1` — `# Cortex Analyzers`
- `frontend/src/lib/auth.js:2` — `Cortex auth utilities` docstring

**Caveat:** Where a comment references a Class-5/6 identifier that is *not yet renamed* (e.g. a docstring mentioning `cortex.db` or `CORTEX_DATA_DIR`), the comment must stay accurate. Do not rename the comment ahead of the identifier it documents.

---

## Class 3 — UI text

User-facing strings beyond the headline brand marks.

| Location | Reference |
|----------|-----------|
| `frontend/src/components/workspace/SectionViews.jsx:2972` | Empty-state copy "Cortex could not identify any known OSS library versions…" |
| `frontend/src/pages/Webhooks.jsx:180` | Field label "Secret (optional — sent as **X-Cortex-Signature** HMAC-SHA256)" |
| `frontend/src/pages/Results.jsx:385–421` | CI/CD snippet generator embedding `CORTEX_TOKEN`, `CORTEX_URL`, "Cortex Security Gate" |

**Critical coupling:** The Webhooks label (line 180) and the Results CI/CD snippet (lines 385–421) are UI text that *describes Class-6 contracts* (`X-Cortex-Signature` header, `CORTEX_*` env var names a customer must set). These strings must change **in lockstep with** the underlying header/env-var rename — not before. If the snippet says `BEETLE_TOKEN` but the API still emits/reads `CORTEX_*`, every copy-pasted pipeline breaks.

---

## Class 4 — Internal implementation

Self-contained code identifiers. Safe to rename together; no external observer depends on them.

| Location | Reference | Notes |
|----------|-----------|-------|
| `backend/database.py:12` | `logging.getLogger("cortex.db")` | Logger name; only matters if log aggregation filters on it |
| `backend/analyzers/cve_mapper.py` | `getLogger("cortex.cve_mapper")` | Same |
| `frontend/tailwind.config.js:11` | `cortex:` color palette namespace | Used as `text-cortex-*` classes throughout JSX — rename is a coordinated find/replace across all components |
| `frontend/package.json:2` | `"name": "cortex-frontend"` | npm package name; internal only |
| `frontend/src/App.jsx:21` | `console.error('Cortex UI error:'…)` | Dev console only |
| `frontend/src/lib/auth.js:38–73` | `cortexServerError`, `cortexNetworkError`, `cortexOriginalError` response tags | Internal JS property names; renaming requires updating consumers in `Home.jsx:171,362`, `Results.jsx:135,362` |
| `backend/main.py:124` | FastAPI `title="Cortex API"` | Appears in OpenAPI docs — borderline Class 1/3; treat as branding for `/docs` |

**Watch item — tailwind namespace:** The `cortex:` palette is referenced as utility classes (`text-cortex-…`, `bg-cortex-…`) across the component tree. A grep for `cortex-` in `frontend/src/**` is required before renaming to catch every usage. This is the largest Class-4 blast radius.

---

## Class 5 — Environment variables (HIGH RISK)

Every `CORTEX_*` key is a **deployment contract**. Renaming them breaks existing `.env` files, `docker-compose` overrides, CI secrets, and any operator runbook. The current `CLAUDE.md` itself documents `CORTEX_ADMIN_PASS` and `CORTEX_DISABLE_LIVE_CHECKS` as required/optional.

**Full inventory:**

| Variable | Read in | Purpose |
|----------|---------|---------|
| `CORTEX_DATA_DIR` | `database.py`, `auth.py`, `audit.py`, `policy.py`, `custom_rules.py`, `webhooks.py`, `cve_mapper.py`, `ai_enrichment.py`, `Dockerfile`, `docker-compose.yml` | SQLite + report dir root |
| `CORTEX_SCAN_DIR` | `decompiler.py`, `scan_storage.py`, `main.py` | Scan extraction root |
| `CORTEX_JWT_SECRET`, `CORTEX_JWT_EXPIRE_HOURS` | `auth.py` | Auth config |
| `CORTEX_ADMIN_PASS`, (admin user) | startup seeding | Initial admin |
| `CORTEX_ALLOW_ANONYMOUS` | `main.py:260` | Auth mode |
| `CORTEX_CORS_ORIGINS` | `main.py:131` | CORS allowlist |
| `CORTEX_MAX_CONCURRENT_SCANS` | `main.py:160` | Queue depth |
| `CORTEX_DISABLE_LIVE_CHECKS` | `live_checks.py:266` | Skip network probes |
| `CORTEX_JADX_MAX_MB`, `CORTEX_JADX_TIMEOUT` | `decompiler.py` | Decompiler limits |
| `CORTEX_SEMGREP_TIMEOUT` | `semgrep_runner.py` | Semgrep limit |
| `CORTEX_SAST_MAX_FILES`, `CORTEX_SAST_MAX_FILE_BYTES` | `code_analyzer.py` | SAST limits |
| `CORTEX_EVIDENCE_MAX_FILES`, `CORTEX_EVIDENCE_MAX_FILE_BYTES` | `evidence_scanner.py` | Evidence limits |
| `CORTEX_PERSIST_MAX_FILES`, `CORTEX_PERSIST_MAX_BYTES`, `CORTEX_PERSIST_MAX_BINARY_BYTES`, `CORTEX_PERSIST_BINARY_READ_BYTES`, `CORTEX_SCAN_TTL` | `scan_storage.py` | Persistence limits |
| `CORTEX_AI_MODEL` | `ai_enrichment.py` | Model override |
| `CORTEX_WEBHOOKS_ALLOW_INTERNAL` | `webhooks.py` | SSRF override |
| `CORTEX_BACKEND_MEM/CPUS`, `CORTEX_FRONTEND_MEM/CPUS` | `docker-compose.yml` | Resource limits |

**Migration pattern (dual-read shim):** Introduce a helper such as:

```python
def env(new_key: str, *legacy_keys: str, default=None):
    if (v := os.environ.get(new_key)) is not None:
        return v
    for k in legacy_keys:
        if (v := os.environ.get(k)) is not None:
            logging.warning("env %s is deprecated; use %s", k, new_key)
            return v
    return default
```

Read `BEETLE_*` first, fall back to `CORTEX_*` with a deprecation warning. Keep the fallback for at least one full release before removing `CORTEX_*`.

---

## Class 6 — Database / storage (CRITICAL RISK)

These references touch **persisted state, issued credentials, signed payloads, or downstream tooling contracts**. A naive rename causes silent data loss or breaks third parties.

### 6a. SQLite filename — `cortex.db`
Referenced in `database.py:30`, `auth.py:51`, `audit.py:31`, `policy.py:35`, `custom_rules.py:36`, `webhooks.py:37`, `cve_mapper.py:62`, `ai_enrichment.py:32`.

- **Risk:** Existing deployments have a populated `cortex.db` in the `cortex-data` Docker volume. Renaming the path to `beetle.db` means a fresh empty DB — **all users, scans, rules, webhooks, audit history vanish**.
- **Strategy:** Keep `cortex.db` on disk indefinitely (it's an internal filename nobody sees), **or** add a one-time startup migration that renames the file if `beetle.db` is absent and `cortex.db` exists. Do **not** flip the constant without the migration.

### 6b. API key prefix — `ck_`
`auth.py:278` generates `ck_{token}`; `auth.py:293,354` use the `ck_` prefix as a lookup hint and auth gate.

- **Risk:** Every issued API key in customers' CI configs starts with `ck_`. Keys are bcrypt-hashed (the prefix is the only routable hint). Changing generation to `bk_` is fine for new keys, but the validator **must accept both** `ck_` and `bk_` or every existing integration 401s.
- **Strategy:** Generate `bk_` for new keys; validator accepts `ck_` OR `bk_`. Never remove `ck_` acceptance unless every legacy key is rotated.

### 6c. HTTP headers
- `X-Cortex-Signature` (`webhooks.py:272`) — webhook consumers verify HMAC against this header name.
- `X-Cortex-Scan-Id` (`main.py:1220`) — response header.

- **Risk:** Webhook receivers have code that reads `X-Cortex-Signature`. Renaming silently breaks their signature verification.
- **Strategy:** **Emit both** `X-Cortex-Signature` and `X-Beetle-Signature` (identical value) for a deprecation window. Document the new header; remove the old one only after consumers migrate.

### 6d. Browser localStorage keys
`cortex_token`, `cortex_user` (`auth.js:5–6`), `cortex-view-mode` (`Results.jsx:767,835`), `cortex_triage:` prefix (`SectionViews.jsx:58,69`).

- **Risk:** Renaming `cortex_token`/`cortex_user` logs out every active user on deploy. Renaming `cortex_triage:` orphans saved triage state.
- **Strategy:** Low stakes but not zero. Either keep the keys (internal) or add a one-time client migration that copies old keys → new keys on first load. Acceptable to accept a single forced re-login if announced.

### 6e. Report / SBOM / SARIF identifiers (downstream tooling contract)
- SARIF `TOOL_NAME = "Cortex Mobile Security Scanner"` (`sarif_exporter.py:23`) and `main.py:778` `"tool": "Cortex"`.
- SBOM vendor/name `"Cortex"`, `"Cortex Mobile Security Scanner"`, `"Cortex Static Analysis"` (`sbom_generator.py:250,252,383,384`).
- PDF titles/footers (`pdf_generator.py:86,247,829`, `compliance_pdf.py:296,644`).
- Downloaded filenames `cortex_<app>_*.pdf/.cdx.json/.sarif.json` (`Results.jsx:135–147,795,818`).

- **Risk:** GitHub Code Scanning and other SARIF consumers **deduplicate and track findings by tool name**. Changing `Cortex Mobile Security Scanner` → `Beetle…` makes every previously-ingested finding appear "fixed" and all current findings "new" — a one-time alert storm. SBOM consumers may key on vendor name.
- **Strategy:** This is a **deliberate, announced** cutover, not a silent rename. Change tool/vendor names in a dedicated release with a changelog note. PDF titles and download filenames are cosmetic (Class-1-like) and can change freely — but the **SARIF tool name and SBOM vendor are a tracked identity** and should change once, intentionally, with consumer notice.

### 6f. User-Agent strings
`Cortex/1.0`, `Cortex-Scanner/1.0` (`domain_analyzer.py:76`, `live_checks.py`, `secret_validator.py`, `osv_scanner.py:281`, `webhooks.py:267`).

- **Risk:** Low. External services don't contract on our UA, though OSV/ip-api logs will show the change. Safe to rename; group with Class 4.

---

## Phased Migration Strategy

### Phase 0 — Freeze & baseline (no code change)
- Adopt this document as the rename contract.
- Add a CI grep guard that **fails the build if a new `CORTEX_*` env var or `X-Cortex-*` header is introduced** without a `BEETLE_*` equivalent — prevents the surface from growing during migration.
- Confirm no logo image assets need redrawing (check `BrandLogo.jsx` + `frontend/public`).

### Phase 1 — Cosmetic rebrand (Classes 1 + 3 display strings + cosmetic Class 6e)
Low risk, high visibility, ships the brand immediately.
- Rename all Class 1 branding strings (logo, login, page title, footer, marketing copy, FastAPI `/docs` title).
- Rename Class 3 empty-state/descriptive UI text **that does not describe a contract**.
- Rename PDF report titles/footers and downloaded filenames (`cortex_*` → `beetle_*`) — cosmetic.
- **Do NOT** touch the Webhooks header label or the CI/CD snippet generator yet (they describe Class-6 contracts still named `CORTEX_*`/`X-Cortex-*`).

### Phase 2 — Internal implementation (Class 4 + Class 2 + Class 6f)
Self-contained, compile-time-verified.
- Rename logger names, the tailwind `cortex:` palette (+ all `text-cortex-*` usages), npm package name, JS internal response-tag properties, `console.error` labels.
- Rename User-Agent strings.
- Update Class-2 comments/docstrings **except** those documenting still-unrenamed Class-5/6 identifiers.
- Verify: `npm run build` + backend import smoke test pass.

### Phase 3 — Environment variables (Class 5) with dual-read shim
- Introduce the `env()` dual-read helper.
- Add `BEETLE_*` as primary, `CORTEX_*` as deprecated fallback (with warning) for **every** variable in the Class 5 table.
- Update `docker-compose.yml`, `Dockerfile`, and `CLAUDE.md` to document `BEETLE_*`.
- Now update the CI/CD snippet generator (`Results.jsx:385–421`) to emit `BEETLE_TOKEN`/`BEETLE_URL` — safe because the backend now accepts both.
- Ship one full release in dual-read mode.

### Phase 4 — Storage & credential contracts (Class 6a–6d) with dual-support
- **6b API keys:** generate `bk_`; validator accepts `ck_` + `bk_`.
- **6c headers:** emit both `X-Cortex-Signature` and `X-Beetle-Signature`; update the Webhooks UI label to describe the new header (mention legacy still sent).
- **6a DB file:** add startup migration `cortex.db` → `beetle.db` (rename-if-absent), or consciously decide to leave the filename as internal and out of scope.
- **6d localStorage:** add first-load key migration or accept one announced forced re-login.

### Phase 5 — Tracked-identity cutover (Class 6e) — announced release
- In a dedicated, changelog-announced release, flip SARIF `TOOL_NAME` and SBOM vendor/name to Beetle.
- Communicate the one-time SARIF finding "churn" to users who ingest into GitHub Code Scanning.

### Phase 6 — Deprecation sunset (next major version)
- Remove `CORTEX_*` env fallback, `ck_` key acceptance (after key rotation), and `X-Cortex-Signature` header.
- Final comment/docstring sweep.
- Migrate the root `*.md` analysis docs and `CLAUDE.md`'s residual legacy identifier references.
- Optionally rename the repo directory `C:\dev\cortex` and the SQLite file if deferred from Phase 4.

---

## Risk Summary

| Phase | Class | Risk | Reversible? | Gate before proceeding |
|-------|-------|------|-------------|------------------------|
| 1 | Branding / UI display | Low | Yes | Visual QA |
| 2 | Internal / docs / UA | Medium | Yes | Build + import smoke test |
| 3 | Env vars | High | Yes (dual-read) | One release in dual mode |
| 4 | DB file, API key, headers, localStorage | Critical | Yes (dual-support) | Existing keys + webhooks verified working |
| 5 | SARIF/SBOM identity | Critical | No (announced) | Changelog + user comms |
| 6 | Sunset legacy | High | No | Confirm zero legacy usage in telemetry |

**The cardinal rule:** anything in Class 5 or 6 gets a dual-support window — never an atomic flip. A consumer (CI pipeline, webhook receiver, SARIF ingester, issued API key) must keep working across at least one release after we introduce the Beetle-named equivalent.

---

## Out of Scope (this document)
- Renaming the working directory `C:\dev\cortex` (operational; defer to Phase 6).
- Renaming Docker volumes `cortex-data` / `cortex-uploads` (renaming a volume orphans its data — treat as Class 6a, leave or migrate explicitly).
- The nine root `*.md` analysis deliverables — they already use "Beetle" for product discussion per the rebrand; their residual "Cortex" references are accurate legacy/code citations and migrate in Phase 6.

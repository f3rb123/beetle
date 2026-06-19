# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

# Project Identity

Public product name: Beetle

Legacy/internal project name: Cortex

When discussing the project, always refer to it as Beetle unless specifically discussing legacy implementation details.

## Development Commands

### Run with Docker (primary workflow)

```bash
# First-time / after code changes
docker compose up --build

# Subsequent runs
docker compose up -d

# View backend logs
docker compose logs -f backend

# Rebuild only backend
docker compose build backend && docker compose up -d backend
```

Frontend is served at `http://localhost:9005`. The backend never exposes a port directly — all traffic routes through nginx.

Required environment variables (set in shell or `.env` before `docker compose up`):
```
SECRET_KEY=<at-least-32-chars>
CORTEX_ADMIN_PASS=<initial-admin-password>
```

Optional:
```
ANTHROPIC_API_KEY=...        # AI enrichment (Claude Haiku)
VIRUSTOTAL_API_KEY=...       # VirusTotal hash lookups
CORTEX_DISABLE_LIVE_CHECKS=1 # Skip Firebase/S3/secret probing
CORTEX_JADX_HEAP=4g          # jadx-only JVM max heap (e.g. 1g/2g/4g/4096m). Unset = jadx default sizing.
                             # Keep below the container mem_limit (6g) to avoid OOM kills (exit 137).
CORTEX_JADX_STATE_DIR=/tmp/jadx  # Writable HOME/XDG base for jadx runtime state (plugin store, cache).
                             # Required under read_only:true (jadx 1.5.0 creates ~/.config/jadx/...).
                             # Defaults to /tmp/jadx (tmpfs); jadx-scoped only, ephemeral by design.
```

### Backend (bare metal)

```bash
cd backend
pip install -r requirements.txt

# Run dev server (reload on change)
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The backend expects JADX at `/opt/jadx/bin/jadx` and apktool at `/usr/local/bin/apktool`. These are installed in the Dockerfile; bare-metal dev without them means Android decompilation silently degrades.

### Frontend (bare metal)

```bash
cd frontend
npm install
npm run dev      # Vite dev server, proxies /api to localhost:8000
npm run build    # Produces dist/ for the nginx container
npm run preview  # Preview the production build locally
```

### No test suite exists

There is currently no test runner, no `tests/` directory, and `pytest` is not in `requirements.txt`. When adding tests, use pytest with a fixture APK/IPA stored under `tests/fixtures/`.

---

## Architecture

### Request path

```
Browser → nginx:9005 → FastAPI (uvicorn:8000) → SQLite /data/cortex.db
                            ↓
                 ThreadPoolExecutor (max 3 concurrent scans)
                            ↓
          android_analyzer.py  OR  ios_analyzer.py  (orchestrators)
                            ↓
                    ~20 sub-analyzers (see below)
```

### The scan pipeline

`main.py` is the single-file controller (1,276 lines). It owns all FastAPI routes, the scan queue (`ThreadPoolExecutor(max_workers=3)`), SSE streaming, and report dispatch. When a file is uploaded, it is saved to `/tmp/cortex/uploads/`, a scan row is inserted (status=`queued`), and a background task is submitted to the executor.

The executor runs either `android_analyzer.analyze()` or `ios_analyzer.analyze()`. These functions call sub-analyzers sequentially and collect results into a single dict. When complete, the dict is serialized and stored in `scans.results_json` — the entire scan output lives in one JSON blob column.

### Sub-analyzer map

| Module | What it does |
|--------|-------------|
| `decompiler.py` | Runs JADX + apktool in parallel; output under `/tmp/cortex/scans/<id>/jadx/` and `apktool/` |
| `evidence_scanner.py` | Secrets (36+ patterns), IPs, JWTs across all decompiled files |
| `code_analyzer.py` + `code_rules.py` | Regex SAST against `CODE_RULES` (Android) or `IOS_CODE_RULES` (iOS) + any enabled custom rules |
| `taint_analyzer.py` | Androguard DEX call-graph BFS, 17 sources → 27 sinks, 60 s timeout |
| `chain_analyzer.py` | Attack chain synthesis from co-occurring findings (6 chain detectors) |
| `elf_analyzer.py` | Pure-Python ELF hardening (PIE, NX, canary, RELRO, FORTIFY) — no LIEF needed |
| `lief_analyzer.py` | Deep Mach-O analysis + instrumentation dylib detection (Frida, Frida Gadget, Substrate) via LIEF |
| `cert_analyzer.py` | APK v1–v4 signing scheme detection, Janus risk, debug cert, RSA key size |
| `cve_mapper.py` | Version strings in binary → OSV.dev CVE lookup; CISA KEV integration |
| `osv_scanner.py` | Dependency file parsing (build.gradle, pom.xml, package.json, pubspec.yaml) → OSV batch API |
| `secret_validator.py` | Live API probing for 13 key types (GitHub, Stripe, Slack, OpenAI, etc.) |
| `virustotal.py` | SHA-256 hash lookups via VT v3 API |
| `domain_analyzer.py` | DNS resolution + ip-api.com geo + OFAC check; 30-domain cap |
| `semgrep_runner.py` | Semgrep CLI wrapper (p/android, p/java, p/kotlin); degrades silently if binary not in PATH |
| `js_bundle_analyzer.py` | RN/Cordova JS bundle secrets and dangerous API patterns |
| `tracker_db.py` | 55+ third-party SDK signatures (analytics, ads, crash, payments, social) |
| `live_checks.py` | Firebase DB probe, S3 bucket listing, AssetLinks.json validation, file inventory |
| `scan_storage.py` | Owns `/tmp/cortex/scans/<scan_id>/` directory lifecycle and the source-file resolver |
| `ai_enrichment.py` | Claude Haiku enrichment per finding; 7-day SQLite cache keyed on content hash |

### Database

Single SQLite file at `/data/cortex.db` in WAL mode. Schema is initialized by `database.py`; two modules self-manage additional tables outside the main schema:
- `ai_enrichment.py` creates `ai_enrichment_cache`
- `cve_mapper.py` creates `cve_cache`

There is no ORM and no migration framework — schema changes go directly into `database.py`'s init block as `CREATE TABLE IF NOT EXISTS` / `ALTER TABLE` calls.

All scan findings are stored as a blob in `scans.results_json`. There is no normalized findings table.

### Authentication

`auth.py` handles JWT (HS256, 24 h) and bcrypt password hashing. API keys use the prefix `ck_` and are bcrypt-hashed in `users.api_key_hash`. Role enforcement uses two FastAPI dependencies injected per route: `get_current_user()` (any authenticated user) and `get_admin_user()` (admin only).

The JWT is currently stored in `localStorage` on the frontend (`frontend/src/lib/auth.js`). The `apiFetch()` wrapper in `auth.js` injects the `Authorization: Bearer` header and handles 401 redirects automatically.

### Frontend section model

The workspace (`/scans/:scanId/:sectionId`) is driven by `frontend/src/lib/scan-data.js`, which defines all ~30 section IDs grouped into: Overview, Evidence, Attack Surface, Hardening, Intelligence, Data Flow, and iOS Deep Analysis. `SectionViews.jsx` renders the appropriate component for each `sectionId`. Adding a new backend result field requires: a new section entry in `SECTION_GROUPS`, a new case in `SectionViews.jsx`, and a new API field in the `results_json` dict.

### Adding a new analyzer

1. Create `backend/analyzers/my_analyzer.py` with a function that takes `(tmpdir, results)` and mutates `results`.
2. Call it from `android_analyzer.analyze()` or `ios_analyzer.analyze()` at the appropriate point in the pipeline.
3. Add a new section to `SECTION_GROUPS` in `scan-data.js` and a renderer in `SectionViews.jsx`.
4. The results dict key you add will be serialized into `results_json` automatically.

### Custom SAST rules

Admin-managed rules live in the `custom_rules` SQLite table. `custom_rules.py` returns them formatted identically to `CODE_RULES` entries with `"source": "CUSTOM_RULE"`. They are merged into the rule list at scan time in `code_analyzer.py` — no restart required.

### Scan file storage layout

```
/tmp/cortex/scans/<scan_id>/
  jadx/         JADX decompiled Java source
  apktool/      smali + resources
  apk_extract/  raw APK zip contents
  ipa_extract/  raw IPA zip contents
```

`scan_storage.resolve_source_file()` searches these subdirs in order to resolve a finding's `file_path` for the source viewer. Files older than `CORTEX_SCAN_TTL` (default 24 h) are cleaned up.

# Beetle — Project Overview

**Applies to:** Beetle v1.2.0  
**Type:** Mobile Application Security Testing (MAST) platform  
**Targets:** Android APKs, iOS IPAs  
**Deployment:** Self-hosted via Docker Compose  
**External port:** 9005 (configurable)  

---

## What Beetle Does

Beetle is a self-contained web application that accepts mobile app binaries (`.apk` / `.ipa`) and produces structured security analysis. A user uploads a file, a backend scan pipeline processes it across ~20 specialized sub-analyzers, and the results are stored in SQLite. The frontend presents findings across ~30 categorized sections covering static analysis, binary hardening, supply chain CVEs, secret detection, network security, compliance mapping, and attack chain synthesis.

The system is designed for security analysts and penetration testers who need a reproducible, auditable toolchain for mobile app assessments without depending on cloud services (except for optional live-check integrations).

---

## Core Capabilities

### Static Analysis
- SAST via regex rules (100+ built-in `CODE_RULES` + `IOS_CODE_RULES`, plus admin-defined custom rules)
- Secrets detection (36+ patterns covering AWS, GCP, Stripe, Slack, GitHub, JWT, PEM, Firebase, etc.)
- Manifest / entitlement analysis (permissions, exported components, intent filters, deep links)
- Network Security Config parsing (NSC XML: cleartext, user CA trust, pinning, debug overrides)
- JS bundle analysis for React Native / Cordova apps
- String-category analysis (28 categories: weak crypto, SQLite, reflection, clipboard, etc.)

### Binary Analysis
- ELF hardening (PIE, NX, stack canary, RELRO, RPATH, FORTIFY, stripped — pure Python, no LIEF dependency)
- Mach-O hardening (PIE, NX, stack canary, ARC, FairPlay encryption, stripped — pure Python struct)
- Deep LIEF analysis for Mach-O (FAT slices, instrumentation dylib detection: Frida, Substrate, Objection)
- APK certificate analysis (v1/v2/v3/v4 scheme detection, SHA-1, debug cert, Janus risk, key size)
- APKiD-style detection without APKiD (Anti-VM, Anti-Debug, Obfuscation, Packer from DEX strings)

### Supply Chain & CVEs
- OSV.dev dependency scanning (build.gradle, pom.xml, package.json, pubspec.yaml, libs.versions.toml)
- Native binary CVE mapping via version-string + symbol extraction (24 OSS libraries: OpenSSL, libcurl, zlib, etc.)
- CISA KEV integration — bumps severity for known-exploited CVEs
- Maven AAR scanning (META-INF/maven pom.properties)
- CocoaPods framework scanning (Frameworks/*.framework Info.plist)
- 55+ third-party tracker signatures (analytics, ads, attribution, crash reporting, payments, social)

### Live Checks (network-required)
- Firebase Realtime Database probe (unauthenticated access: critical if confirmed open)
- S3 bucket public listing check (ListObjectsV2)
- AssetLinks.json validation for deep-link security
- Secret validator — live API probing for 13 key types (GitHub, Stripe, OpenAI, Slack, etc.)
- VirusTotal hash lookup (main APK + up to 5 DEX files; requires `VIRUSTOTAL_API_KEY`)
- Domain geo/intel via ip-api.com (DNS, country, OFAC sanctions, suspicious TLDs, dynamic DNS)

### Intelligence & Enrichment
- Inter-procedural taint analysis (androguard DEX call graph, BFS, 17 sources → 27 sinks)
- Attack chain synthesis (6 chained attack detectors: WebView RCE, Debug/Backup exfil, Permission leak, Intent injection, Crypto failure, Firebase exposure)
- Pentest playbook generation (up to 10 concrete steps per scan)
- AI enrichment via Claude Haiku — contextual findings explanations with 7-day cache
- IP extraction and geolocation

### Reporting
- PDF reports (ReportLab, A4, light/dark themes): executive + technical
- Compliance PDF (MASVS v2, PCI-DSS v4.0, OWASP Mobile Top 10)
- CycloneDX 1.5 SBOM export (JSON)
- SARIF 2.1.0 export (GitHub Code Scanning compatible)
- JSON export (raw results)
- Scan comparison (diff against a previous scan)

### Platform Features
- JWT authentication (HS256, 24-hour tokens); admin auto-created from env vars on first run
- API key auth (`ck_` prefix, bcrypt-hashed, admin-provisioned)
- Role-based access: `admin` (full access) vs `analyst` (scan + read only)
- Server-Sent Events for real-time scan progress (400ms poll, 5s heartbeat, 6-minute cap)
- Webhook notifications with HMAC-SHA256 signatures and SSRF / DNS-rebinding defense
- Custom SAST rules (admin-managed, stored in SQLite, merged at scan time)
- CI/CD policy gate (`/api/scans/{id}/policy`) — configurable thresholds per severity level
- Source file browser with code viewer (jadx/apktool/apk-extract output)
- Audit log (all privileged actions, 500-entry API view)
- Scan TTL-based cleanup (24-hour default for extracted source files)
- Semgrep integration (p/android, p/java, p/kotlin rulesets)

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend language | Python 3.11 |
| API framework | FastAPI 0.111.0 + uvicorn 0.29.0 |
| Database | SQLite (WAL mode) at `/data/cortex.db` |
| Android decompilation | JADX v1.5.0, apktool 2.9.3, androguard 4.1.3 |
| iOS analysis | plistlib, struct (Mach-O), LIEF ≥0.14 |
| Binary analysis | LIEF ≥0.14.0 (optional, degrades gracefully) |
| SAST | Built-in regex rules + optional Semgrep ≥1.70.0 |
| PDF generation | ReportLab 4.1.0 |
| HTTP client | httpx 0.27.0 |
| Auth | python-jose[cryptography] 3.3.0 (JWT), passlib[bcrypt] 1.7.4 |
| AI enrichment | Anthropic SDK ≥0.40.0 (claude-haiku-4-5-20251001) |
| Frontend framework | React 18.3.1 |
| Frontend build | Vite 5.2.12 |
| Frontend styling | Tailwind CSS 3.4.4 |
| Charts | Recharts 2.12.7 |
| Reverse proxy | Nginx (alpine) |
| Container orchestration | Docker Compose |

---

## Deployment Model

```
Browser → Nginx (port 9005) → FastAPI backend (port 9005, internal)
                                       ↓
                               SQLite /data/cortex.db     (named volume: cortex-data)
                               /tmp/cortex/uploads        (tmpfs 2GB)
                               /tmp/cortex/scans          (tmpfs 2GB)
                               /data/reports              (named volume: cortex-uploads)
```

The backend runs read-only (`read_only: true`) with all caps dropped (`cap_drop: ALL`) and a 2GB tmpfs for uploads and scan artifacts. No network ports are exposed from the backend container directly — all traffic routes through Nginx. Resource limits: backend 6GB RAM / 4 CPUs, frontend 256MB RAM / 1 CPU.

---

## User Roles

| Role | Capabilities |
|------|-------------|
| `admin` | All analyst capabilities + user management, API key creation, webhook management, custom rule management, audit log access |
| `analyst` | Upload files, run scans, view all scan results, download reports, view scan comparison |

The first admin account is created automatically on startup from `CORTEX_ADMIN_USER` / `CORTEX_ADMIN_PASS` environment variables. Anonymous access is not supported — every request requires a JWT or API key.

---

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `SECRET_KEY` | JWT signing key | Required |
| `CORTEX_ADMIN_USER` | Initial admin username | `admin` |
| `CORTEX_ADMIN_PASS` | Initial admin password | Required |
| `ANTHROPIC_API_KEY` | AI enrichment (optional) | — |
| `VIRUSTOTAL_API_KEY` | VirusTotal lookups (optional) | — |
| `CORTEX_DISABLE_LIVE_CHECKS` | Skip Firebase/S3 network probes | `0` |
| `CORTEX_SEMGREP_TIMEOUT` | Semgrep per-scan timeout | `90s` |
| `CORTEX_JADX_MAX_MB` | Skip JADX on APKs larger than N MB | `1000` |
| `CORTEX_SCAN_TTL` | Source file retention time | `86400s` (24h) |
| `CORTEX_DATA_DIR` | SQLite database directory | `/data` |
| `CORTEX_SCAN_DIR` | Scan extraction root | `/tmp/cortex/scans` |

---

## Confidence in this Overview

**High.** Every source file in the repository was read across two sessions. Version numbers come from Dockerfile pinned dependencies and SARIF exporter metadata. Role capabilities were inferred from route-level auth decorators in `main.py` and `auth.py`. Environment variables were verified against their point-of-use in each module.

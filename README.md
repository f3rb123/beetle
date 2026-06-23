# Beetle

**Mobile Static Security Workspace**

Beetle is an offline-first mobile application security platform. Drop in an APK or
IPA and Beetle decompiles it, runs ~20 static analyzers, and presents the result
as an *explainable* security workspace — every finding traced to a real
file·line, mapped to MASVS/OWASP, and explained the way an analyst would.

No cloud upload. No telemetry. The package never leaves your machine.

---

## Features

- **Static analysis** — regex SAST, taint analysis, and structural checks across decompiled Java/Kotlin, smali, resources, and native binaries
- **MASVS mapping** — findings aligned to the OWASP Mobile Application Security Verification Standard
- **Attack chains** — co-occurring weaknesses synthesized into concrete, end-to-end exploit narratives
- **Source-level evidence** — every finding resolves to a real file and line with a code snippet; no fabricated locations
- **Multi-evidence navigation** — step through every location a finding touches with Prev/Next, auto-scroll, and line highlight
- **Secrets intelligence** — 36+ credential patterns with masking, entropy gating, and live key validation
- **Permission intelligence** — each declared permission resolved to where it is actually referenced in source (or the manifest line that declares it)
- **Certificate intelligence** — per-issue analysis (debug cert, weak signature, small RSA key, Janus/v1, expiry) with attack scenario, impact, and developer fix
- **API inventory** — categorized Android/iOS platform API usage with evidence
- **Manifest analysis** — exported components, deep links, security posture, and cleartext configuration
- **AI explanations** — optional, provider-agnostic LLM enrichment; fully functional offline using deterministic analyst intelligence

---

## Architecture

```
Frontend (React / Vite)
        │
      Nginx          ← serves the SPA, reverse-proxies /api
        │
     FastAPI         ← routes, auth, scan queue (ThreadPoolExecutor)
        │
    Analyzers        ← ~20 sub-analyzers (orchestrated per platform)
        │
  JADX / apktool     ← decompilation + resource decoding
        │
     Results         ← single JSON blob per scan, persisted in SQLite
```

The backend is a single FastAPI service. Uploaded packages are decompiled into a
per-scan workspace, analyzed sequentially, and serialized to a SQLite database.
The frontend is a static SPA served by nginx, which also proxies API traffic — the
backend is never exposed directly.

---

## Screenshots

_Placeholder — screenshots to be added._

---

## Quick Start

```bash
docker compose up -d
```

Then open **http://localhost:9005**.

Set these before first run (shell or `.env`):

```
SECRET_KEY=<at-least-32-chars>
CORTEX_ADMIN_PASS=<initial-admin-password>
```

On first run an `admin` account is created and its credentials are printed to the
backend logs (`docker compose logs backend`).

Optional integrations:

```
ANTHROPIC_API_KEY=...        # AI enrichment
VIRUSTOTAL_API_KEY=...       # VirusTotal hash lookups
```

---

## Supported Formats

| Format | Platform | Tooling |
|--------|----------|---------|
| **APK** | Android  | JADX + apktool |
| **IPA** | iOS      | Mach-O / plist analysis |

---

## Philosophy

> _"See the app the way an attacker does."_

A scanner that only lists findings forces the analyst to rebuild context by hand.
Beetle does the opposite: it shows the evidence, the chain, and the impact, so the
question is never *"is this real?"* but *"how bad is it, and how do I fix it?"*

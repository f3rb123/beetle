# Beetle

### Attack-Chain Driven Mobile Security Workspace

Beetle is an offline-first mobile application security platform. Drop in an
Android **APK** or iOS **IPA** and Beetle decompiles it, runs ~20 static
analyzers, and presents the result as an *explainable* security workspace — every
finding traced to a real file·line, mapped to MASVS/OWASP, and synthesized into
concrete attack chains the way an analyst would.

**No cloud upload. No telemetry. The package never leaves your machine.**

---

## Features

- **Android APK support** — JADX + apktool decompilation, smali, resources, and native ELF analysis
- **iOS IPA support** — Mach-O, plist, and embedded framework analysis
- **Attack Chain Intelligence** — co-occurring weaknesses synthesized into end-to-end exploit narratives
- **MASVS posture scoring** — findings aligned to the OWASP Mobile Application Security Verification Standard
- **Secrets detection** — 36+ credential patterns with masking, entropy gating, and live key validation
- **AI-assisted triage** — optional, provider-agnostic LLM enrichment; fully functional offline via deterministic analyst intelligence
- **Evidence-driven findings** — every finding resolves to a real file and line with a code snippet; no fabricated locations
- **View Code navigation** — jump from any finding to the decompiled source, step through every location it touches
- **PDF export** — technical and compliance (MASVS / PCI-DSS / OWASP Mobile) reports

---

## Screenshots

> _Screenshots coming soon._

<!-- Drop images into docs/screenshots/ and uncomment:
![Overview](docs/screenshots/overview.png)
![Findings & Evidence](docs/screenshots/findings.png)
![Attack Chains](docs/screenshots/attack-chains.png)
![View Code](docs/screenshots/view-code.png)
-->

| View | Description |
|------|-------------|
| Overview | Security score, trust score, risk summary, top risks |
| Findings | Evidence-driven findings with severity and source location |
| Attack Chains | Synthesized end-to-end exploit narratives |
| View Code | Finding-to-source navigation over decompiled output |

---

## Quick Start

```bash
git clone https://github.com/f3rb123/beetle.git
cd beetle
docker compose up -d
```

Then open **http://localhost:9005**.

Set these before first run (shell or `.env`):

```
SECRET_KEY=<at-least-32-chars>
CORTEX_ADMIN_PASS=<initial-admin-password>
```

On first run an `admin` account is created. The backend startup banner
(`docker compose logs backend`) confirms the access URL.

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

See [`ARCHITECTURE.md`](ARCHITECTURE.md), [`PROJECT_OVERVIEW.md`](PROJECT_OVERVIEW.md),
and [`FEATURE_INVENTORY.md`](FEATURE_INVENTORY.md) for detail.

---

## Philosophy

> _"See the app the way an attacker does."_

A scanner that only lists findings forces the analyst to rebuild context by hand.
Beetle does the opposite: it shows the evidence, the chain, and the impact, so the
question is never *"is this real?"* but *"how bad is it, and how do I fix it?"*

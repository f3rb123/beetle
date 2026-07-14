<p align="center">
  <img src="docs/screenshots/beetle-banner.png" width="100%" alt="Beetle — Attack-Chain Driven Mobile Application Security Platform">
</p>

<p align="center">
  <a href="https://github.com/f3rb123/beetle/releases"><img src="https://img.shields.io/github/v/tag/f3rb123/beetle?label=release&sort=semver&color=2ea44f" alt="Latest Release"></a>
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-backend-009688?logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/React-frontend-61DAFB?logo=react&logoColor=black" alt="React">
  <img src="https://img.shields.io/badge/Docker-native-2496ED?logo=docker&logoColor=white" alt="Docker">
  <br>
  <img src="https://img.shields.io/badge/Android-APK-3DDC84?logo=android&logoColor=white" alt="Android">
  <img src="https://img.shields.io/badge/iOS-IPA-000000?logo=apple&logoColor=white" alt="iOS">
  <img src="https://img.shields.io/badge/OWASP-MASVS-1B1F23?logo=owasp&logoColor=white" alt="OWASP MASVS">
  <img src="https://img.shields.io/badge/Export-SARIF-orange" alt="SARIF">
  <img src="https://img.shields.io/badge/SBOM-CycloneDX-darkred" alt="CycloneDX SBOM">
  <img src="https://img.shields.io/badge/License-Apache_2.0-blue" alt="License Apache 2.0">
  <img src="https://img.shields.io/badge/docs-available-blue" alt="Documentation Available">
  <img src="https://img.shields.io/badge/contributions-welcome-brightgreen" alt="Contributions Welcome">
</p>

<h1 align="center">🪲 Beetle</h1>

<p align="center"><strong>Attack-Chain Driven Mobile Application Security Platform</strong></p>

<p align="center">
Android • iOS • Flutter • React Native • OWASP MASVS • Attack Chains • Source Navigation • SARIF • CycloneDX SBOM • Optional AI • Docker
</p>

---

## Overview

**Beetle** is an offline-first **Application Security Intelligence Platform** for analyzing Android APKs and iOS IPAs, including apps built with **Flutter** and **React Native**.

It is built for **penetration testers, mobile security engineers, developers, security researchers, and auditors**, and brings together static analysis, explainable security intelligence, attack chains, source navigation, evidence-driven findings, professional reporting, and optional AI assistance in a single analyst workspace.

> Unlike traditional static analyzers that primarily enumerate findings, Beetle builds an explainable investigation workflow by combining evidence, ownership, confidence, finding fusion, attack chains, source navigation and optional AI assistance into a single analyst experience.

Beetle is **offline-first**: all analysis runs locally on your own infrastructure, and application binaries and source code are never uploaded to external services. The deterministic intelligence engines require no network and no AI provider to run a complete scan.

---

## Why Beetle?

A modern mobile application can produce hundreds of security findings. Beetle is designed around the analyst workflow — helping you decide *what is vulnerable, why it matters, and how an attacker could combine weaknesses* — rather than handing you an undifferentiated list.

* **Explainable findings** — every score and verdict ships with a human-readable reason
* **Evidence before assumptions** — findings are grounded in concrete artifacts (code, manifest, certificates, binaries)
* **Low false-positive rate** — ownership, confidence, and evidence gating are designed to suppress noise, not inflate a count
* **Attack Chains** — isolated findings are correlated into realistic, evidence-backed attack paths
* **Source Navigation** — every finding links directly to its exact file and line
* **Standards Mapping** — OWASP MASVS coverage and OWASP Mobile Top 10 alignment
* **Offline-first** — complete analysis with no network and no AI provider required
* **Optional AI** — explain findings, reason about evidence, and answer security questions in context
* **Professional Reporting** — executive, technical, and compliance reports plus machine-readable exports

---

## Core Capabilities

* **Static Analysis** — Android APK + iOS IPA decompilation, manifest/plist, certificates, entitlements, and native binaries
* **Explainable Intelligence Engines** — Ownership, Confidence, Evidence Selection, Finding Fusion, Secret Intelligence, and more — each adds metadata without ever deleting a finding
* **Attack Chains** — correlate findings into realistic, evidence-backed attack paths
* **Source Navigation** — jump from any finding to its exact source location with a rich code viewer
* **Standards Mapping** — OWASP MASVS coverage and OWASP Mobile Top 10
* **AI Security (optional)** — an AI Assistant and AI Actions that augment, but never replace, deterministic analysis ([details below](#ai-security-optional))
* **Reporting & Integrations** — PDF, SARIF, CycloneDX SBOM, JSON, webhooks, and CI/CD policy gating

---

## AI Security (Optional)

Beetle performs **all security analysis locally** using deterministic intelligence engines. AI is a completely **optional** layer on top of that analysis.

> **AI does not scan applications. AI does not discover vulnerabilities.** It reasons only over Beetle's own findings and evidence, and it augments the analyst workflow.

The design philosophy is deliberate: detection and scoring must be deterministic, reproducible, and explainable, so they are never delegated to a model. AI is positioned strictly as an interpretation aid that helps analysts move faster through results that Beetle has already produced.

AI helps:

* **Explain findings** in plain language, including why they matter
* **Explain evidence** behind a finding
* **Answer security questions** about findings, controls, and attack scenarios
* **Suggest remediation** grounded in the finding's evidence
* **Generate executive summaries** from Beetle's findings and rollups
* **Assist investigations** across multiple findings or an attack path

If an AI provider is **not** configured:

* Beetle still performs **complete security analysis**.
* Investigation, reporting, and all deterministic intelligence engines continue working normally.
* Only AI-enhanced features require an AI provider.

**Supported providers:**

* Claude
* OpenAI
* Gemini
* DeepSeek
* Ollama (local / fully on-premises)

AI features require a configured provider — they are not available until one is set up.

---

## Features

### Mobile Security Intelligence

* Android Security Intelligence
* iOS Security Intelligence
* Flutter Security Intelligence
* React Native Security Intelligence

### Detection & Analysis

* Android static analysis & APK / IPA decompilation with shared source indexing
* Secret & credential detection
* Endpoint & URL extraction
* Taint analysis (source-to-sink data-flow)
* Certificate & code-signing analysis
* Native binary hardening analysis (NX, PIE, RELRO, stack canary)
* CVE enrichment for native libraries and dependencies
* Domain intelligence
* API behavior analysis
* Attack Chain analysis
* OWASP MASVS mapping

### Intelligence Engines

* Secret Intelligence v2
* Network Intelligence
* Cloud Configuration Intelligence
* APKLeaks Integration
* Semgrep Intelligence
* Ownership Engine
* Confidence Engine
* Evidence Selection Engine
* Finding Fusion Engine
* Attack Chain Intelligence
* MASVS Intelligence

### Investigation Workspace

* Engineering Workspace
* Investigation Dashboard
* Source Explorer
* Security Explorer
* Rich Code Viewer
* Source Resolution
* Trust Score
* Security Score
* AI Assistant
* AI Actions

### Reports & Export

* Executive PDF
* Technical PDF
* Compliance Reports
* SARIF Export
* CycloneDX SBOM
* JSON Export

---

## Screenshots

### Engineering Workspace

The home workspace — your entry point for scan targets, recent activity, and investigations.

![Engineering Workspace](docs/screenshots/home-engineering-workspace.png)

### Scan Overview

A high-level overview of a scanned application: scores, finding rollups, and platform intelligence at a glance.

![Scan Overview](docs/screenshots/Overview-screen.png)

### Security Findings

The findings view — evidence-driven, confidence-scored, and mapped to standards.

![Security Findings](docs/screenshots/findings-latest.png)

### Open Finding

An individual finding with its evidence, ownership, confidence, and remediation context.

![Open Finding](docs/screenshots/open-finding.png)

### Source Navigation

Jump from any finding to its exact file and line in the rich code viewer.

![View Code](docs/screenshots/view-code.png)

### Source Explorer

Browse the full decompiled and resolved source tree of the application.

![Source Explorer](docs/screenshots/source-explorer.png)

### MASVS Coverage

OWASP MASVS coverage mapping across the analyzed application.

![MASVS Coverage](docs/screenshots/masvs-coverage.png)

### AI Analysis

Optional, evidence-grounded AI analysis that explains findings and attack paths.

![AI Analysis](docs/screenshots/Ai-Analysis.png)

### AI Assistant

Conversational, context-aware security Q&A over your scan results.

![AI Assistant](docs/screenshots/Ai%20Assistant.png)

---

## Architecture

Beetle ingests a scan target, registers it, runs the appropriate platform analyzer and detection engines to emit canonical findings, then enriches those findings through a chain of explainable intelligence engines before correlating them into attack chains and rendering them into reports and the investigation dashboard.

```mermaid
flowchart TD
    A[Scan Target] --> B[Scan Target Registry]
    B --> C[Platform Analyzer]
    C --> D[Intelligence Engines]
    D --> E[Canonical Findings]
    E --> F[Ownership]
    F --> G[Confidence]
    G --> H[Evidence Selection]
    H --> I[Finding Fusion]
    I --> J[Attack Chains]
    J --> K[Reports]
    J --> L[Investigation Dashboard]
```

---

## Validation

Beetle's detection is exercised against **known-vulnerable reference applications** — deliberately insecure test apps with documented, ground-truth weaknesses — with an explicit focus on **evidence-backed findings and a low false-positive rate**.

The guiding principle across the detection engines is that a finding must map to real, attributable code:

* **Ownership gating** — library and framework code is separated from application code, so third-party SDK behavior is not reported as an application weakness.
* **Reachability honesty** — data-flow findings distinguish *proven* data-flow from *method-reachable* co-occurrence, and severity/confidence are labeled accordingly rather than overstated.
* **Evidence grounding** — every finding resolves to a concrete artifact (a source line, a manifest entry, a certificate, or a binary), and correlated attack chains are built from that evidence rather than from keyword coincidence.

The goal is a report an analyst can trust finding-by-finding, where each verdict can be traced back to the exact code or artifact that produced it.

---

## Documentation

Beetle includes comprehensive technical documentation. The **Beetle Bible** is the single authoritative reference — it documents what every feature does, why it exists, how it works internally, and how an analyst should interpret its output.

* **[Beetle Bible](docs/beetle-bible/README.md)** — complete technical reference (architecture, engines, scoring, reports, FAQ, glossary)
* **[Architecture Guide](ARCHITECTURE.md)** — system architecture and pipeline
* **[Feature Inventory](FEATURE_INVENTORY.md)** — full inventory of implemented capabilities
* **[Project Overview](PROJECT_OVERVIEW.md)** — high-level project orientation

---

## Quick Start

### Clone the repository

```bash
git clone https://github.com/f3rb123/beetle.git
cd beetle
```

### Configure Beetle (optional)

Beetle runs out of the box — no configuration is required to start scanning. A fresh installation ships with default **development** administrator credentials:

| Username | Password |
| -------- | -------- |
| `beetle` | `beetle` |

To use your own credentials, override them (in `docker-compose.yml` or the environment) **before the first startup**:

```env
CORTEX_ADMIN_USERNAME=beetle
CORTEX_ADMIN_PASSWORD=beetle
```

* Bootstrap credentials are applied **only when no administrator account exists** — existing accounts are **never overwritten** and passwords are never reset.
* The login page displays these defaults only on a fresh installation and hides them automatically once the password is changed.

> ⚠️ **Production deployments must override these defaults** with strong credentials before first startup, or change the password immediately after the first login. The `beetle` / `beetle` defaults are intended for local development only.

Optional integrations (AI providers and threat intelligence) can be enabled with additional variables:

```env
ANTHROPIC_API_KEY=...
OPENAI_API_KEY=...
GEMINI_API_KEY=...
DEEPSEEK_API_KEY=...
VIRUSTOTAL_API_KEY=...
```

> The JWT signing secret is generated and persisted automatically on first run; set `CORTEX_JWT_SECRET` if you want to supply your own.

### Build the containers

```bash
docker compose build
```

### Start Beetle

```bash
docker compose up
```

Once the backend reports that it has started successfully, open:

```
http://localhost:9005
```

Sign in with the default administrator credentials:

| Username | Password |
| -------- | -------- |
| `beetle` | `beetle` |

The login page shows these default credentials on a fresh installation and hides them automatically once the password is changed. Change the password after your first login, and override the defaults for production deployments.

Stop Beetle at any time with `Ctrl + C`.

### Scan Performance

Beetle's shared source-analysis architecture reads and indexes the decompiled application **once** and reuses it across every detection and intelligence engine. A typical scan completes in seconds to a few minutes.

Actual duration depends on the application size and resource complexity, and on host resources (CPU, available RAM, and storage performance).

---

## Troubleshooting

### Can't sign in / resetting the administrator account

The administrator account is created **only on first initialization**. If the database already contains an administrator, the bootstrap credentials are ignored and existing accounts are never modified — so changing `CORTEX_ADMIN_USERNAME` / `CORTEX_ADMIN_PASSWORD` on an existing installation has no effect.

To reset Beetle to a clean state (this recreates the default `beetle` / `beetle` administrator):

```bash
docker compose down -v
docker compose up
```

> ⚠️ **`docker compose down -v` is destructive.** It removes:
>
> * Local database
> * Uploaded scans
> * Reports
> * Docker volumes
> * Persisted local data
>
> Use it only when you intentionally want to reset Beetle to a clean state.

---

## Supported Formats

| Platform     | Supported |
| ------------ | --------- |
| Android      | APK       |
| iOS          | IPA       |
| Flutter      | APK / IPA |
| React Native | APK / IPA |

---

## Current Capabilities

* Android, iOS, Flutter & React Native Security Intelligence
* APK / IPA Decompilation & Shared Source Indexing
* Secret Intelligence v2 & Endpoint Extraction
* Taint Analysis (source-to-sink data-flow)
* Certificate & Code-Signing Analysis
* Native Binary Hardening Analysis
* CVE Enrichment (native libraries & dependencies)
* Network Intelligence & Domain Intelligence
* Cloud Configuration Intelligence
* API Behavior Analysis
* APKLeaks Integration
* Semgrep Intelligence
* Ownership Engine
* Confidence Engine
* Evidence Selection Engine
* Finding Fusion Engine
* Attack Chain Intelligence
* MASVS Intelligence & OWASP Mobile Top 10 Mapping
* Engineering Workspace & Investigation Dashboard
* Source Explorer & Security Explorer
* Rich Code Viewer & Source Resolution
* Trust Score & Security Score
* AI Assistant & AI Actions (optional)
* Scan Target Architecture
* Executive, Technical & Compliance Reports
* SARIF Export, CycloneDX SBOM & JSON Export

---

## Roadmap

The following capabilities are planned for future releases:

* Infrastructure-as-Code Intelligence
* Dynamic Security Intelligence
* Cloud Security Intelligence
* Enterprise Dashboard
* Team Collaboration
* Plugin SDK

---

## Design Principles

* Offline-first architecture
* Evidence before assumptions
* Explainable findings
* Analyst-focused workflow
* Standards-based security analysis
* Docker-native deployment
* Extensible architecture

---

## Contributing

Bug reports, feature requests, documentation improvements, and pull requests are welcome.

Please open an issue before submitting large feature changes so the implementation can be discussed first.

---

## License

Beetle is released under the **Apache License 2.0**. See [LICENSE](LICENSE) for the full text.

---

## Acknowledgements

Beetle builds upon and benefits from the open-source mobile security ecosystem, including projects such as:

* JADX
* apktool
* LIEF
* Semgrep
* APKLeaks
* MobSF (Mobile Security Framework) — a reference point for mobile SAST capabilities and detection benchmarking
* Exodus Privacy — tracker signature data
* OWASP Mobile Application Security Verification Standard (MASVS)
* OWASP Mobile Security Testing Guide (MSTG)

Their work has significantly advanced mobile application security and made tools like Beetle possible.
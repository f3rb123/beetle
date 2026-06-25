# 🪲 Beetle

# Attack-Chain Driven Mobile Application Security Platform

<p align="center">
  <img src="docs/screenshots/home.png" width="1000">
</p>

<p align="center">

**Android • iOS • MASVS • AI-Assisted Analysis • Attack Chains • SARIF • CycloneDX SBOM • Docker**

</p>

---

## Overview

Beetle is an offline-first mobile application security platform designed to help security engineers, penetration testers, developers, and auditors analyze Android APKs and iOS IPAs.

Rather than presenting isolated findings, Beetle correlates weaknesses into realistic attack paths, links every finding to source evidence, and provides explainable security analysis.

Applications are analyzed entirely on your own infrastructure. No application binaries or source code are uploaded to external services.

---

## Why Beetle?

Modern mobile assessments generate hundreds of findings.

Beetle focuses on helping analysts answer three questions:

* What is vulnerable?
* Why does it matter?
* How can an attacker combine these weaknesses?

Instead of only listing issues, Beetle provides:

* Evidence-driven findings
* Attack chain generation
* Source-code navigation
* AI-assisted security explanations
* Standards mapping
* Professional reporting

---

# Features

### Android Static Analysis

* APK decompilation
* JADX integration
* apktool integration
* Manifest analysis
* Smali analysis
* Resource analysis
* Native library inspection

### iOS Static Analysis

* IPA extraction
* Mach-O analysis
* Framework analysis
* Info.plist analysis
* Entitlements inspection
* Binary security checks

### Security Analysis

* OWASP MASVS mapping
* Permission analysis
* Secrets detection
* Cryptography analysis
* Certificate inspection
* Exported component analysis
* WebView analysis
* Network security analysis

### Analyst Workspace

* Evidence-driven findings
* View Code
* Attack Chains
* Trust Score
* Security Score
* Finding correlation
* Rich code snippets

### AI-Assisted Analysis

* Optional AI enrichment
* Offline deterministic explanations
* Attack path reasoning
* Remediation guidance

### Reports & Integrations

* PDF Reports
* Compliance Reports
* SARIF Export
* CycloneDX SBOM
* JSON Export

---

# Screenshots

## Home

![Home](docs/screenshots/home.png)

## Scan Overview

![Overview](docs/screenshots/overview.png)

## Findings

![Findings](docs/screenshots/findings.png)

## Permission Analysis

![Permissions](docs/screenshots/permissions.png)

## Secrets Detection

![Secrets](docs/screenshots/secrets.png)

## AI Security Assistant

![Ask AI](docs/screenshots/ask-ai.png)

## AI Analysis

![AI Response](docs/screenshots/ai-response.png)

---

# Quick Start

```bash
git clone https://github.com/f3rb123/beetle.git

cd beetle

docker compose up -d
```

Open:

```
http://localhost:9005
```

Configure:

```
SECRET_KEY=<minimum-32-character-secret>

CORTEX_ADMIN_PASS=<initial-admin-password>
```

Optional integrations:

```
ANTHROPIC_API_KEY=...

VIRUSTOTAL_API_KEY=...
```

---

# Supported Formats

| Platform | Format |
| -------- | ------ |
| Android  | APK    |
| iOS      | IPA    |

---

# Architecture

Frontend (React + Vite)

↓

FastAPI Backend

↓

Decompiler (JADX + apktool)

↓

Static Analysis Engine

↓

Evidence Engine

↓

Attack Chain Generator

↓

Reports (PDF • SARIF • SBOM)

See:

* ARCHITECTURE.md
* PROJECT_OVERVIEW.md
* FEATURE_INVENTORY.md

---

# Design Principles

* Offline-first
* Explainable findings
* Evidence over assumptions
* Standards-based analysis
* Analyst-centric workflow
* Docker-native deployment

---

# Current Capabilities

* Android static analysis
* iOS static analysis
* Attack chain generation
* MASVS mapping
* AI-assisted explanations
* Trust scoring
* Evidence viewer
* Source navigation
* PDF reports
* SARIF export
* CycloneDX SBOM

---

# Roadmap

Upcoming development includes:

* Native APKLeaks integration
* Full source explorer
* Enterprise collaboration
* CI/CD CLI
* Docker Hub images
* GitHub Action
* Plugin SDK
* Enhanced binary analysis
* Advanced iOS inspection

---

# License

See the LICENSE file.

---

# Acknowledgements

Beetle builds upon the open-source mobile security ecosystem and benefits from projects such as JADX, apktool, LIEF, and the OWASP Mobile Security Testing Guide.
# Cortex vs. MobSF — Comparative Analysis

**Basis for MobSF analysis:** MobSF 3.9+ (public documentation, open source codebase, published research).  
**Basis for Cortex analysis:** Full source code review completed June 2026.

---

## Overview

| Dimension | Cortex | MobSF |
|-----------|--------|-------|
| License | Proprietary (closed source, self-hosted) | Open source (GPL-3.0) |
| Backend language | Python 3.11 (FastAPI) | Python 3.10+ (Django + REST Framework) |
| Frontend | React 18 SPA (custom) | Django templates + Bootstrap |
| Database | SQLite | SQLite (default) / PostgreSQL (supported) |
| Android static | androguard 4.x + JADX + apktool | androguard 3.x + apktool (older) |
| iOS static | plistlib + struct + LIEF | plistlib + custom binary parsing |
| API framework | FastAPI (modern, async) | Django REST Framework (mature, sync) |
| Deployment | Docker Compose | Docker or bare metal |
| Auth | JWT + API keys, RBAC | Session-based + API token, single role |
| Maturity | Early-stage product | ~7 years, active community |

---

## Where Cortex Leads

### 1. Attack Chain Synthesis — Cortex Only

MobSF reports individual findings. Cortex synthesizes correlated attack chains (6 chain types: WebView RCE, Firebase exposure, permission leak, etc.) and generates a pentest playbook. This is a genuine differentiator — turning a list of findings into an exploitable narrative is high-value for pentesters.

**Verdict:** Cortex significantly ahead.

### 2. CISA KEV Integration — Cortex Only

Cortex fetches the CISA Known Exploited Vulnerabilities catalog and upgrades CVE severity for KEV entries. MobSF does not integrate KEV. For compliance-sensitive organizations, this is a meaningful differentiator.

**Verdict:** Cortex ahead.

### 3. Native Library CVE Mapping — Cortex Ahead

Cortex's `cve_mapper.py` parses version strings from binary data across 24 OSS libraries, cross-checks with symbol tables (when LIEF is available), and queries OSV.dev. MobSF's binary analysis focuses on hardening flags and does not perform version-string CVE mapping.

**Verdict:** Cortex ahead on native library CVE coverage.

### 4. Modern API Design — Cortex Ahead

FastAPI with automatic OpenAPI docs, async handlers, proper dependency injection, and Server-Sent Events for real-time progress is a more modern API surface than Django REST Framework. The Cortex API is cleaner and more scriptable.

**Verdict:** Cortex ahead.

### 5. Secret Validation (Live Probing) — Cortex Only

Cortex's 13-validator live probing of discovered secrets (GitHub, Stripe, Slack, OpenAI, etc.) with severity escalation for confirmed-live credentials has no equivalent in MobSF. MobSF detects secrets but does not validate them.

**Verdict:** Cortex ahead (with caveats around consent — see WEAKNESSES.md).

### 6. AI Enrichment — Cortex Only

Claude Haiku integration for contextual finding explanations is not present in MobSF. Useful for junior analysts or for automated report generation.

**Verdict:** Cortex ahead.

### 7. React SPA Frontend — Cortex Ahead on UX

The Cortex frontend (~30 organized sections, scan comparison, code viewer, recharts dashboards) is a more capable workspace than MobSF's Django-template-rendered pages. The UX for navigating complex scan results is significantly better.

**Verdict:** Cortex ahead on UX.

### 8. Taint Analysis — Roughly Equivalent

Both Cortex and MobSF use androguard for taint analysis on Android. Cortex's implementation (17 sources, 27 sinks, BFS with 60s timeout) is comparable to MobSF's taint engine in coverage and has similar limitations (no context sensitivity, no iOS support).

**Verdict:** Roughly equivalent.

---

## Where MobSF Leads

### 1. Dynamic Analysis — MobSF Only

MobSF supports full dynamic analysis: instrumented Android emulator / device testing, real-time API monitoring, traffic interception, runtime behavior capture, and screenshot analysis. Cortex is **pure static analysis only**. This is the single largest capability gap.

Dynamic analysis surfaces:
- Runtime permission requests
- Actual network traffic (cleartext, certificate pinning bypass attempts)
- Runtime secret usage
- Filesystem writes during execution
- Dynamic code loading (dex loading from network)
- Anti-analysis technique effectiveness

**Verdict:** MobSF decisively ahead. Dynamic analysis is not optional for a comprehensive MAST tool.

### 2. Maturity and Community — MobSF Ahead

MobSF has ~7 years of development, 17,000+ GitHub stars, active issue tracker, extensive documentation, and community-contributed rules. Cortex has a single initial commit. MobSF has processed millions of apps; its false positive rates are battle-tested.

**Verdict:** MobSF decisively ahead on maturity.

### 3. PostgreSQL Support — MobSF Ahead

MobSF officially supports PostgreSQL as its database backend, enabling production-grade deployments. Cortex is SQLite-only, which is a blocker for any high-volume or multi-instance deployment.

**Verdict:** MobSF ahead.

### 4. Android Emulator Integration — MobSF Only

MobSF integrates with Android emulators (via `frida` + ADB) for runtime analysis. Cortex has no emulator integration.

### 5. HTTPS / TLS Configuration — MobSF Better

MobSF's Docker setup includes better documentation for TLS termination. Cortex's Docker Compose exposes HTTP-only on port 9005 with no TLS guidance.

**Verdict:** MobSF ahead.

### 6. iOS Dynamic Analysis — MobSF Only

MobSF supports connected device dynamic analysis for iOS apps (jailbroken device with Frida). Cortex has no iOS dynamic capability.

### 7. Rule Community and Updates — MobSF Ahead

MobSF benefits from community-contributed detection rules and regular updates to its signature database. Cortex's rules are static Python code that requires a code deployment to update.

---

## Where They Are Comparable

| Feature | Cortex | MobSF |
|---------|--------|-------|
| Android manifest analysis | Full | Full |
| Permissions analysis | Full | Full |
| Exported component detection | Full | Full |
| WebView analysis | SAST + chain | SAST |
| NSC parsing | Full | Full |
| Certificate analysis | Full (v1-v4) | Full |
| Secrets detection | 36+ patterns + live validation | 20+ patterns |
| ELF binary hardening | Pure Python | Similar |
| Tracker detection | 55+ signatures | 40+ signatures |
| OSV dependency scan | Full (6 file types) | Via external tools |
| SBOM generation | CycloneDX 1.5 | CycloneDX |
| SARIF export | SARIF 2.1.0 | Limited |
| PDF reports | Full | Full |
| CI/CD API | Policy gate endpoint | REST API |
| Webhook notifications | Full (HMAC) | Not built-in |

---

## Feature Gaps in Cortex Relative to MobSF

| Gap | Priority for Cortex |
|-----|-------------------|
| Dynamic analysis (Android emulator) | P0 — defining capability missing |
| Dynamic analysis (iOS device) | P1 |
| PostgreSQL support | P0 — required for production |
| Frida instrumentation | P1 |
| Multi-user/team isolation | P1 |
| Rule update mechanism (without code deploy) | P2 |
| Community rule contributions | P3 |
| Windows/macOS bare-metal install support | P3 |

---

## Feature Gaps in MobSF Relative to Cortex

| Gap | MobSF Status |
|-----|-------------|
| Attack chain synthesis | Not present |
| CISA KEV integration | Not present |
| Native library CVE mapping | Not present |
| Live secret validation | Not present |
| AI-powered finding enrichment | Not present |
| Modern React SPA workspace | Not present (Django templates) |
| HMAC webhook notifications | Not present |
| CI/CD policy gate with per-severity thresholds | Basic equivalent |

---

## Positioning Recommendation

**Cortex is a strong complement to MobSF, not a replacement.**

If forced to choose one tool for a team without an existing mobile security program:
- **Choose MobSF** if dynamic analysis is required (it usually is for a complete assessment).
- **Choose Cortex** if the use case is purely CI/CD static analysis with rich attack chain and supply chain coverage, and the UX matters.

The ideal enterprise setup uses both:
- MobSF for dynamic analysis and as the "second opinion" static scanner
- Cortex for CI/CD integration (policy gate), SBOM generation, supply chain CVE tracking, and the attack chain narrative for pentest reports

---

## Honest Assessment

Cortex's static analysis coverage is competitive with or ahead of MobSF in several areas, particularly for supply chain (native CVE mapping + CISA KEV) and findings synthesis (attack chains). The frontend UX is meaningfully better. The API is more modern.

However, the absence of dynamic analysis, PostgreSQL support, and maturity testing against diverse real-world apps means Cortex cannot replace MobSF for a team that needs production-grade coverage today. The security weaknesses in the platform itself (JWT in localStorage, no rate limiting, plaintext webhook secrets) would concern a security team doing due diligence before deploying an internal security tool.

**If Cortex adds dynamic analysis, PostgreSQL, and fixes the critical security issues in the platform itself, it becomes a genuinely compelling alternative to MobSF with a better developer experience.**

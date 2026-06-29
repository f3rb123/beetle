# Beetle — Official Documentation

### The Beetle Bible — Authoritative Technical Reference

---

<p align="center"><em>Mobile Application Security Platform</em></p>
<p align="center">Android APK · iOS IPA · Repository / CI-CD · OWASP MASVS · Attack Chains · Explainable Intelligence</p>

---

> **About this document.** This is the single authoritative reference for Beetle. It
> documents *what* every feature does, *why* it exists, *how* it works internally, and
> *how* an analyst should interpret its output. It is a professional technical reference —
> not marketing material — written for security engineers, penetration testers, mobile
> security researchers, auditors, and the developers who build and operate Beetle.
>
> It is intentionally detailed enough that a new security engineer can understand every
> screen, score, engine and report **without reading the source code.**

---

## How this document is organized

The documentation is split into one Markdown file per chapter (numbered for ordering).
Each chapter is self-contained and cross-references related chapters. The set is designed
to be concatenated and exported to a single polished PDF (≈150–300 pages depending on the
final screenshot set).

| #  | Chapter | File |
|----|---------|------|
| 1  | Introduction | [`01-introduction.md`](01-introduction.md) |
| 2  | System Architecture | [`02-system-architecture.md`](02-system-architecture.md) |
| 3  | Scan Targets | [`03-scan-targets.md`](03-scan-targets.md) |
| 4  | Intelligence Engines | [`04-intelligence-engines.md`](04-intelligence-engines.md) |
| 5  | Dashboard Guide | [`05-dashboard-guide.md`](05-dashboard-guide.md) |
| 6  | Scoring Systems | [`06-scoring-systems.md`](06-scoring-systems.md) |
| 7  | Risk Rating | [`07-risk-rating.md`](07-risk-rating.md) |
| 8  | Trust Score | [`08-trust-score.md`](08-trust-score.md) |
| 9  | Security Score | [`09-security-score.md`](09-security-score.md) |
| 10 | Finding Confidence | [`10-finding-confidence.md`](10-finding-confidence.md) |
| 11 | Source Resolution | [`11-source-resolution.md`](11-source-resolution.md) |
| 12 | Attack Chains | [`12-attack-chains.md`](12-attack-chains.md) |
| 13 | Evidence Engine | [`13-evidence-engine.md`](13-evidence-engine.md) |
| 14 | Ownership Engine | [`14-ownership-engine.md`](14-ownership-engine.md) |
| 15 | Finding Fusion | [`15-finding-fusion.md`](15-finding-fusion.md) |
| 16 | Reports | [`16-reports.md`](16-reports.md) |
| 17 | MASVS Coverage | [`17-masvs-coverage.md`](17-masvs-coverage.md) |
| 18 | OWASP Coverage | [`18-owasp-coverage.md`](18-owasp-coverage.md) |
| 19 | Framework Intelligence | [`19-framework-intelligence.md`](19-framework-intelligence.md) |
| 20 | Network Intelligence | [`20-network-intelligence.md`](20-network-intelligence.md) |
| 21 | Source Explorer | [`21-source-explorer.md`](21-source-explorer.md) |
| 22 | AI | [`22-ai.md`](22-ai.md) |
| 23 | Reports for Different Audiences | [`23-audience-reports.md`](23-audience-reports.md) |
| 24 | FAQ | [`24-faq.md`](24-faq.md) |
| 25 | Glossary | [`25-glossary.md`](25-glossary.md) |

> **Documentation review.** A first-time-user review of this entire set — with every fix
> applied — is recorded in [`REVIEW.md`](REVIEW.md). It is a maintenance artifact, not part of
> the published reference, and is **excluded** from the PDF build.

---

## Reading conventions

| Convention | Meaning |
|------------|---------|
| `monospace` | A file, function, configuration key, API field, or literal value as it appears in the system. |
| **Bold term** | A Beetle concept defined in the [Glossary](25-glossary.md). |
| `> Note` blocks | Important caveats, limitations, or interpretation guidance. |
| Embedded screenshots | Real captures from `../screenshots/` are embedded inline (home, overview, findings, secrets, permissions, AI). |
| *Insert screenshot* placeholders | Where a capture does not yet exist (e.g. MASVS radar, Source Explorer, Network IPs); insert before the final PDF. |
| Mermaid diagrams | Architecture and data-flow diagrams; render in any Mermaid-aware viewer or the PDF pipeline. |

Throughout this document the product is referred to as **Beetle**. `Cortex` is the legacy
internal/in-code name and appears only in code paths, environment variables (`CORTEX_*`),
and database filenames.

---

## A one-paragraph orientation

Beetle ingests a mobile artifact (an Android **APK**, an iOS **IPA**, or a source/CI-CD
**repository archive**), decompiles or unpacks it, and runs a battery of static
**detection engines** that emit **Canonical Findings**. Those raw findings then pass
through a chain of **explainable intelligence engines** — Ownership, Secret Intelligence,
Confidence, Evidence, Triage, Finding Fusion, Reachability, Attack Chains and Bug Bounty —
each of which *adds* metadata without ever deleting a finding. The enriched result is
scored (Security Score, Trust Score, Risk Rating, per-finding Confidence), correlated into
**Attack Chains**, mapped to **OWASP MASVS / Mobile Top 10**, and rendered into the analyst
**workspace** and exportable **reports** (PDF, SARIF, CycloneDX SBOM, JSON). Every number
Beetle shows is accompanied by a human-readable reason — explainability is the design
philosophy that runs through the entire platform.

---

## Building the PDF

The chapters are plain GitHub-flavored Markdown with Mermaid fenced code blocks. To
produce the polished PDF reference, concatenate the chapters in order and render with a
Mermaid-aware toolchain. Example (Pandoc + a Mermaid filter):

```bash
cd docs/beetle-bible
pandoc README.md \
  01-introduction.md 02-system-architecture.md 03-scan-targets.md \
  04-intelligence-engines.md 05-dashboard-guide.md 06-scoring-systems.md \
  07-risk-rating.md 08-trust-score.md 09-security-score.md \
  10-finding-confidence.md 11-source-resolution.md 12-attack-chains.md \
  13-evidence-engine.md 14-ownership-engine.md 15-finding-fusion.md \
  16-reports.md 17-masvs-coverage.md 18-owasp-coverage.md \
  19-framework-intelligence.md 20-network-intelligence.md 21-source-explorer.md \
  22-ai.md 23-audience-reports.md 24-faq.md 25-glossary.md \
  --toc --toc-depth=2 --number-sections \
  --resource-path=.:.. \
  -F mermaid-filter \
  -o Beetle-Documentation.pdf
```

> `--resource-path=.:..` lets the embedded `../screenshots/*.png` images resolve during the
> build. `REVIEW.md` is intentionally omitted from the file list so it is not part of the PDF.

> Replace the renderer with your house toolchain if different; the only hard requirement
> is Mermaid support for the architecture diagrams and a table-of-contents pass.

---

*Document status: complete reference, first official edition. Maintained alongside the
codebase — when an engine changes, update its chapter and the [Glossary](25-glossary.md).*

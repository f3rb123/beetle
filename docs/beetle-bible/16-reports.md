# 16. Reports

Beetle turns an enriched scan result into a set of professional, audience-aware deliverables.
This chapter documents every report format and every section. Audience-specific *in-app*
reports (CISO / Developer) are detailed further in [Chapter 23](23-audience-reports.md).

---

## 16.1 The report formats

| Format | Module | Purpose | Consumer |
|--------|--------|---------|----------|
| **Technical / Executive PDF** | `report/pdf_generator.py` | The full human-readable report. | Everyone |
| **Compliance PDF** | `report/compliance_pdf.py` | MASVS v2 / PCI-DSS v4.0 / OWASP Mobile Top 10 control mapping. | Auditors, compliance |
| **CycloneDX SBOM** | `report/sbom_generator.py` | Software Bill of Materials (CycloneDX 1.5 JSON). | Supply-chain / SCA tooling |
| **SARIF 2.1.0** | `sarif_exporter.py` | Static-analysis interchange. | GitHub Code Scanning / SAST pipelines |
| **JSON** | the raw `results_json` | The complete, machine-readable scan. | Automation / custom tooling |

All are generated server-side from the single enriched result, so every format reflects the
*same* fused, triaged, scored findings. Generated artifacts are written under
`/data/reports/`. The **Reports & Export** workspace section drives all of them
([Ch 5 §5.1](05-dashboard-guide.md)).

*Insert screenshot of the Reports & Export section here.*

---

## 16.2 The main PDF — section by section

`generate_pdf()` supports a **light** and **dark** theme and an optional `prepared_by`
attribution. It assembles the report in this exact order:

| # | Section | What it contains |
|---|---------|------------------|
| 0 | **Cover page** | App name, platform, version, hash, scan date, author, detection engines used, scan duration. |
| 1 | **Executive Summary** | Security Score + grade, severity breakdown, headline risk narrative. |
| 2 | **CISO Summary** | Business-risk rating, MASVS maturity, top concerns in non-technical language ([Ch 23](23-audience-reports.md)). |
| 3 | **Attack Chains** | Each correlated chain with severity, narrative, OWASP/MASVS mapping, exploitability ([Ch 12](12-attack-chains.md)). |
| 4 | **App Info** | Package/bundle id, SDK levels, signing, framework, file metadata. |
| 5 | **Permissions** | Sensitive/dangerous permissions and their risk. |
| 6 | **Findings** | The full detail of every visible finding: severity, description, evidence snippet, recommendation, CWE/MASVS/OWASP, ownership, confidence, detected-by. |
| 7 | **Developer Summary** | Fix-oriented rollup grouped for engineering ([Ch 23](23-audience-reports.md)). |
| 8 | **MASVS Posture** | Per-category coverage + overall maturity ([Ch 17](17-masvs-coverage.md)). |
| 9 | **Secrets** | Detected secrets with intelligence status (masked values). |
| 10 | **Endpoints** | URLs / deep links / network destinations ([Ch 20](20-network-intelligence.md)). |
| 11 | **Behavior** | Notable runtime-relevant behaviors and API usage. |
| 12 | **Malware / Permission** | VirusTotal verdict + permission-risk correlation. |
| 13 | **Domain Intelligence** | Geo / OFAC-sanctions / reputation for contacted domains. |
| 14 | **Attack Surface** | Exported-component & deep-link inventory, attack-surface score. |
| 15 | **SDKs** | Third-party SDK / tracker inventory. |
| 16 | **Components** | Activities / Services / Receivers / Providers + exported status. |
| 17 | **Taint** | Data-flow source→sink paths (Android) ([Ch 4 §4.5](04-intelligence-engines.md)). |
| 18 | **Score** | The full Security Score breakdown — deductions, bonuses, factors ([Ch 9](09-security-score.md)). |
| 19 | **Certificate** | Signing schemes, Janus risk, debug cert, key size, fingerprints. |
| 20 | **Binary** | ELF/Mach-O hardening summary, instrumentation detection. |
| 21 | **String Analysis** | Categorized strings of interest. |
| 22 | **Browsable** | Browsable/deep-link intent surface. |

Each finding entry carries the same explainability the UI shows: the evidence snippet, the
analyst explanation (why it matters / how to verify / how to fix), and the standards mapping.

> **The OWASP and MASVS "sections"** requested in a generic report outline are realized as:
> the **MASVS Posture** section (coverage), the per-finding **MASVS/OWASP mapping** in the
> Findings section, the **Attack Chains** OWASP/MASVS tags, and the standalone **Compliance
> PDF** (§16.4). There is no standards information that is omitted — it is distributed across
> these surfaces.

### PDF caveats

- Generation is synchronous in the request handler and has no hard page cap, so a scan with
  hundreds of findings produces a long PDF and a longer request. For very large scans prefer
  SARIF/JSON for automation and the PDF for the curated narrative.

---

## 16.3 Report-section coverage matrix (against a generic report outline)

For completeness, here is where each commonly-expected report section lives in Beetle:

| Expected section | Where in Beetle |
|------------------|-----------------|
| Executive Summary | PDF §1; in-app Overview |
| Developer Summary | PDF §7; in-app Developer Report ([Ch 23](23-audience-reports.md)) |
| CISO Summary | PDF §2; in-app CISO Summary ([Ch 23](23-audience-reports.md)) |
| OWASP | per-finding mapping + chain tags + Compliance PDF ([Ch 18](18-owasp-coverage.md)) |
| MASVS | PDF §8 MASVS Posture + Compliance PDF ([Ch 17](17-masvs-coverage.md)) |
| Permissions | PDF §5 |
| Network | PDF §10 Endpoints + §13 Domain Intel ([Ch 20](20-network-intelligence.md)) |
| SDKs | PDF §15 |
| Secrets | PDF §9 |
| Certificates | PDF §19 |
| Components | PDF §16 |
| Storage | within Findings (Insecure Storage category) + iOS Data Storage analysis |
| Crypto | within Findings (MASVS-CRYPTO) |
| Native | PDF §20 Binary |
| Framework | App Info + Framework metadata ([Ch 19](19-framework-intelligence.md)) |
| Source Explorer | in-app investigation surface ([Ch 21](21-source-explorer.md)) |
| Attack Chains | PDF §3 ([Ch 12](12-attack-chains.md)) |
| Recommendations | per-finding `recommendation` + analyst remediation ([Ch 4 §4.23](04-intelligence-engines.md)) |
| Appendix | Score breakdown §18, String Analysis §21, SBOM (§16.5) |

---

## 16.4 Compliance PDF

Maps detected issues to three frameworks:

- **OWASP MASVS v2** — pass/fail per control based on findings + coverage.
- **PCI-DSS v4.0** — relevant mobile controls.
- **OWASP Mobile Top 10** — category coverage.

> **Interpretation caveat.** The mapping is static: a finding in category X maps to the same
> controls regardless of context, and a control with zero findings shows as "pass" even if
> the analyzer never exercised the relevant behavior. Read a "pass" as "no failing evidence
> found," not "verified compliant." Pair it with the MASVS *coverage* maturity
> ([Ch 17](17-masvs-coverage.md)), which is explicit about what was and wasn't checked.

---

## 16.5 CycloneDX SBOM

A CycloneDX 1.5 JSON Software Bill of Materials listing detected components — native
libraries (with versions and CVE references), Maven AARs, and CocoaPods frameworks — built
from the CVE/OSV detection ([Ch 4 §4.9](04-intelligence-engines.md)).

> **Completeness caveat.** The SBOM is only as complete as detection: statically-linked,
> obfuscated, or dynamically-loaded components may be invisible. No SPDX format and no
> component license data today.

---

## 16.6 SARIF 2.1.0 export

For GitHub Code Scanning and SAST toolchains:

- Severity mapping: critical/high → `error`, medium → `warning`, low/info → `note`.
- CWE relationships via `rule["relationships"]`.
- `file_evidence` → `relatedLocations` (up to 3).
- Recommendations → `fixes[].description`.
- Secrets are emitted as finding-like results (no SARIF-native secret type).

This is the recommended format for **automation and CI** — it carries the fused findings with
their locations and standards into your existing code-scanning UI.

---

## 16.7 JSON export

The complete `results_json` — every finding with all engine annotations
(ownership/confidence/evidence/triage/fusion/reachability/bug-bounty), every score, every
summary object, and all the intelligence streams. This is the canonical machine-readable
artifact; everything else is a rendering of it. Use it to build custom dashboards, feed other
tools, or archive a portable scan record.

---

## 16.8 Integrations that consume reports

- **Webhooks** (`webhooks.py`) — fire on scan completion with an HMAC-SHA256-signed payload,
  SSRF-protected, per-event filtered. Use them to push results into chat/ticketing.
- **CI/CD policy gate** (`policy.py`) — a pass/fail endpoint with per-severity thresholds
  (`max_critical`, `max_high`, …) returning `{pass, violations[]}` for pipeline gating.

---

*Next: [Chapter 17 — MASVS Coverage](17-masvs-coverage.md).*

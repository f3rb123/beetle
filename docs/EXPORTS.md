# Beetle Exports & Reports

Beetle produces several outputs from a single scan. Each targets a different audience and workflow —
a human report for analysts and stakeholders, machine-readable formats for tooling and CI, and a
policy gate for pipelines. All are generated from the same underlying findings, so they never
disagree with each other.

| Export | Format | Audience | Use it for |
| ------ | ------ | -------- | ---------- |
| **Security Report** | PDF | Analysts, engineers, stakeholders | Reading, sharing, and archiving results |
| **CycloneDX SBOM** | JSON/XML | Supply-chain & vuln-management tooling | Tracking dependencies and their CVEs |
| **SARIF 2.1** | JSON | Developer tooling / code scanning | Surfacing findings in GitHub or the IDE |
| **CI Gate** | Pass/fail check | CI/CD pipelines | Blocking a build on policy thresholds |

---

## Security Report (PDF)

The primary human-readable deliverable: **full technical findings, evidence, and scores** in one
document.

**Contains:**
- Executive and CISO summaries, overall risk rating, and the security / trust scores
- Every finding with its severity, evidence, exact source location, and remediation guidance
- Attack chains — correlated, evidence-backed attacker paths
- MASVS posture across the eight categories
- Optional **compliance scorecards** — MASVS, PCI-DSS, and OWASP Mobile Top 10 alignment

**Use it for:** a report you can read start to finish, hand to a client or an engineering lead, and
keep as the record of an assessment. It's the format built for people, not tooling.

---

## CycloneDX SBOM

A **Software Bill of Materials** in the [CycloneDX](https://cyclonedx.org/) standard — an inventory
of everything the app is built from, with known vulnerabilities attached.

**Contains:** dependencies, third-party SDKs, trackers, and native libraries, each with any known
**CVEs**.

**Compatible with:** [OWASP Dependency-Track](https://dependencytrack.org/) and AWS Inspector,
among other SBOM consumers.

**Use it for:** supply-chain and vulnerability management. Feed it into your dependency-tracking
platform to monitor the app's components over time and get alerted when a new CVE lands on a library
it ships — without re-scanning.

---

## SARIF 2.1

[SARIF](https://sarifweb.azurewebsites.net/) (Static Analysis Results Interchange Format) is the
standard format for static-analysis results, understood by developer tooling.

**Use it for:**
- **GitHub Code Scanning** — upload the SARIF and Beetle's findings appear inline on pull requests
  and in the repository's Security tab.
- **VS Code SARIF viewer** — open findings directly in the editor, navigate to each location, and
  triage them alongside the code.

This is the format that puts findings **where developers already work**, rather than in a separate
report.

---

## CI Gate

Not a file — a **pass/fail check** that evaluates a scan against configured thresholds, for use in a
CI/CD pipeline.

**How it works:** you define pass/fail policy (for example, "fail on any CRITICAL," or a maximum
allowed count per severity), and the CI Gate checks a scan's results against it. The gate returns a
clear pass or fail (and can be copied/wired into a pipeline step) so a build can be **blocked
automatically** when an app crosses your security bar.

**Use it for:** enforcing a security baseline on every build — shifting mobile app security left so
regressions are caught in the pipeline, not after release.

---

## Which one do I use?

- **Reading / sharing / archiving results** → **Security Report (PDF)**
- **Tracking dependencies & CVEs over time** → **CycloneDX SBOM**
- **Findings in GitHub or the IDE** → **SARIF 2.1**
- **Blocking a build on policy** → **CI Gate**

All four come from the same scan and the same findings — so the PDF a stakeholder reads, the SARIF a
developer triages, and the CI Gate that blocks the build are always telling the same story.

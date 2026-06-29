# 25. Glossary

Every Beetle term, defined. Cross-references point to the chapter with the full treatment.

---

**Analyzer** — The ingestion entry point for a scan target (`analyze_apk`, `analyze_ipa`,
`analyze_repository`). Produces Canonical Findings; the shared pipeline does the reasoning.
[Ch 2](02-system-architecture.md), [Ch 3](03-scan-targets.md).

**Analyst Explanation** — A deterministic, rule-driven narrative attached to every finding:
why it matters, the attack scenario, prerequisites, impact, how to verify, how to fix. No LLM,
no network. The backbone the AI Assistant grounds on. [Ch 4 §4.23](04-intelligence-engines.md).

**Attack Chain** — A realistic, evidence-backed attacker journey correlating multiple findings
(entry point → required links → goal), with confidence, exploitability and a graph. Beetle's
flagship capability. [Ch 12](12-attack-chains.md).

**Attack Surface** — The reachable entry points (exported components, deep links) and the
posture metrics summarizing them (`exported_component_inventory`, `attack_surface_score`).
[Ch 4 §4.19](04-intelligence-engines.md).

**Bug Bounty / Reportability** — An estimate of whether a finding/chain is actionable,
reportable and valuable (`reportability_score`, `state`, `review_priority` P1–P4). Severity is
*not* an input. [Ch 4 §4.22](04-intelligence-engines.md).

**Canonical Finding** — The normalized finding model every detector emits and every engine
annotates. One shape for all targets, which is why new detectors need no pipeline change.
[Ch 2 §2.6](02-system-architecture.md).

**CISA KEV** — CISA's Known Exploited Vulnerabilities feed; a CVE in KEV is bumped to high
severity. [Ch 4 §4.9](04-intelligence-engines.md).

**CI/CD Intelligence** — The detection engine for repository scan targets; finds pipeline/
workflow misconfigurations. [Ch 3 §3.5](03-scan-targets.md), [Ch 4 §4.25](04-intelligence-engines.md).

**Cloud Configuration / Exposure / Correlation** — Network-free detection of bare cloud hosts
(buckets, Cloud Functions); opt-in read-only exposure probing; correlation of secrets +
exposures into cloud attack paths. [Ch 4 §4.24](04-intelligence-engines.md), [Ch 20](20-network-intelligence.md).

**Confidence (Finding Confidence)** — How much Beetle trusts a single finding (0–100), from
five independent dimensions (detection, ownership, evidence, context, exploitability). Not
severity. [Ch 10](10-finding-confidence.md).

**Confidence Breakdown** — The full per-dimension detail behind `overall_confidence`, always
retained for explainability. [Ch 10 §10.7](10-finding-confidence.md).

**Content Hash (Evidence)** — A deterministic SHA-256 of the normalized evidence items,
stable across re-scans (timestamp excluded); seeds `evidence_id` and enables golden-regression
drift detection. [Ch 13 §13.9](13-evidence-engine.md).

**Cortex** — The legacy internal/in-code name for Beetle. Appears in code paths, `CORTEX_*`
env vars and the database filename. The product is **Beetle**.

**Coverage (Detection Coverage)** — A catalog + benchmark layer ensuring Beetle never silently
misses what mature scanners find, and measuring coverage over time. Not a second detector.
[Ch 4 §4.14](04-intelligence-engines.md).

**CWE** — Common Weakness Enumeration id carried by most rules; the bridge that powers both
OWASP/MASVS mapping and Fusion's cross-engine identity. [Ch 18 §18.3](18-owasp-coverage.md).

**Detected By** — The list of engines that found a (fused) finding; with `detection_count` it
drives the multi-engine agreement confidence bonus. [Ch 15](15-finding-fusion.md).

**Detection Engine** — A component that *finds* candidate issues and emits Canonical Findings
(SAST, Semgrep, secrets, taint, CVE, manifest, binary, CI/CD, framework sub-analyzers).
[Ch 4 Part A](04-intelligence-engines.md).

**Evidence Bundle** — The structured, multi-source, typed evidence aggregated per finding
(items, quality, verification, reproduction, correlation, content hash). [Ch 13](13-evidence-engine.md).

**Evidence Confidence / Quality** — How strong/verifiable a finding's evidence is. Quality
bands: Excellent / Good / Moderate / Weak / Missing. Feeds Trust Score and Confidence.
[Ch 13 §13.5](13-evidence-engine.md), [Ch 11](11-source-resolution.md).

**Evidence Selection** — The subsystem that picks the single best *renderable* file/line/
snippet to show for a finding. [Ch 11 §11.3](11-source-resolution.md).

**Exploitability** — How exploitable a finding/app is (0–100 at the app level from the Posture
analyzer; a conservative per-finding dimension in Confidence). Distinct from severity.
[Ch 4 §4.19](04-intelligence-engines.md), [Ch 12](12-attack-chains.md).

**Finding Confidence** — See *Confidence*.

**Finding Fusion** — The stage that collapses cross-engine duplicate findings into one
canonical finding with unified provenance and conflict resolution. [Ch 15](15-finding-fusion.md).

**Finding Located** — A finding carrying a `file_path` (+ usually `line`) that points at a real
artifact. [Ch 11 §11.1](11-source-resolution.md).

**Fusion Score** — A 0–100 corroboration-strength score for a fused finding. [Ch 15 §15.5](15-finding-fusion.md).

**Grade** — The A–F letter mapped from the Security Score (A ≥ 90 … F < 40). [Ch 9 §9.3](09-security-score.md).

**Hidden by Default** — A Triage visibility meaning *kept, but collapsed until the analyst opts
in*. Never deleted. [Ch 4 §4.17](04-intelligence-engines.md).

**Instrumentation Dylib** — A tampering/hooking library detected by LIEF (Frida, FridaGadget,
Substrate, Objection, …); a strong anti-analysis/tamper signal. [Ch 4 §4.8](04-intelligence-engines.md).

**IP Classification** — The RFC taxonomy Beetle assigns each discovered IP (public, private,
loopback, link_local, multicast, documentation, …). [Ch 20 §20.3](20-network-intelligence.md).

**Janus** — CVE-2017-13156, an APK signing vulnerability flagged for v1-only signed apps.
[Ch 5 §5.9](05-dashboard-guide.md).

**Line Resolution** — Pinning a finding to a specific source line (vs file- or class-level).
[Ch 11](11-source-resolution.md).

**MASVS** — OWASP Mobile Application Security Verification Standard. Beetle measures *coverage
maturity* against its eight categories. [Ch 17](17-masvs-coverage.md).

**Maturity (MASVS)** — A per-category band (weak / moderate / strong) describing how well an
area is implemented. [Ch 17 §17.3](17-masvs-coverage.md).

**Mode (AI)** — A tag on every AI answer: `llm` (model reasoning) or `deterministic` (evidence
restated, no provider). [Ch 22 §22.1](22-ai.md).

**Network Intelligence** — The subsystem discovering and enriching URLs, deep links, IPs,
domains and cloud backends. [Ch 20](20-network-intelligence.md).

**OSV** — OSV.dev, the open vulnerability database Beetle queries for dependency and native-
library CVEs. [Ch 4 §4.9](04-intelligence-engines.md).

**OWASP Mobile Top 10** — The category taxonomy (M1–M10) Beetle maps findings to.
[Ch 18](18-owasp-coverage.md).

**Ownership** — The classification of *who owns* a finding's code (Application, ThirdPartySDK,
framework, GeneratedCode, Unknown, …). The substrate of noise reduction. [Ch 14](14-ownership-engine.md).

**Posture Analyzer** — The finalize stage that summarizes attack surface, exploitability and
the attack graph from existing findings. [Ch 4 §4.19](04-intelligence-engines.md).

**Reachability** — Whether a finding can actually be exploited (YES / MAYBE / NO) with a path
and likelihood; can de-emphasize severity by one notch (original preserved). [Ch 4 §4.20](04-intelligence-engines.md),
[Ch 11](11-source-resolution.md).

**Renderable Evidence** — The concrete, displayable snippet (code/manifest/taint) chosen as a
finding's best proof. [Ch 11 §11.3](11-source-resolution.md), [Ch 13](13-evidence-engine.md).

**Reportability** — See *Bug Bounty*.

**Risk Rating** — The app-level business-risk label (Critical → Minimal) shown on the
dashboard and CISO summary. [Ch 7](07-risk-rating.md).

**SAFE-CHAINING** — The rules preventing false-positive attack chains (framework noise/FP
secrets/generated code never a required link; finding-soup avoidance). [Ch 12 §12.6](12-attack-chains.md).

**SARIF** — Static Analysis Results Interchange Format (2.1.0); Beetle's export for GitHub Code
Scanning / SAST toolchains. [Ch 16 §16.6](16-reports.md).

**SBOM** — Software Bill of Materials (CycloneDX 1.5) of detected components. [Ch 16 §16.5](16-reports.md).

**Scan Target** — The abstraction for *what* is analyzed (Android APK, iOS IPA, Repository/ZIP,
future IaC/AI). Separates ingestion from the shared intelligence pipeline. [Ch 3](03-scan-targets.md).

**Scan Target Registry** — The single source of truth (`scan_targets.py`) mapping extensions to
analyzers; adding a target is one entry. [Ch 3 §3.2](03-scan-targets.md).

**Security Explorer** — The pane that filters the Source Explorer tree by security category
(Secrets, Crypto, Network, Storage, …). [Ch 21 §21.3](21-source-explorer.md).

**Security Score** — The 0–100 "how secure is the app?" score with an A–F grade. [Ch 9](09-security-score.md).

**Secret Intelligence** — The engine that decides whether a detected value is a *real, live
secret* via deterministic validation, ownership and FP detection; assigns a status. [Ch 4 §4.6](04-intelligence-engines.md).

**Secret Status** — The final classification of a detected value: Validated Secret / Probable /
Possible / False Positive / Documentation Example / Public Value / Generated Constant /
Unknown. [Ch 4 §4.6](04-intelligence-engines.md).

**Severity** — The per-finding impact label (Critical → Informational). Refined by live
validation, fusion (worst wins) and reachability. [Ch 7](07-risk-rating.md).

**Source Explorer** — The file tree + code viewer investigation workspace with intelligence
badges. [Ch 21](21-source-explorer.md).

**Source Resolution %** — The share of source-applicable findings that resolve to a persisted
source file; a Trust Score factor. [Ch 11 §11.4](11-source-resolution.md).

**SSRF Protection** — The webhook safeguard (DNS resolution + RFC-1918/loopback/link-local
blocklist + DNS-rebinding re-check). [Ch 2 §2.13](02-system-architecture.md).

**Taint Analysis** — Inter-procedural data-flow (Android only) tracing sources → sinks over the
DEX call graph. [Ch 4 §4.5](04-intelligence-engines.md).

**Triage** — The engine assigning each finding an explainable decision + visibility for noise
reduction; suppresses for *lack of value*, never for being a library. [Ch 4 §4.17](04-intelligence-engines.md).

**Trust Score** — A 0–100 report-trustworthiness score (HIGH/MEDIUM/LOW): *can you trust these
findings?* Excludes reachability. [Ch 8](08-trust-score.md).

**Unknown (Ownership)** — The fallback owner classification, common under obfuscation; kept
visible, lowers Trust Score, not a resolution failure. [Ch 14 §14.8](14-ownership-engine.md).

**Verification Status (Evidence)** — How verifiable a finding's evidence is: Verified /
Partially Verified / Decompiler Only / Manifest Only / Binary Only / Generated / Needs Review /
Unknown. [Ch 13 §13.6](13-evidence-engine.md).

**View Code** — The UI action that opens the Source Explorer at a finding's exact file and
line, highlighting the snippet. [Ch 11 §11.6](11-source-resolution.md), [Ch 21 §21.4](21-source-explorer.md).

**Visibility (Triage)** — The recommended display state derived from a triage decision:
Highlight / Show / Review / HiddenByDefault. [Ch 4 §4.17](04-intelligence-engines.md).

---

*End of the Beetle Documentation. Return to the [index](README.md).*

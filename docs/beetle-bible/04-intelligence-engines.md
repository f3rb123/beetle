# 4. Intelligence Engines

Beetle is two layers of engines. **Detection engines** find candidate issues and emit
Canonical Findings. **Intelligence engines** reason over those findings — classifying,
scoring, correlating and triaging them — without ever deleting or re-severitying anything.

This chapter profiles every engine. Each profile follows the same template:

> **Purpose · Input · Processing · Output · Limitations · Future**

Engines with a dedicated chapter (Ownership, Confidence, Evidence, Finding Fusion, Attack
Chains, Network Intelligence, Source/Security Explorer, the Report generator) get a concise
profile here and a cross-reference to the full chapter.

---

## 4.0 The two layers

```mermaid
flowchart LR
    subgraph Detection (emit Canonical Findings)
      D1[Regex SAST] --- D2[Semgrep]
      D3[Evidence Scanner<br/>secrets/IP/JWT] --- D4[Taint]
      D5[CVE / OSV] --- D6[Cert · Manifest · NSC]
      D7[ELF / LIEF binary] --- D8[Trackers / SDKs]
      D9[APKLeaks source] --- D10[CI/CD]
      D11[Flutter / RN sub-analyzers] --- D12[Endpoint / Network]
    end
    Detection --> CF[Canonical Findings]
    CF --> I[Intelligence layer<br/>Ownership → Secret Intel → Confidence → Evidence →<br/>Triage → Fusion → Posture → Reachability → Chains → Bug Bounty]
```

A key architectural principle: **detection engines never call intelligence engines.** They
only emit canonical-shaped findings; the finalize pipeline does the reasoning. This is why
a brand-new detector (or a future Flutter/CI-CD/AI detector) inherits the entire
intelligence stack for free.

> **Terms used ahead of their chapters.** This chapter references standards and concepts that
> have their own later chapters: **CWE/OWASP** mapping ([Ch 18](18-owasp-coverage.md)),
> **MASVS** coverage ([Ch 17](17-masvs-coverage.md)), **severity** ([Ch 7](07-risk-rating.md)),
> **taint** and **reachability** ([Ch 11](11-source-resolution.md)), and the **Canonical
> Finding** model ([Ch 2 §2.6](02-system-architecture.md)). All bolded terms are in the
> [Glossary](25-glossary.md). You can read this chapter first for the engine catalog and follow
> the links when you need a definition.

---

# Part A — Detection Engines

## 4.1 Regex SAST (Code Analyzer)

**Purpose.** Detect security-relevant code patterns in decompiled source.

**Input.** JADX Java / apktool smali (Android) or Swift/ObjC (iOS); plus admin-defined
custom rules from SQLite.

**Processing.** Applies 100+ built-in `CODE_RULES` (Android) / `IOS_CODE_RULES` (iOS) — and
any enabled custom rules — to each file. Categories include WebView, crypto, SQL injection,
intent injection, insecure storage, IPC, network, permissions, dynamic code loading.
Custom rules are merged at scan time (`"source": "CUSTOM_RULE"`), no restart required. Each
rule carries CWE + OWASP Mobile Top 10 + MASVS metadata, and matches are attributed to an
exact file + line; the same pattern across files aggregates into multi-file evidence.

**Output.** Canonical findings with `cwe`/`masvs`/`owasp`, `file_path`, `line`, `snippet`.

**Limitations.** Pure regex — no AST, no dataflow — so it has a higher false-positive rate
for context-dependent patterns and degrades on obfuscated/heavily-minified code. The
*intelligence layer* is what tames this: Ownership, Confidence and Triage demote
library/framework noise and low-evidence matches.

**Future.** Coverage gaps are added as *data* (`code_rules.CODE_RULES`) and tracked by the
Detection Coverage engine (§4.14).

---

## 4.2 Semgrep

**Purpose.** Complement regex SAST with semantic, AST-aware rules.

**Input.** Decompiled source trees.

**Processing.** Runs the Semgrep CLI with curated rulesets (`p/android`, `p/java`,
`p/kotlin`), per-file 10 s timeout, memory/job caps tuned for the 6 GB container. SARIF
output is parsed and deduplicated against existing findings — and then, in the finalize
pipeline, **fused** semantically by CWE + location (§4.12, [Chapter 15](15-finding-fusion.md)).

**Output.** Canonical findings tagged with Semgrep as a detection source; cross-engine
duplicates with Beetle-native findings fuse into one "Detected By: Beetle · Semgrep".

**Limitations.** Semgrep is a Python dependency; confirm the CLI binary is on `PATH` in your
image for results to appear. First run may need registry access to fetch rules. Community
rule OWASP/MASVS tags are inconsistent.

**Future.** Additional rulesets register as detection sources with no pipeline change.

---

## 4.3 Evidence Scanner — secrets, IPs, JWTs

**Purpose.** Find candidate secrets, hardcoded IPs and JWTs across all decompiled files.

**Input.** The full decompiled tree (JADX first, then `apk_extract`, then smali).

**Processing.** 36+ secret patterns (AWS, GCP, Azure, GitHub, Stripe, Slack, Twilio,
SendGrid, OpenAI, JWT, PEM, Firebase, S3, Mapbox, …) with a Shannon-entropy filter,
±2-line code context, per-value+file dedup, and file/size caps (15k files / 2 MB each).
High-FP stdlib smali paths are skipped. This engine only *finds candidates* — the
**Secret Intelligence engine** (§4.6) decides what they actually are.

**Output.** `results["secrets"]`, `results["ips"]`, JWT findings — all of which become
Canonical Findings/streams that the intelligence layer enriches.

**Limitations.** Regex on decompiled output; minified/obfuscated code defeats matching.
IPv4 extraction skips smali to avoid version-number false positives (see Network
Intelligence, [Chapter 20](20-network-intelligence.md), which supersedes the old IP path).

**Future.** New patterns flow through the unified `secret_catalog` (§4.14).

---

## 4.4 Secret Validator (live API probing)

**Purpose.** Determine whether an extracted secret is an *active* credential.

**Input.** Detected secrets of supported provider types.

**Processing.** 13 validators (GitHub PAT, Stripe, SendGrid, Slack OAuth + Webhook, OpenAI,
HuggingFace, npm, Mailchimp, AWS, Shopify, Databricks) probe the real API with 8 concurrent
threads and a 6 s timeout each. A `"live"` result bumps the finding to **critical** and sets
`severity_bumped=True`. Result taxonomy: `live | invalid | unknown | skipped`. Disabled by
`CORTEX_DISABLE_LIVE_CHECKS=1`.

**Output.** Validation status on the secret; a validated secret floors Confidence at 95 and
is "safe-by-design" in Triage and Attack Chains.

**Limitations.** AWS/Shopify/Databricks return `unknown` for structural reasons (they need a
secondary value). Live probing uses real credentials against real services — **ensure you
are authorized to do so** for the app under test. No per-service shared rate limiting across
parallel scans.

**Future.** More validators register in `secret_validators/`.

---

## 4.5 Taint Analysis (Android)

**Purpose.** Inter-procedural data-flow: trace attacker-controlled inputs to dangerous
sinks.

**Input.** The androguard DEX call graph.

**Processing.** BFS from 27 sinks (Log.*, network I/O, `execSQL`/`rawQuery`,
`FileOutputStream`, `Cipher.init`, `Runtime.exec`, `WebView.loadUrl`,
`startActivity`/`sendBroadcast`, …) back to 17 sources (Intent extras, EditText,
Clipboard, Location, SMS, Accounts, ContentResolver, SharedPreferences, …), `MAX_DEPTH=6`,
`MAX_PATHS=200`/sink, 60 s hard timeout, `MAX_DEX_MB=30`. SQLi/RCE sinks are critical. The
full call chain is preserved.

**Output.** Taint findings with an ordered call chain — used by Reachability and Attack
Chains as a concrete "externally-controlled → sink" signal.

**Limitations.** Android only. No reflection/polymorphic-dispatch modeling. Large/obfuscated
apps hit the timeout or DEX cap (incomplete results aren't loudly flagged). No
context-sensitivity.

**Future.** Dynamic analysis can add runtime-reachable taint as a new signal.

---

## 4.6 Secret Intelligence Engine

**Purpose.** Decide whether a detected value is a *real, live secret* — *"a value should not
become a finding just because it matches a regex."*

**Input.** Each detected secret's raw value + file context + ownership.

**Processing.** A deterministic 11-stage pipeline: type classification → context analysis →
ownership analysis (reuses the Ownership engine) → entropy → format validation →
**checksum validation** (GitHub CRC32, Luhn) → provider validation → environment classify →
false-positive detection → confidence scoring → final status. It actively recognizes
non-secrets: famous documentation/example credentials (stored as SHA-256 hashes, never as
literals), NIST AES test vectors, degenerate UUIDs, placeholders, public keys/certs, and
crypto-library constants (by ownership). It reports AWS **Cognito identity/user pools** and
config identifiers honestly as low-exploitability recon signals, not as critical keys.

**Output.** A per-secret `status` — `Validated Secret · Probable · Possible · False
Positive · Documentation Example · Public Value · Generated Constant · Unknown` — five
explainable confidence dimensions, and `reasons`. The raw value is never stored in the
assessment.

**Limitations.** Offline only (live probing stays in §4.4). Deterministic checksums exist
only for some providers.

**Future.** New providers/validators/examples are one record each.

> See [Chapter 10](10-finding-confidence.md) for how secret status feeds confidence, and
> the Glossary for each status term.

---

## 4.7 APKLeaks integration (detection sources)

**Purpose.** Add APKLeaks-style endpoint/secret extraction as an additional **detection
source** that fuses with Beetle-native detections.

**Input.** Decompiled strings / resources.

**Processing.** `detection_sources/` registers APKLeaks patterns as a source. A
detection-time stream layer (`detection_sources/fusion.py`) merges secret/endpoint streams
that share an exact rule name and bridges secrets into findings. The finalize-time
**Finding Fusion** engine (§4.12) then unifies cross-engine equivalents semantically.

**Output.** Canonical findings carrying APKLeaks in their `detected_by` list; duplicates
with native detections collapse to one finding.

**Limitations.** Pattern-based; the same caveats as regex extraction.

**Future.** The detection-source registry is the seam every future engine (MobSF module,
YARA, AI detector) flows through.

---

## 4.8 Binary analysis — ELF & LIEF

**Purpose.** Assess native-code hardening and detect instrumentation/tampering tooling.

**Input.** `.so` ELF libraries (Android/iOS) and Mach-O binaries (iOS).

**Processing.**
- **ELF (`elf_analyzer.py`)** — pure-Python, no external dependency: PIE, NX, stack canary,
  RELRO (full/partial), RPATH/RUNPATH, FORTIFY, stripped, and dangerous libc imports;
  capped at 20 `.so` files; emits an aggregate "N/M fully hardened" summary.
- **LIEF (`lief_analyzer.py`)** — deep Mach-O/ELF: FAT-binary ARM64 slice selection,
  ObjC class enumeration, entitlement extraction, import/export symbols, and
  **instrumentation-dylib detection** (Frida, FridaGadget, Substrate, Objection → critical;
  libhooker/libellekit/libcycript → high).

**Output.** Binary hardening findings and instrumentation flags feeding the Binaries view
and the Security Score binary-hardening bonus.

**Limitations.** ELF byte-pattern matching is fragile on stripped binaries; `memcpy` flagged
as "dangerous" is a frequent benign hit. LIEF is an optional native dependency — confirm it
installs in your image. Both cap the number of binaries scanned.

**Future.** Per-binary coverage reporting; version-aware hardening baselines.

---

## 4.9 Dependency & native CVE mapping (OSV + KEV)

**Purpose.** Identify vulnerable third-party components.

**Input.** Declared dependencies (`build.gradle`, `libs.versions.toml`, `pom.xml`,
`package.json`, `pubspec.yaml`, `Package.swift`/`Podfile.lock`) and version strings in
native binaries.

**Processing.**
- **`osv_scanner.py`** — parses dependency files (with version-catalog ref resolution),
  batches up to 60 deps to OSV.dev `/v1/querybatch`, reports up to 5 CVEs/lib with the fixed
  version.
- **`cve_mapper.py`** — detects 24 bundled OSS native libraries by version strings
  (symbol-cross-checked for 19 of them), queries OSV per component, integrates the **CISA
  KEV** feed (known-exploited → severity bumped to high), and caches OSV responses 24 h.
  Also covers Maven AARs and CocoaPods frameworks. Confidence is "high" with LIEF
  sections+symbols, "medium" otherwise.

**Output.** Vulnerable-component findings, the SBOM component list, and CVE references.

**Limitations.** Version-string matching misses statically-linked/obfuscated libraries; the
60-dependency batch cap truncates very large dependency sets; no semantic version
normalization.

**Future.** Unify on the batch API everywhere; expand the native-library catalog.

---

## 4.10 Tracker / SDK detection & API usage

**Purpose.** Inventory third-party SDKs (privacy/security relevance) and platform-API usage.

**Input.** Package paths in decompiled code; API call sites.

**Processing.** `tracker_db.py` matches 55+ tracker signatures (analytics, crash, ads,
attribution, social, payments, messaging, maps, debug, ML) and SDK signatures by package
path; `api_analyzer.py` categorizes Android API usage (35 categories), extracts emails, and
runs APKiD feature detection.

**Output.** The Trackers / SDKs / Android API views and inputs to Ownership fingerprinting.

**Limitations.** Presence-only (no usage frequency or data-category analysis); some
signatures are historical (e.g. shut-down ad networks); no per-tracker severity or
regulatory (GDPR/CCPA) context.

**Future.** Regulatory tagging; data-flow-aware tracker risk.

---

## 4.11 Endpoint & Network Intelligence

**Purpose.** Discover URLs, deep links and IP addresses, and enrich them.

**Processing.** `endpoint_intel.py` extracts `http/https/ws/wss/ftp` URLs *and* custom-scheme
deep links across source/resource/config/smali/dart (filtering spec noise);
`network_intel.py` discovers IPv4 **and** IPv6, classifies them into a full RFC taxonomy,
attributes ownership, de-duplicates, scores confidence and suppresses noise (kept +
counted, never dropped); `domain_analyzer.py` adds geo/OFAC-sanctions/reputation;
`cloud_config.py` catches bare cloud hostnames the URL extractor misses (Firebase/GCS
buckets, Cloud Functions).

**Output.** `results["endpoints"]`, enriched `results["ips"]`, domain intelligence, cloud
config findings.

This is a full chapter — see [Chapter 20 — Network Intelligence](20-network-intelligence.md).

---

# Part B — Intelligence Engines (the finalize pipeline)

All Part-B engines share the same design: a pure, deterministic, cached-singleton package
with **data in `config.py`** and **logic in `engine.py`**; an `annotate(results)` entry
wired into both orchestrators' finalize step, guarded so a failure never breaks a scan; and
**additive-only** output (writes new fields via `dict.update`, never removes existing data).
Every one is **versioned** so scores are comparable across releases.

## 4.12 The pipeline order (and why)

```mermaid
flowchart LR
    OWN[Ownership] --> SEC[Secret Intel] --> CON[Confidence] --> EVI[Evidence] --> TRI[Triage] --> FUS[Fusion] --> POS[Posture] --> REA[Reachability] --> ACH[Attack Chains] --> BB[Bug Bounty]
```

Ownership is first because nearly everything reads `owner_type`. Secret Intelligence runs
before secret masking (needs raw values). Confidence reads ownership *and* Fusion's
multi-engine agreement. Evidence summarizes ownership+confidence. Triage reads all of the
above. Reachability needs the attack surface (Posture). Attack Chains and Bug Bounty consume
every prior engine.

## 4.13 Ownership Engine

**Purpose.** Answer "who owns the code this finding points at?" — Application, ThirdPartySDK,
AndroidFramework, GoogleSDK, AppleFramework, VendorSDK, OpenSourceLibrary, GeneratedCode, or
Unknown.

**Input / Processing.** Derives package/class/path/platform signals and matches a 140+
record fingerprint database with longest-prefix-wins, platform-gating, and a generated-code
stage that runs *before* the application-namespace stage.

**Output.** `owner_type`, `owner_name`, `owner_confidence` (justified anchors 30–100),
`owner_reason`, `classification_stage`; scan-level `ownership_summary`.

Full chapter: [Chapter 14 — Ownership Engine](14-ownership-engine.md).

## 4.14 Detection Coverage Engine

**Purpose.** Guarantee Beetle "never silently misses" what mature scanners surface, and
measure coverage over time. It is a **catalog + benchmark layer, not a second detector.**

**Processing.** A machine-readable `CoverageEntry` registry documents *every* detection;
`kind="secret"` entries route into the unified `secret_catalog` (matched by the one combined
secret walk), `kind="crypto"` gaps are added to `code_rules`. A benchmark module normalizes
Beetle/MobSF/APKLeaks output to canonical signatures and buckets them
(`common / beetle_only / missing / duplicate / better_evidence`); a regression corpus
(DVIA, InsecureShop, OWASP MSTG, GoatDroid, …) asserts the coverage surface never shrinks; an
`audit.py` "consolidate-first" check catches duplicate rule ids/patterns and orphaned
references.

**Output.** Coverage summary, benchmark comparison, audit report.

**Limitations / Future.** Benchmarks require external tool output; the corpus asserts on
signatures (the binaries aren't shipped).

## 4.15 Confidence Engine

**Purpose.** Measure how much Beetle trusts each finding — *not* its severity.

**Processing.** Five independent dimensions (detection, ownership, evidence, context,
exploitability) → weighted overall `0.30·detection + 0.20·ownership + 0.25·evidence +
0.15·context + 0.10·exploitability`, with decision-path short-circuits (validated secret →
≥95, chain member → ≥85, unresolved evidence → ≤35). Reads Fusion's multi-engine agreement.

**Output.** `overall_confidence`, full `confidence_breakdown`, `confidence_reason`.

Full chapter: [Chapter 10 — Finding Confidence](10-finding-confidence.md).

## 4.16 Evidence Engine

**Purpose.** Make evidence a first-class, structured, reusable, reproducible artifact.

**Processing.** Builds an aggregated multi-source `evidence_bundle` per finding from typed
`EvidenceItem`s (code/manifest/cert/secret/taint-flow), scores each item, derives a quality
band and verification status, emits reproduction steps and correlation edges, and computes a
deterministic `content_hash`.

**Output.** `evidence_bundle` + scan-level `evidence_summary`.

Full chapter: [Chapter 13 — Evidence Engine](13-evidence-engine.md). The closely-related
**Evidence Selection** subsystem chooses the single best renderable snippet/file for the UI
([Chapter 11](11-source-resolution.md)).

## 4.17 Triage Engine — noise reduction

**Purpose.** Give every finding an explainable triage **decision** + **visibility** —
*"never suppress because something is a library; suppress because the finding lacks
meaningful security value."*

**Input / Processing.** Reads Ownership, Confidence, Evidence and Secret Intelligence into a
flat context, evaluates a priority-ordered, modular **rule registry** (first match wins),
then applies a **SAFE-BY-DESIGN** guard that force-promotes protected findings (application
code, validated secrets, reachable exported components, app manifest security surface) out
of hidden-by-default.

**Output.** A `triage` dict: `decision` (Highlight / Show / Review / FrameworkNoise /
SDKNoise / GeneratedCode / Documentation / FalsePositive / NeedsHumanReview / …) → a
`visibility` (Highlight / Show / Review / HiddenByDefault) + reason + the rules that fired;
scan-level `triage_summary` with a noise-reduction metric.

> **Nothing is deleted.** `HiddenByDefault` means *kept, hidden until the analyst opts in.*
> The frontend's default Findings view applies visibility; the analyst can always reveal
> hidden findings.

**Limitations / Future.** Rule conditions are heuristic over engine metadata; future engines
(Bug Bounty, a Policy engine, AI overrides) register additional rules via `triage.register`.

## 4.18 Finding Fusion Engine

**Purpose.** Collapse duplicate findings from multiple engines into one canonical finding
that is "Detected By" all of them — so report noise stays flat as detectors grow.

**Processing.** Groups by **semantic identity** (`issue_class` from alias-registry → CWE →
normalized `category:title`, plus file + line-bucket + value-fingerprint), with a broad-CWE
over-merge guard; folds groups with documented, deterministic conflict resolution
(severity: worst wins; category: precedence; ownership: highest-confidence; location:
strongest evidence); stamps provenance; and feeds a bounded **multi-engine agreement** bonus
into Confidence.

**Output.** `detected_by`, `detection_count`, `sources`, `fusion_score`, `merged_locations`,
and `fusion.reason`; scan-level `fusion_summary`.

Full chapter: [Chapter 15 — Finding Fusion](15-finding-fusion.md).

## 4.19 Posture / Attack Surface Analyzer

**Purpose.** Summarize the attack surface the detectors already established.

**Processing.** Reads attack surface, chains and findings and adds: deep-link inventory,
exported-component inventory, high-risk components, an attack-surface score, an overall
**exploitability score** (0–100 + reason) and per-finding exploitability, and an
**attack graph** (nodes/edges/paths). It invents no findings and changes no severities.

**Output.** `attack_surface_score`, `exploitability_score`, `exported_component_inventory`,
`deep_link_inventory`, `attack_graph` — consumed by the Security Score's correlated-risk
penalty ([Chapter 9](09-security-score.md)) and by Attack Chains.

## 4.20 Reachability Engine

**Purpose.** Move from "does this setting exist?" to "can this actually be exploited?"

**Processing.** Runs after Posture, before scoring. For every finding it determines
`reachability` (YES / MAYBE / NO), an ordered human `reachability_path` from an entry point
to the sink, and a `likelihood` (High/Medium/Low). Reachability *influences* severity (an
unreachable setting is de-emphasized one notch; `severity_original` is preserved) and
generates `results["attack_paths"]` — narrated exploit paths for the overview.

**Output.** Per-finding reachability + `attack_paths`. See [Chapter 11](11-source-resolution.md)
and [Chapter 12](12-attack-chains.md).

## 4.21 Attack Chains v2

**Purpose.** Explain realistic attacker journeys, not just connect findings.

**Processing.** Tags capabilities per finding, assigns a chaining role (required / supporting
/ excluded under SAFE-CHAINING), and fills modular chain **templates** (WebView JS-bridge
RCE, deep-link→WebView disclosure, exported-component SQLi, command-injection RCE, dynamic
code loading, ContentProvider disclosure, cleartext token theft, cert-bypass MitM, hardcoded
secret abuse, insecure-storage theft, backup/debuggable extraction, weak-crypto exposure).
Confidence/exploitability/severity are derived from prior engines; subset chains are
de-duplicated to avoid "finding soup".

**Output.** `attack_chains_v2` with a graph, narrative, evidence references and
`confidence_explanation`.

Full chapter: [Chapter 12 — Attack Chains](12-attack-chains.md).

## 4.22 Bug Bounty Intelligence

**Purpose.** Estimate whether a finding/chain is **actionable, reportable and valuable** —
assist the analyst, never decide.

**Processing.** A deterministic, signal-weighted score (`BASE 50 ± signal weights + policy
boost`) where **severity is not an input** — a low-severity application finding can outscore
a critical-severity framework finding. Hard classifiers handle documentation/generated/FP;
realistic triager gates handle unreachable / unproven-flow; score bands map to states.

**Output.** Per-finding and per-chain `bug_bounty`: `reportability_score`, `state`,
`research_value`, `verification_effort`, `business_impact`, `review_priority (P1–P4)`,
`recommended_next_step`, signals + reasoning; scan-level `bug_bounty_summary`.

**Limitations / Future.** Ships the neutral `DEFAULT_POLICY`; `ProgramPolicy` is the hook for
bounty-platform / enterprise / vertical (banking/healthcare/gov) profiles.

## 4.23 Analyst & Remediation Intelligence

**Purpose.** Turn each finding into an explainable narrative — *why it matters, how it'd be
attacked, what to check before believing it, how to fix it* — deterministically, with no LLM
and no network.

**Processing.** Category templates (WebView, crypto, storage, network, IPC, …) merged with
per-finding fields produce an `analyst_explanation` (why_it_matters, attack_scenario,
prerequisites, impact, verification, remediation) on every finding and cloud attack path.

**Output.** `analyst_explanation` + `analyst_summary`. This is the deterministic backbone the
AI Assistant grounds itself on ([Chapter 22](22-ai.md)).

## 4.24 Cloud Intelligence (config · exposure · correlation)

Three cooperating, opt-in-safe modules:

- **`cloud_config.py`** (network-free) — detects bare cloud hostnames/URIs the URL extractor
  misses (Firebase/GCS buckets `*.appspot.com`/`gs://`, `*.firebaseapp.com`/`*.web.app`,
  `*.cloudfunctions.net`) and emits "Cloud Configuration" findings.
- **`cloud_intel.py`** (read-only probes, **off by default** — needs
  `CORTEX_ENABLE_CLOUD_INTELLIGENCE`, not a benchmark run, live checks enabled) — single
  read-only HTTP GET per probe behind a strict safety envelope (5 s timeout, single attempt,
  **never stores sensitive data** — only a masked target + status + method). Produces
  `cloud_exposures`.
- **`cloud_correlation.py`** (pure transform) — correlates secrets + validation + exposures
  into cloud attack paths: validated credential + confirmed exposure = HIGH; unvalidated +
  exposure = MEDIUM; credential only = LOW (suppressed by default). References only masked
  values.

**Limitations.** Live cloud probing touches real services — keep it off unless authorized.

## 4.25 CI/CD Security Intelligence

**Purpose.** A first-class detection engine for repository scan targets — finds CI/CD
pipeline/workflow misconfigurations.

**Processing.** Classifies files by platform predicate (GitHub Actions, GitLab CI, Azure
DevOps, Jenkins, CircleCI, Bitbucket, Drone, Buildkite, Tekton, generic YAML), runs per-line
`LINE_RULES` and repository-level `REPO_RULES`, and emits canonical findings (mutable action
refs, `curl|bash`, `permissions: write-all`, `docker.sock` mounts, CI-specific hardcoded
creds, missing secret scanning). Deliberately low-FP; generic secrets are left to Secret
Intelligence.

**Output.** Canonical findings → the same finalize pipeline. See [Chapter 3](03-scan-targets.md).

**Future.** Trivy/Grype/Syft/SBOM, Terraform/CloudFormation/Kubernetes/Helm IaC, OPA policy
plug into the same engine as data.

## 4.26 Framework Intelligence (Flutter / React Native)

**Purpose.** Make Flutter and React Native first-class platforms — as **sub-analyzers**
inside the Android/iOS flow, not parallel pipelines.

**Processing.** Gated on the existing `framework == "flutter" | "react_native"` detection,
each sub-analyzer harvests its sources (Dart/`pubspec`/`libapp.so` strings; JS/Hermes
bundles/`package.json`) and emits canonical findings (platform channels / native bridge,
storage, network/TLS, build/debug) tagged `Detected By: Flutter|React Native Intelligence`.
Secrets go through the shared `scan_text_for_secrets` → Secret Intelligence. Everything else
(Ownership → … → Reports) is unchanged.

**Output.** Findings + `results["flutter"]` / `results["react_native"]` metadata (deps,
channels, project structure).

Full chapter: [Chapter 19 — Framework Intelligence](19-framework-intelligence.md).

## 4.27 Source Explorer & Security Explorer

**Purpose.** The investigation workspace — a file tree + code viewer with intelligence
badges, plus a Security Explorer that filters the tree by security category. Built entirely
as an overlay on existing metadata (no new extraction).

**Output.** `results["source_explorer"]` (`file_index`, `security_index`,
`project_structure`).

Full chapter: [Chapter 21 — Source Explorer](21-source-explorer.md).

## 4.28 Report Generator

**Purpose.** Render the enriched result into PDF (executive/technical), compliance PDF
(MASVS / PCI-DSS / OWASP), CycloneDX SBOM, SARIF 2.1.0, and JSON; plus audience-specific
in-app reports (CISO / Developer).

Full chapter: [Chapter 16 — Reports](16-reports.md) and
[Chapter 23 — Audience Reports](23-audience-reports.md).

## 4.29 Future: AI Security

The AI layer ([Chapter 22](22-ai.md)) is deliberately constrained today: it **reasons over
analyzer evidence only**, never rediscovers vulnerabilities, never invents chains, never
suppresses findings. Planned directions — an AI Reviewer that consumes the confidence/
evidence breakdowns as grounded context and can `register()` refinement rules for Triage and
Attack Chains; AI-assisted detection sources that register as canonical-finding emitters and
fuse like any other engine. The architecture (deterministic, versioned, additive) is built
so an AI engine is *another detection/intelligence source*, never an unbounded oracle.

---

## 4.30 Engine summary table

| Engine | Layer | Emits / Adds | Chapter |
|--------|-------|--------------|---------|
| Regex SAST | Detection | findings (CWE/MASVS/OWASP) | §4.1 |
| Semgrep | Detection | findings (fused) | §4.2 |
| Evidence Scanner | Detection | secrets/IPs/JWTs | §4.3 |
| Secret Validator | Detection | live secret status | §4.4 |
| Taint | Detection | data-flow findings | §4.5 |
| Secret Intelligence | Intelligence | secret status + reasons | §4.6, [10](10-finding-confidence.md) |
| APKLeaks / detection sources | Detection | fused findings | §4.7 |
| ELF / LIEF | Detection | binary hardening / instrumentation | §4.8 |
| CVE (OSV + KEV) | Detection | vulnerable components | §4.9 |
| Trackers / SDK / API | Detection | inventories | §4.10 |
| Endpoint / Network | Detection+Intel | endpoints, IPs, domains, cloud cfg | [20](20-network-intelligence.md) |
| Ownership | Intelligence | owner_* | [14](14-ownership-engine.md) |
| Detection Coverage | Meta | coverage/benchmark/audit | §4.14 |
| Confidence | Intelligence | confidence_* | [10](10-finding-confidence.md) |
| Evidence | Intelligence | evidence_bundle | [13](13-evidence-engine.md) |
| Triage | Intelligence | triage{decision,visibility} | §4.17 |
| Finding Fusion | Intelligence | detected_by, dedup | [15](15-finding-fusion.md) |
| Posture | Intelligence | attack surface, exploitability | §4.19 |
| Reachability | Intelligence | reachability, attack_paths | §4.20 |
| Attack Chains v2 | Intelligence | attack_chains_v2 | [12](12-attack-chains.md) |
| Bug Bounty | Intelligence | reportability | §4.22 |
| Analyst Intel | Intelligence | analyst_explanation | §4.23 |
| Cloud (cfg/intel/corr) | Detection+Intel | cloud findings/exposures/paths | §4.24 |
| CI/CD | Detection | repo findings | §4.25, [3](03-scan-targets.md) |
| Flutter / RN | Detection | framework findings | [19](19-framework-intelligence.md) |
| Source/Security Explorer | UI overlay | source_explorer | [21](21-source-explorer.md) |
| Report generator | Output | PDF/SARIF/SBOM/JSON | [16](16-reports.md) |

---

*Next: [Chapter 5 — Dashboard Guide](05-dashboard-guide.md).*

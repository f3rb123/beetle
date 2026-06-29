# 3. Scan Targets

A **Scan Target** is Beetle's abstraction for *what* is analyzed. It is the cleanest, most
important architectural boundary in the platform: it separates **ingestion** (which differs
per input type) from **intelligence** (which is identical for every input type).

---

## 3.1 Why Scan Targets exist

Before the Scan Target abstraction, "Android" and "iOS" were hard-coded branches in the
upload endpoint and the job runner. Every new input type meant touching the HTTP layer, the
queue, and risking regressions in the shared engines.

The Scan Target refinement (Beetle 2.6) fixes this by making one rule explicit:

> The pipeline is **target-agnostic**. Only ingestion differs per target. Everything after
> Canonical Findings — Ownership → Secret Intelligence → Confidence → Evidence → Triage →
> Finding Fusion → Reachability → Attack Chains → Bug Bounty → Scoring → Reports — runs
> **identically** for every target.

```mermaid
flowchart TD
    subgraph Ingestion (per-target)
      A1[Android APK<br/>decompile + analyze]
      A2[iOS IPA<br/>extract + analyze]
      A3[Repository ZIP<br/>extract + CI/CD analyze]
      A4[(future: IaC, AI project)]
    end
    A1 --> CF[Canonical Findings]
    A2 --> CF
    A3 --> CF
    A4 -.-> CF
    CF --> P[Shared Intelligence Pipeline<br/>identical for all targets]
    P --> R[Reports · Dashboard]
```

The payoff: **adding a scan target is a single registry entry.** No change to the upload
endpoint, the job runner, or any intelligence engine.

---

## 3.2 The Scan Target model

A scan target (`backend/analyzers/scan_targets.py`) owns *only* ingestion concerns:

```python
@dataclass(frozen=True)
class ScanTarget:
    id: str            # "android" | "ios" | "repository"
    label: str         # human label shown in the UI
    platform: str      # the results["platform"] tag downstream reads
    extensions: tuple  # which uploaded extensions select this target
    needs_decompile: bool   # whether the (APK-only) decompile prepare step runs
    analyze: Callable[[str, str, str, dict], dict]  # uniform entry point
```

Every analyzer is wrapped by a thin adapter so the diverse analyzer signatures are called
through one uniform shape `analyze(file_path, scan_id, filename, artifacts)`:

```python
def _android(file_path, scan_id, filename, artifacts):
    return analyze_apk(file_path, scan_id, filename,
                       jadx_dir=artifacts.get("jadx_dir"),
                       apktool_dir=artifacts.get("apktool_dir"))
```

### The registry — single source of truth

```python
SCAN_TARGETS = (
    ScanTarget("android",    "Android APK",      "android", (".apk",), True,  _android),
    ScanTarget("ios",        "iOS IPA",          "ios",     (".ipa",), False, _ios),
    ScanTarget("repository", "Repository / ZIP", "cicd",    (".zip",), False, _repository),
)
```

`resolve_target(filename)` maps an uploaded file's extension to a target (returning `None`
for unsupported types, which the caller turns into a `400` with `accepted_extensions()`).
`main.py` then drives `prepare()` (decompile if `needs_decompile`) and `analyze()`
generically.

---

## 3.3 Android APK

| Property | Value |
|----------|-------|
| Extension | `.apk` |
| Platform tag | `android` |
| Decompile step | **Yes** — JADX (Java) + apktool (smali/resources), in parallel |
| Analyzer | `android_analyzer.analyze_apk` |

The APK is unzipped, decompiled, and run through the full Android detection battery
(manifest, NSC, certificate, SAST, taint, native/ELF, CVE, trackers, framework
sub-analyzers) before the shared finalize pipeline. See
[Chapter 2 §2.7](02-system-architecture.md) for the stage-by-stage breakdown and
[Chapter 19](19-framework-intelligence.md) for Android-native / Flutter / React Native
specifics.

Android is the only target that sets `needs_decompile=True`. Decompilation degrades
gracefully (size-scaled timeouts, partial output kept, skip switch for very large APKs).

---

## 3.4 iOS IPA

| Property | Value |
|----------|-------|
| Extension | `.ipa` |
| Platform tag | `ios` |
| Decompile step | No (an IPA is a ZIP; the app binary is Mach-O, analyzed directly) |
| Analyzer | `ios_analyzer.analyze_ipa` |

The IPA is unzipped, `Payload/*.app` located, and analyzed: Info.plist & entitlements,
Mach-O hardening (PIE/NX/canary/ARC/FairPlay), LIEF deep analysis with instrumentation-dylib
detection, data-storage / crypto / WebView analysis, embedded frameworks and CocoaPods CVE
scanning. iOS shares the entire finalize pipeline with Android — engine tests verify
Android==iOS output parity. See [Chapter 2 §2.8](02-system-architecture.md).

> **iOS coverage caveat.** iOS apps are not decompiled to source the way APKs are; analysis
> works over the Mach-O binary, plists, entitlements, embedded frameworks and any bundled
> scripts/bundles. Taint analysis (which relies on the androguard DEX call graph) is
> Android-only.

---

## 3.5 Repository / ZIP (CI/CD Security Intelligence)

| Property | Value |
|----------|-------|
| Extension | `.zip` |
| Platform tag | `cicd` |
| Decompile step | No |
| Analyzer | `repo_analyzer.analyze_repository` → `cicd_intel` |

A repository archive is extracted (bounded to **20,000 files / 500 MB**) and the **CI/CD
Security Intelligence** engine walks the tree for pipeline and workflow configuration. It is
a first-class detection engine, shaped like the mobile analyzers: it emits canonical
findings that flow through the same finalize engines (Finding Fusion → Ownership →
Confidence → Evidence → Triage → Attack Chains → Scoring). The extracted tree is persisted
under `repo/` so the Source Explorer renders the pipeline + source files and finding →
source navigation works.

**Phase-1 platforms:** GitHub Actions, GitLab CI, Azure DevOps, Jenkins, CircleCI,
Bitbucket Pipelines, Drone, Buildkite, Tekton, and generic YAML pipelines.

The CI/CD engine is deliberately **low-false-positive**: it targets CI/CD-specific,
high-signal constructs rather than generic patterns —

- Mutable action references (e.g. `uses: actions/checkout@master` instead of a pinned SHA).
- `curl … | bash` pipe-to-shell installs.
- `permissions: write-all` over-privileged workflow tokens.
- `docker.sock` mounts in build jobs.
- Hardcoded credentials in CI/CD-specific constructs (`env:` blocks, inline `with:` inputs).
- Repository-level checks (e.g. "no secret scanning configured").

Generic in-repo secrets are intentionally **left to the Secret Intelligence engine** when a
full repository is scanned, so there is no duplicate secret logic. The engine is built to
extend: future sources (Trivy / Grype / Syft / SBOM, Terraform / CloudFormation /
Kubernetes / Helm IaC, OPA policy) plug into the *same* engine via its `PLATFORMS`,
`LINE_RULES` and `REPO_RULES` data tables, with no redesign.

See [Chapter 4 §4.13](04-intelligence-engines.md) for the CI/CD engine in depth.

---

## 3.6 Framework-built apps are not separate targets

A common misconception: "is there a Flutter target / a React Native target?" No — and
deliberately so. A Flutter app ships as an Android APK (`libflutter.so` + `libapp.so` +
`flutter_assets`) or an iOS IPA (`Flutter.framework` + `flutter_assets`); a React Native app
ships as an APK/IPA with a JS/Hermes bundle. They use the **APK/IPA scan targets** and are
detected *inside* the Android/iOS analyzers, which then run a dedicated **sub-analyzer**.
The sub-analyzer contributes canonical findings to the same streams, so Flutter and React
Native findings are scored, fused, chained and reported exactly like native findings. This
is covered in [Chapter 19 — Framework Intelligence](19-framework-intelligence.md).

The `platform` field a finding ultimately reports (`flutter`, `react_native`) comes from
framework detection, not from a separate scan target. The Engineering Workspace exposes
Flutter/React Native launch cards purely as a convenience (`accept: '.apk,.ipa'`) — they
reuse the existing upload + auto-detection workflow.

---

## 3.7 Future architecture

The registry comments document the intended (not-yet-enabled) seams:

```python
# ScanTarget("iac",        "Infrastructure as Code", "iac", (".zip",), False, _iac)
# ScanTarget("ai_project", "AI Project",             "ai",  (".zip",), False, _ai_project)
```

Enabling a future target is a three-step, no-redesign change:

1. Write an ingestion analyzer that emits canonical findings into `results["findings"]`
   (and optionally `secrets` / `endpoints` / a `project_structure`).
2. Add one `ScanTarget(...)` registry row with its extension(s) and adapter.
3. (Optional) Add a launcher card / Source Explorer metadata.

Because the intelligence pipeline is target-agnostic, the new target *inherits* Ownership,
Confidence, Evidence, Fusion, Attack Chains, scoring, MASVS/OWASP mapping and the entire
report set automatically. This is the same extensibility that let CI/CD repository scanning
ship as "just another target."

---

## 3.8 Scan Target reference table

| Target | Ext | Platform | Decompile | Analyzer entry | Persists tree under |
|--------|-----|----------|:---------:|----------------|---------------------|
| Android APK | `.apk` | `android` | ✓ | `analyze_apk` | `jadx/`, `apktool/`, `apk_extract/` |
| iOS IPA | `.ipa` | `ios` | – | `analyze_ipa` | `ipa_extract/` |
| Repository / ZIP | `.zip` | `cicd` | – | `analyze_repository` | `repo/` |
| Flutter (APK/IPA) | `.apk`/`.ipa` | `flutter` | as host | host analyzer + `flutter_analyzer` | host dirs |
| React Native (APK/IPA) | `.apk`/`.ipa` | `react_native` | as host | host analyzer + `react_native_analyzer` | host dirs |
| IaC *(seam)* | `.zip` | `iac` | – | *not enabled* | — |
| AI Project *(seam)* | `.zip` | `ai` | – | *not enabled* | — |

*Insert screenshot of the upload screen / Engineering Workspace launcher cards here.*

---

*Next: [Chapter 4 — Intelligence Engines](04-intelligence-engines.md).*

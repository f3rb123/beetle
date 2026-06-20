# Cortex (Beetle) vs MobSF — Benchmark & Quality-Gate Plan

> Phase 8 deliverable. This document defines the **objective, repeatable**
> measurement framework used to (a) gate every future Cortex/Beetle release and
> (b) compare Cortex against MobSF and against prior Cortex releases.
>
> Scope guard: this phase adds **no new detections and no UI**. It only measures,
> validates, compares, and reports on what already exists.

---

## 1. Purpose

Cortex has shipped a large amount of analyst-workflow machinery (ownership
classification, trust score, evidence quality, reachability, attack chains,
exploitability, source/view-code resolution, robust PDF export). Before more
features are added we need an **objective quality bar** so that:

1. A regression in evidence quality, source resolution, view-code coverage,
   trust, or PDF export is caught automatically — *before merge*.
2. Cortex's analyst-grade output can be compared, capability-by-capability,
   against MobSF (the de-facto open-source baseline).
3. Each release produces a durable, diffable artifact (`benchmark_report.json`)
   that future releases are measured against.

The framework is the **quality gate every future Cortex release must pass**.

---

## 2. Methodology

```
   benchmark.py
        │
        ├── for each AVAILABLE benchmark app
        │       ├── decompile_apk()        (jadx + apktool, real pipeline)
        │       ├── analyze_apk()           (full Cortex analysis)
        │       ├── generate_pdf()          (export robustness check)
        │       └── collect_metrics()       (read result keys, derive metrics)
        │
        ├── evaluate success criteria (per app + aggregate)
        ├── compare vs previous baseline   (regression detection)
        ├── emit benchmark_report.json + benchmark_report.md
        └── exit non-zero on gate failure OR regression  (CI-friendly)
```

* **Real pipeline, no mocks.** Metrics are read from the exact `results` dict the
  product produces, so the benchmark cannot drift from reality.
* **Deterministic inputs.** A fixed APK dataset (see §6) under a configurable
  directory. Apps that are not present are reported as `missing`, never faked.
* **Baseline-relative.** First run writes `benchmark_baseline.json`. Subsequent
  runs diff against it and flag any tracked metric that drops beyond tolerance.

### Running

```bash
# inside the backend container (has jadx / apktool / androguard)
docker compose exec backend python benchmark.py                 # run + gate
docker compose exec backend python benchmark.py --update-baseline   # bless current as baseline
docker compose exec backend python benchmark.py --apk insecureshop  # single app
```

APK directory: `CORTEX_BENCHMARK_APK_DIR` (default `/tmp/cortex`).
Output directory: `CORTEX_BENCHMARK_OUT` (default `/tmp/cortex/benchmark`).

---

## 3. Metric definitions

| Metric | Definition | Source |
|---|---|---|
| **Trust Score** | 0–100 weighted blend of evidence quality, source resolution, ownership certainty, reachability certainty, chain confidence. | `results.trust_score.score` |
| **Evidence Coverage %** | findings carrying ≥1 concrete piece of evidence / total findings. | `results.resolution_scores.evidence_coverage_pct` |
| **Source Resolution %** | source-applicable findings resolved to a real file / source-applicable findings. | `results.resolution_scores.source_resolution_pct` |
| **View Code Coverage %** | source-applicable findings with a working View-Code target / source-applicable findings. | `results.resolution_scores.view_code_coverage_pct` |
| **Ownership Certainty** | findings with a non-`UNKNOWN` ownership label / total. *(Proxy for ownership accuracy; true accuracy needs a labelled corpus — see §3.1.)* | derived from `findings[].ownership_label` |
| **Attack Chain Coverage** | detected chains ∩ expected chains / expected chains. | `findings[].is_attack_chain` vs profile `expected_chains` |
| **False-Positive Rate** | findings suppressed as known FPs / raw detections. Measures how much noise the engine removes before the analyst sees it. | `finding_quality_stats` |
| **Signal-to-Noise** | see §3.2. | derived |
| **PDF Export Success** | PDF generates without exception and is non-trivial in size. | `generate_pdf()` |

### 3.1 Accuracy / Trust / Coverage / Evidence / View Code / FP / Workflow

* **Accuracy** — correctness of classification (ownership, severity, reachability).
  Measured today as *ownership certainty* + *attack-chain coverage* against the
  per-app expected set. Full precision/recall requires a labelled finding corpus
  (future work, §7).
* **Trust** — the Trust Score (a single 0–100 number the analyst can act on).
* **Coverage** — source resolution % and view-code coverage % over the findings
  where source is applicable.
* **Evidence** — evidence coverage % (every visible finding must be evidenced).
* **View Code** — % of findings the analyst can open in the code viewer.
* **False-Positive Rate** — proportion of raw detections suppressed as noise/FP.
* **Analyst Workflow** — composite (see §3.3): how quickly an analyst can answer
  "top risks? exploitable? how? what's exposed? fix first?".

### 3.2 Signal definitions

> **Signal findings** = application-owned findings *with* evidence.
> **Noise findings** = library/framework-owned findings, or suppressed findings.

```
Signal Ratio = Signal Findings / Total Visible Findings
```

A high signal ratio means the default analyst view is dominated by actionable,
app-owned, evidenced findings rather than third-party noise.

### 3.3 Analyst-workflow composite (0–100)

Equal-weighted blend of: trust score, signal ratio, evidence coverage,
view-code coverage, and "has ≥1 attack chain + exploitability score". Used only
for the MobSF comparison narrative, not for the hard gate.

---

## 4. Scoring model — two-tier gate

The framework distinguishes **aspirational quality targets** (a fixed bar) from
the **merge gate** (a ratchet). This matters: a deliberately-obfuscated app such
as DVBA legitimately scores *below* the trust target (low ownership certainty is
the correct classification), so a pure absolute gate would be red forever and
could never be "passed by every release." The merge gate instead enforces
"never get worse," which is both achievable today and protective going forward.

### 4a. Absolute quality targets (Task 7 — reported, informational)

An app **meets targets** when all hold:

| Criterion | Threshold |
|---|---|
| Trust Score | **> 80** |
| Evidence Coverage | **> 95%** |
| Source Resolution | **> 95%** |
| View Code Coverage | **> 95%** |
| PDF Export Success | **= 100%** |

These are shown per app (`MET` / `below`) so the team always sees how close each
app is to the bar. They do **not** by themselves block a merge.

### 4b. Merge gate (the ratchet — blocks the PR / exits non-zero)

A release **passes the merge gate** when **both** hold:

1. **No regression** vs the blessed baseline, beyond tolerance:

   | Tracked metric | Regression tolerance |
   |---|---|
   | Trust Score | drop > 3 points |
   | Evidence Coverage | drop > 2 pp |
   | Source Resolution | drop > 2 pp |
   | View Code Coverage | drop > 2 pp |
   | PDF Export | `true → false` is always a regression |
   | Expected attack chains | any expected chain lost |

2. **PDF export succeeds on every app** (hard requirement, currently 100%).

`benchmark.py` exits non-zero when the merge gate fails, so it can be wired into
CI as a required check. `--update-baseline` blesses the current run as the new
ratchet floor once a release is green.

---

## 5. MobSF comparison model

MobSF is not run live here (no live MobSF in this environment); the MobSF column
reflects its **documented capabilities** as of its current open-source release.
The comparison is therefore a **capability matrix**, scored per dimension:

| Dimension | What it measures |
|---|---|
| Detection Coverage | breadth of static checks (manifest, code, certs, secrets, deps) |
| Evidence Quality | exact file+line+snippet vs flat finding text |
| View Code Quality | jump-to-source from a finding |
| False-Positive Rate | library/framework noise suppression |
| Ownership Awareness | app vs library/SDK/framework classification |
| Attack Chain Detection | correlation of findings into exploit chains |
| Analyst Usability | reachability, exploitability, prioritization |
| Report Quality | export robustness + executive/trust summaries |

Each dimension is scored `0–3` for both tools; the report renders them
side-by-side. (Cortex's MobSF baseline is documented, not measured — flagged in
the output so it is never mistaken for a live run.)

---

## 6. Benchmark dataset

| # | App | Type | APK present? | Notes |
|---|---|---|---|---|
| 1 | DVBA (Damn Vulnerable Bank) | vulnerable | yes | deliberately vulnerable bank |
| 2 | InsecureShop | vulnerable | yes | OWASP-style insecure shop |
| 3 | Washington Post | real-world | yes | large (85 MB) production news app |
| 4 | Signal | real-world (hardened) | operator-supplied | privacy-hardened messenger |
| 5 | Firefox Android | real-world (large) | operator-supplied | very large, many native libs |
| 6 | Banking App | **template** | n/a | expected-profile only (operator drops in a real banking APK) |
| 7 | Enterprise App | **template** | n/a | expected-profile only |

* Vulnerable apps validate **detection + attack-chain coverage**.
* Real-world apps validate **noise suppression, signal ratio, scale, PDF
  robustness** (a hardened app like Signal should show *few* app-owned findings
  and a high signal ratio without false alarms).
* Templates define the *expected* thresholds a future operator APK must meet;
  they are documented profiles, not executed until an APK is supplied.

APKs are **not** committed (size/licensing). The operator places them in
`CORTEX_BENCHMARK_APK_DIR`; the framework runs whatever is present and reports
the rest as `missing`.

---

## 7. Future benchmarking workflow

1. **Pre-merge gate (CI).** `python benchmark.py` runs on the available dataset;
   the PR is blocked if the gate fails or a metric regresses.
2. **Release blessing.** On a green release, `--update-baseline` records the new
   baseline so future runs measure against the shipped quality.
3. **Dataset growth.** Add labelled findings per app to upgrade ownership
   *certainty* into ownership *accuracy* (precision/recall) and to compute
   detection precision/recall against a ground-truth set.
4. **Live MobSF runs.** When a MobSF instance is available, replace the
   documented capability matrix with measured side-by-side metrics on the same
   dataset.

---

## 8. Deliverables produced by this phase

* `docs/CORTEX_VS_MOBSF_BENCHMARK_PLAN.md` — this document.
* `backend/benchmark.py` — runner (dataset, metrics, comparison, report, regression, gate).
* `benchmark_report.json` / `benchmark_report.md` — generated per run (sample committed under `docs/benchmarks/`).

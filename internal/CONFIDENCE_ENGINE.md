# Beetle 2.0 — Explainable Confidence Engine

**Phase:** 1.3 · **Branch:** `beetle-2.0` · **Scope:** confidence measurement only.

The Confidence Engine measures **how much Beetle trusts each finding** — not its
severity, not its exploitability, not whether to suppress it. It produces five
**independent, explainable** dimensions plus a weighted overall, always retaining
the full breakdown and a human-readable reason.

This phase **only** computes confidence. It does not filter, suppress, score
severity, or change the UI/reports.

---

## 1. Architecture

```
analyzers/confidence/
  __init__.py   public API (classify, enrich, annotate, ConfidenceEngine, …)
  config.py     THE single tuning file — every weight/base/threshold, documented
  engine.py     logic only — dimension scorers + weighted roll-up + annotate()
```

Mirrors the Ownership Engine: a pure, deterministic, cached singleton; data and
constants live in `config.py`, logic in `engine.py`. Same input → same output,
always. No network, no randomness, no environment lookups.

### Confidence metadata on `CanonicalFinding`

```
detection_confidence       0-100   detector identified a real issue
ownership_confidence       0-100   read straight from the Ownership Engine
evidence_confidence        0-100   quality/quantity of verifiable evidence
context_confidence         0-100   meaningful application context
exploitability_confidence  0-100   conservative likelihood of exploitation (NOT severity)
overall_confidence         0-100   explainable weighted roll-up
confidence_reason          str     human "why"
confidence_breakdown       dict    full per-dimension detail (never hidden)
confidence_stage           str     decision path: Weighted | Validated | Correlated | Unresolved-Evidence
confidence_version         str     config version that produced the scores
```

The legacy `confidence` / `confidence_score` fields used by the existing pipeline
are **left untouched** — these are a separate, additive trust signal.

---

## 2. Pipeline

```
finding (dict)
  └─ CanonicalFinding.from_legacy()
       └─ ConfidenceEngine.classify()      # 5 independent scorers → weighted overall
            └─ result.to_fields()          # additive confidence_* keys
                 └─ dict.update(finding)    # legacy dict at the edge
```

`annotate(results)` is wired into both orchestrators' finalize **after** the
Ownership Engine (it reads `owner_*`), following the established annotation
pattern, guarded so a failure never breaks a scan. It enriches `findings` and
`suppressed_findings` and emits `results["confidence_summary"]`.

---

## 3. The five dimensions (independent by design)

The dimensions are **never collapsed** before the final weighting, so the
breakdown always explains the number. This is what lets Beetle distinguish:

| Case | detection | context | exploitability | overall |
|------|----------:|--------:|---------------:|--------:|
| Hardcoded JWT in **app** code | high | high | medium-high | **high** |
| **Generated** BuildConfig secret | high | low | very low | medium |
| **Framework** `eval()` | high | low | low | medium-low |
| Library / SDK finding | medium-high | low | low | lower |
| Documentation URL | medium | low | very low | low |

### Detection
Confidence of the *detector class* (a precision prior): structural parsers
(manifest/cert) and binary/dependency analyzers are near-deterministic; AST
(Semgrep) beats regex SAST; secret detectors sit between. A live-**validated**
secret is 100. Detector class is resolved from `evidence_type` → `source_module`
→ `category`.

### Ownership
**Read directly** from the Ownership Engine's `owner_confidence` — no
duplication. A neutral prior (50) is used only if ownership never ran.

### Evidence
Additive: a base plus points for each verifiable artifact (line, snippet, method,
class, resolvable file, decompiler-resolved source, manifest backing, taint/call
chain, multiple cross-referenced locations, binary metadata). A claimed-but-
unresolved location caps evidence low.

### Context
Driven by `owner_type` (Application 95 … Framework 25, GeneratedCode 30), with an
application-config/manifest floor (app surface is meaningful even with no
package), a medium score for resource files, and a neutral score for native libs.

### Exploitability *(conservative — NOT severity)*
Starts low; rises only with concrete signals (reachable, exported component,
externally-controlled taint source, dangerous sink/API, validated secret, attack-
chain membership, sensitive permission). Hard caps for code that cannot
meaningfully run: unreachable, generated, or framework internals. Deliberately
conservative — later reachability/exploit engines refine it.

---

## 4. Scoring model & weighting

```
overall = round( 0.30·detection + 0.20·ownership + 0.25·evidence
                 + 0.15·context  + 0.10·exploitability )
```

Rationale (in `config.py`): *detection* (is it real?) and *evidence* (can we
prove it?) dominate confidence-in-a-finding; *ownership* and *context* modulate
operational relevance; *exploitability* is the smallest factor here so it never
overpowers a well-evidenced, app-owned finding (it is a likelihood refined later).

**Decision-path short-circuits** (applied after the weighted score; the breakdown
is always retained): validated secret → floor 95 (`Validated`); attack-chain
member → floor 85 (`Correlated`); unresolved evidence → cap 35
(`Unresolved-Evidence`); otherwise `Weighted`.

**No magic numbers:** every constant lives in `config.py` with a comment
explaining it. Tuning the model = editing that one file; bump `CONFIDENCE_VERSION`
so stored scores remain traceable.

---

## 5. Explainability

Every decision carries:
* `confidence_reason` — the salient factors, e.g. *"Application context; regex sast
  detector; code snippet; method identified; reachable"*.
* `confidence_breakdown` — every dimension's score, weight and factor list, plus
  the weighted overall, band and stage. Nothing is hidden.

Bands (label only, not used in math): High ≥ 75, Medium ≥ 50, Low ≥ 25,
Informational < 25.

---

## 6. Future integration

| Consumer | How it will use confidence |
|----------|----------------------------|
| **Bug Bounty Mode** | rank/surface only high `overall_confidence`, app-context findings |
| **AI Reviewer** | feed the breakdown + reason as context; focus the model on low-confidence items |
| **SDK Suppression** | combine low `context_confidence` + library `owner_type` to group third-party noise |
| **Attack Chains** | prefer high-confidence links; `exploitability_confidence` weights chain plausibility |
| **Report Engine** | confidence badges, "high-signal findings" sections, per-dimension columns |
| **Enterprise Dashboard** | `confidence_summary` band distribution; trend confidence over releases |

All of these **read** confidence metadata; none re-run the engine. Because scores
are deterministic and versioned, dashboards can compare across scans safely.

---

## 7. Compatibility & testing

* **Additive only.** `annotate()` writes `confidence_*` via `dict.update` and
  never reads or rewrites existing finding data. Severity, the legacy
  `confidence`/`confidence_score`, suppression, attack chains, reports, exports
  and the UI are unaffected.
* **Tests:** `backend/tests/test_confidence_engine.py` (20 cases) covers
  high/low-confidence, SDK/framework/manifest/native/secret/generated/binary
  findings, missing snippet/line, partial decompilation, multiple evidence
  sources, dimension independence, determinism, the direct ownership read, the
  end-to-end ownership→confidence flow, and the non-destructive guarantee.
  Runnable on stdlib or pytest. The Phase 1.1/1.15/1.2 suites continue to pass.

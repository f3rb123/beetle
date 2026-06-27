# Beetle 2.0 — Attack Chain Engine v2

**Phase:** 1.7 · **Branch:** `beetle-2.0` · **Scope:** the attack-chain engine
only — Beetle's flagship analysis capability.

The goal is not to connect findings — it is to **explain realistic attacker
journeys** through the app using the intelligence produced by every prior engine.
Each chain answers: where the attack begins, what conditions are required, which
findings participate (required vs supporting), the attacker's objective, what
breaks the chain, and how confident/exploitable it is — all evidence-backed,
deterministic and explainable.

This phase only redesigns chaining. It is **additive**: it writes
`results["attack_chains_v2"]` and leaves the legacy chain output, findings,
severity, reports and UI untouched.

---

## 1. Architecture

```
analyzers/attack_chains/
  __init__.py   public API (build_chains, annotate, get_engine, register, …)
  config.py     THE tuning file — scoring weights, severity/evidence maps,
                eligibility (SAFE CHAINING) rules
  model.py      ChainNode/ChainEdge/ChainGraph + AttackChain (the graph + chain model)
  templates.py  modular chain templates (the chain types) — register() to extend
  engine.py     capabilities + eligibility + slot matcher + scoring + narrative + graph
```

Same shape as the prior engines: pure, deterministic, cached singleton; data
(templates, capabilities, weights) separated from logic.

---

## 2. Graph model

A chain is built as a typed graph and serialized for a future UI:
* **Nodes:** EntryPoint, Finding, Activity/Service/Receiver/Provider, Permission,
  Intent, Secret, Certificate, Endpoint, Resource, NativeLibrary, WebView,
  DeepLink, Goal.
* **Edges (relations):** uses, requires, exposes, calls, depends_on, leads_to,
  protects, weakens.

The graph reads: `EntryPoint —exposes→ Component —leads_to→ Finding —leads_to→ …
—leads_to→ Goal`, with `Mitigation —protects→ Goal` and supporting findings
`—weakens→` the path. The whole graph is on each chain (`chain.graph`).

---

## 3. Chain generation

```
findings (triaged) + attack_surface
  → tag_capabilities()   deterministic tags per finding (WEBVIEW_JS, SQL_SINK,
                          SECRET, CLEARTEXT, CERT_BYPASS, EXPORTED, DEEPLINK, …)
  → chain_role()         required | supporting | excluded  (SAFE CHAINING)
  → for each template (priority desc):
       resolve entry point (manifest component / finding / synthetic)
       fill REQUIRED capability slots via constrained matching
       gather SUPPORTING findings; detect BLOCKERS (mitigations)
       score · narrate · graph
  → dedupe (a chain whose required set is a subset of a higher-priority chain is
            dropped — prevents "finding soup")
```

**Constrained matching** fills the most-constrained slot first, so a finding that
matches several slots is never greedily consumed by an earlier one — chains form
correctly and deterministically.

### Chain types (templates)
WebView JS-bridge RCE, Deep-link→WebView file disclosure, Exported-component SQL
injection, Command injection / RCE, Dynamic code loading / reflection RCE,
Exported ContentProvider file disclosure, Cleartext-traffic token theft,
Disabled-cert-validation MitM, Hardcoded secret / API-key abuse, Insecure-storage
theft, Backup-enabled extraction, Debuggable extraction, Weak-crypto exposure.
Each is a small `ChainTemplate` (entry, required slots, supporting caps,
blockers, goal, mitigations); **`register()` adds more without engine changes.**

---

## 4. Evidence usage

Chains are evidence-backed end to end. Each step references the member finding's
**Evidence Bundle** (Phase 1.5): the exact `file:line`, the resolved
class/method, and the `evidence_id`. The chain aggregates `affected_files`,
`affected_classes`, `affected_methods` and `evidence_references` from its members,
so an analyst can reproduce every link.

---

## 5. Confidence & scoring model (no arbitrary numbers)

Everything is derived from the prior engines:
* **overall_confidence** = `0.55 · mean(member overall_confidence) + 0.45 ·
  mean(member evidence score)`, scaled by an entry-reachability multiplier
  (reachable external 1.0, distribution 0.95, unproven external 0.85, device-
  access 0.75).
* **overall_evidence_quality** = the *worst* required member's evidence band (a
  chain is only as verifiable as its weakest required link).
* **overall_exploitability** = entry-kind base blended with members'
  `exploitability_confidence`, +app-control bonus, −blocked penalty.
* **severity** = goal-based floor, downgraded when exploitability is low or the
  chain is blocked. It **never changes any finding's severity** — it is a
  chain-level property.

`confidence_explanation` records **why the chain exists, why each member belongs,
which findings were rejected, why the confidence, and why the exploitability** —
fully auditable. Severity is never the basis for chaining.

---

## 6. False-positive avoidance (SAFE CHAINING)

Driven by Triage (1.6), Secret Intelligence (1.4) and Ownership (1.2):
* **Never a required link:** framework noise, suppressed findings, documentation
  examples, false-positive/public/generated-constant secrets, generated code.
* **Supporting only:** framework/SDK-noise findings that provide a structural
  vehicle (a WebView, an exported component) may appear as *supporting context*.
* **Finding-soup avoidance:** a single unrelated high-severity finding never
  becomes a chain; templates require specific capability combinations, and subset
  chains are de-duplicated.

The result: dramatically fewer false-positive chains, framework noise excluded,
Android and iOS supported equally.

---

## 7. Explainability & narrative

Every chain produces an analyst-friendly, ordered narrative — entry point → each
required step (with its evidence reference) → objective — plus a graph, a
`triage_summary` and `ownership_summary` of its members, the blocking
mitigation(s), and recommended fixes.

---

## 8. Integration with prior engines

| Engine | Used for |
|--------|----------|
| **Ownership (1.2)** | app-control bonus; framework/SDK noise excluded from required links |
| **Confidence (1.3)** | member `overall_confidence` + `exploitability_confidence` feed chain scoring |
| **Secret Intelligence (1.4)** | only real secrets become SECRET/API_KEY/TOKEN links; FP/doc/public excluded |
| **Evidence (1.5)** | per-step `file:line`/class/method references; evidence quality drives confidence & the weakest-link evidence band |
| **Triage (1.6)** | `decision`/`visibility` decide each finding's chaining role (required/supporting/excluded) |
| **Reachability** | entry reachability sets the confidence multiplier & exploitability base |

---

## 9. Future integration

* **Future UI** visualizes `chain.graph` (nodes/edges) and the narrative — no
  backend change needed.
* **Bug Bounty Mode** surfaces only high-confidence, reachable, non-blocked
  chains with reproduction steps.
* **AI Reviewer** consumes `confidence_explanation` + evidence references as
  grounded context and can `register()` refinement templates.
* **Dynamic analysis** can add runtime-reachability as a new capability/entry,
  promoting chains from "external" to "external_reachable".
* **Golden Regression Suite** — chains and their ids are deterministic and
  versioned (`CHAIN_VERSION`), so chain drift between releases is detectable.

---

## 10. Compatibility & testing

* **Additive, non-destructive.** `annotate()` writes `attack_chains_v2`
  (+ summary) only; findings, severity, the legacy chain output, reports and UI
  are untouched.
* **Tests:** `backend/tests/test_attack_chains_v2.py` (19 cases) — WebView JS
  RCE, exported-component SQLi, ContentProvider disclosure, cleartext/cert MitM,
  hardcoded secret abuse (Android + iOS), backup/debuggable/storage/weak-crypto,
  SAFE CHAINING (framework noise / suppressed / FP secret never required),
  finding-soup avoidance, blocked chains, evidence/confidence-based scoring,
  graph, explainability, determinism and the non-destructive guarantee. Runnable
  on stdlib or pytest. The Phase 1.1–1.6 suites continue to pass.

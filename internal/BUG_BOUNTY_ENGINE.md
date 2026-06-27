# Beetle 2.0 — Bug Bounty Intelligence & Reportability Engine

**Phase:** 1.8 · **Branch:** `beetle-2.0` · **Scope:** reportability guidance only
— Beetle's final intelligence layer before external integrations (APKLeaks, AI).

This engine is **not another severity score**. It estimates whether an
experienced researcher / vulnerability triager would consider a finding (or an
attack chain) **actionable, reportable and valuable**, so analysts don't waste
time on findings that are technically correct but operationally unlikely to be
accepted. It **assists**, it does not decide — and it never modifies or removes
anything.

---

## 1. Architecture

```
analyzers/bug_bounty/
  __init__.py   public API (assess_finding, assess_chain, annotate, register, …)
  config.py     THE tuning file — states, weighted signal table, thresholds,
                value/effort/impact maps, the program-policy hook
  signals.py    modular positive/negative signal registry (data-driven)
  engine.py     context extraction + scoring + state/value/effort/impact + annotate()
```

Same shape as every prior engine: pure, deterministic, cached singleton; signals
& weights are data, logic is in `engine.py`. It **only consumes** prior engines —
it changes none of them.

### Output (on every finding's `bug_bounty`)
`reportability_score (0-100)`, `reportability_state`, `research_value`,
`verification_effort`, `business_impact`, `review_priority (P1-P4)`,
`recommended_next_step`, `positive_signals[]`, `negative_signals[]`, `reasoning[]`,
`score_breakdown{}`, `policy`, `version`.

### Output (on every attack chain's `bug_bounty`)
`reportability_score/state`, `business_impact`, `research_value`,
`verification_effort`, `remediation_priority`, signals + reasoning.

---

## 2. Reportability states

Likely Reportable · Likely Valid · Needs Manual Verification · Needs Exploitation ·
Needs Runtime Validation · Informational · Probably Duplicate · Framework Issue ·
SDK Issue · Generated Code · Documentation Example · Likely Out of Scope · False
Positive · Unknown. The vocabulary is extensible (add a `State` constant; no
engine change).

---

## 3. Scoring model (deterministic, never severity)

`score = clamp( BASE(50) + Σ positive signal weights − Σ negative signal weights
+ policy category boost )`. Severity is **not** an input — a low-severity
application finding outscores a critical-severity framework finding.

Each firing signal is recorded with its weight and reason, so the number is fully
explainable (`score_breakdown` + `positive_signals`/`negative_signals`).

### Positive signals (examples)
application-owned code, reachable attack path, validated/real secret, excellent/
good/verified evidence, participates in an attack chain, high-impact vulnerability
class in app code, reachable exported component, triage-highlighted, high
confidence, application security surface.

### Negative signals (examples)
framework internals, third-party SDK, generated code, false-positive / placeholder
secret, documentation example / public value, weak/missing evidence, unreachable,
no application control, triage hidden-by-default, low confidence, unresolved
evidence, framework/SDK noise, informational category.

`register()` adds more signals; a program policy can override any weight.

---

## 4. Decision process (state)

```
hard classifiers (deterministic, override the score):
  Documentation Example / Public Value      → Documentation Example
  Generated Constant / generated code        → Generated Code
  False-positive secret / triage FP          → False Positive
  framework/SDK + low score (not in a chain) → Framework Issue / SDK Issue / Out of Scope
realistic triager gates (not in a chain, not a validated secret):
  reachability == NO                          → Needs Runtime Validation
  unproven taint flow                         → Needs Exploitation
score bands:
  ≥80 Likely Reportable · ≥65 Likely Valid · ≥30 mid (verification kind) · <30 Informational
duplicate hint (within the scan):
  a second identical (rule_id,title,owner) reportable finding → Probably Duplicate
```

`research_value`, `verification_effort`, `business_impact`, `review_priority` and
`recommended_next_step` are derived deterministically from the context + state
(e.g. validated secret / RCE / SQLi / auth ⇒ High business impact; unreachable /
unresolved / Missing evidence ⇒ High verification effort).

### Analyst guidance (next step)
Strong Candidate for Reporting · Investigate Further · Requires Manual Review ·
Exploitability Needs Confirmation · Runtime Validation Recommended · Likely Not
Worth Reporting · Likely SDK Noise · Likely Documentation Artifact.

---

## 5. Explainability

Every decision lists the factors that raised and lowered the score (`✓`/`✗`
reasoning), the exact signal weights, and the score breakdown — e.g. *Overall
Reportability 91 — ✓ Application-owned code, ✓ Excellent evidence, ✓ Reachable
exported component, ✓ Strong attack chain, ✓ Validated secret*.

---

## 6. Attack-chain integration

Each `attack_chains_v2` chain receives its own `bug_bounty`: a reportability
score/state, business impact (from chain severity), research value (high for
exploitable, non-blocked critical/high chains), verification effort (low when
highly exploitable with strong evidence; high when blocked or low-exploitability),
and a **remediation priority**. A chain's required findings also *boost* their
own reportability (the `in_attack_chain` positive signal), and chain membership
can override a framework/SDK negative — a framework link inside a real chain is
no longer "out of scope".

---

## 7. Inputs (consumes every prior engine)

Ownership (app/framework/SDK/generated), Confidence (overall + exploitability),
Secret Intelligence (status), Evidence (quality + verification + reachability
applicability), Triage (decision/visibility), Attack Chains (membership +
confidence), plus manifest/category context. No engine is modified.

---

## 8. Program policies & enterprise modes (designed, not yet populated)

`ProgramPolicy` (in `config.py`) lets a future caller adjust **signal weights**
and **category boosts** and the minimum reportable score — without touching engine
logic. This is the extension point for:

* **Bounty platform / private-assessment** profiles (scope-aware emphasis).
* **Enterprise assessment mode** (raise weight on app-control & business logic,
  lower the bar for "needs review").
* **Vertical policies** — banking / healthcare / government / consumer (e.g.
  healthcare boosts `sensitive data exposure`; banking boosts auth/crypto).

This phase ships only the neutral `DEFAULT_POLICY`; the hook + tests prove
extensibility.

---

## 9. Compatibility & testing

* **Additive, non-destructive.** `annotate()` writes `bug_bounty` on each finding
  and chain (+ `bug_bounty_summary`); nothing is modified, removed, hidden or
  re-severitied. No UI/report/detector changes.
* **Tests:** `backend/tests/test_bug_bounty_engine.py` (19 cases) — application
  vulns, framework/SDK/generated, secrets (validated/FP/doc), certificates/
  permissions, attack-chain assessment + membership boost, Flutter/RN/Cordova/
  Unity, Android/iOS, score-not-severity, program-policy override, duplicate
  detection, explainability, determinism and the non-destructive guarantee.
  Runnable on stdlib or pytest. The Phase 1.1–1.7 suites continue to pass.

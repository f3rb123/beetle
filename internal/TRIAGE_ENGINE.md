# Beetle 2.0 — Intelligent Finding Triage & Noise Reduction Engine

**Phase:** 1.6 · **Branch:** `beetle-2.0` · **Scope:** triage only — the final
quality gate before Attack Chain v2.

> *"Never suppress because something is a library. Suppress because the finding
> lacks meaningful security value."*

The Triage Engine gives **every** finding an explainable triage decision and a
visibility recommendation by reasoning over the prior engines (Ownership,
Confidence, Evidence, Secret Intelligence). It dramatically reduces analyst noise
while guaranteeing important findings are never hidden.

**Nothing is deleted.** `HiddenByDefault` means "kept, hidden until the analyst
opts in". This phase changes no severity, confidence, ownership, evidence or
secret data — it only adds a `triage` recommendation.

---

## 1. Architecture

```
analyzers/triage/
  __init__.py   public API (triage, annotate, get_engine, register, …)
  states.py     vocabulary: Decision + Visibility + decision→visibility map +
                the SAFE-BY-DESIGN category/secret sets (the tuning data)
  rules.py      the MODULAR rule registry (id/name/priority/condition/decision/
                confidence/reason/documentation) — no giant if/else
  engine.py     context extraction + deterministic evaluator + safe-by-design
                guard + annotate()
```

Same shape as the prior engines: pure, deterministic, cached singleton; the
decision logic is a **priority-ordered set of independent rules**, not a switch.

### Where it lives on a finding
A new `triage` dict on `CanonicalFinding`: `decision, visibility, reason,
rule_id, rule_name, rule_priority, confidence, documentation, matched_rules[],
safe_override, inputs{}, version`.

---

## 2. Decision pipeline

```
finding → CanonicalFinding.from_legacy()
        → extract_context()        normalize ownership/confidence/evidence/secret
                                     into a flat TriageContext every rule reads
        → evaluate rules (priority desc, stable id tie-break) → first match wins
        → SAFE-BY-DESIGN guard      protected findings can never be HiddenByDefault
        → triage{decision, visibility, reason, rule, inputs}
```

`annotate(results)` runs **last** in both orchestrators (after ownership →
confidence → evidence), guarded, additive-only. It also emits
`results["triage_summary"]` (decision/visibility distribution + a noise-reduction
metric). It never deletes, hides, re-severities or reorders findings.

---

## 3. Triage states (decisions) → visibility

| Decision | Visibility | Meaning |
|----------|-----------|---------|
| Highlight | Highlight | top-value (validated secret, high-confidence app finding) |
| Show | Show | application code / app security surface |
| Review | Review | real-but-uncertain secret, reachable exported, library w/ evidence |
| FrameworkNoise | HiddenByDefault | framework/AndroidX finding, weak evidence, not reachable |
| SDKNoise | HiddenByDefault | third-party SDK, weak evidence, low confidence, not reachable |
| GeneratedCode | HiddenByDefault | machine-generated code / crypto constant |
| Documentation | HiddenByDefault | documentation example / public key/cert |
| FalsePositive | HiddenByDefault | confirmed non-secret / false positive |
| NeedsHumanReview | Review | unresolved evidence or very low signal |
| Suppress / HiddenByDefault | HiddenByDefault | explicit (future policies) |
| Unknown | Review | default — never hidden |

The vocabulary is extensible: add a `Decision` constant + a `DECISION_VISIBILITY`
entry; no engine change.

---

## 4. The rule model (modular policies)

Each `Rule` has: **id, name, priority, decision, confidence, documentation, a
pure condition over `TriageContext`, and a reason** (static or computed). The
engine sorts by priority (descending, stable by id → deterministic) and the
highest-priority matching rule decides; a final `DEFAULT` rule (always matches,
keeps the finding visible) guarantees a decision. A buggy rule condition is caught
and skipped — triage never breaks.

Priority bands:
```
1000  SAFE-BY-DESIGN / high value      (validated secret, reachable exported,
        app security surface, high-value app secret/finding)  — never suppressed
 880  real secret (probable/possible)  — never auto-suppressed, even in an SDK
 820  secret false-positive/doc/generated  — overrides app visibility (no value)
 800  application code                 — always at least Show
 600  generated code
 450  framework noise   /  400  SDK noise   → HiddenByDefault
 350  unresolved evidence  /  300  low signal → NeedsHumanReview
 120  library default (visible)  /  50  default (visible)
```

**Future engines register additional rules** via `triage.register(Rule(...))` —
e.g. Bug Bounty Mode, a Policy Engine, or AI-Reviewer overrides.

---

## 5. SAFE-BY-DESIGN

Two layers guarantee important findings stay visible:
1. **Priority** — the safe rules sit at the top, so they win over any noise rule.
2. **A final guard** — even if a rule had a gap, a *protected* finding
   (application code, validated secret, reachable exported component, app-scoped
   manifest security surface) is force-promoted out of `HiddenByDefault`
   (`safe_override: true`). Confirmed false-positive secrets are the one
   exception — they have no value and are not protected, satisfying the
   philosophy that we suppress for **lack of value**, not for being a library.

Worked examples (from the brief), all reproduced by the tests:
* `androidx.work` + weak evidence + no app reachability → **FrameworkNoise → HiddenByDefault**.
* App `BuildConfig` + validated JWT + excellent evidence → **Highlight**.
* Firebase SDK hardcoded API key → **Review** (NOT suppressed — it's a real secret).
* BouncyCastle constant / documentation example → **FalsePositive/GeneratedCode → HiddenByDefault**.
* Exported `ContentProvider` (third-party class, app manifest, reachable) → **Review** (NOT suppressed).

---

## 6. Explainability

Every decision carries a human `reason` (e.g. *"Finding originates from AndroidX
WorkManager (ThirdPartySDK). Ownership confidence is 100%. Evidence quality is
weak. No application-controlled execution path exists (reachability: none)."*),
the `rule_id`/`rule_name` that fired, every rule that matched (`matched_rules`),
and the `inputs` (owner, confidence, evidence quality, verification, secret
status, reachability) that drove it — fully auditable.

---

## 7. Integration with every prior engine

| Engine | Triage uses |
|--------|-------------|
| **Ownership (1.2)** | `owner_type`/`owner_name`/`owner_confidence` → app vs framework vs SDK vs generated |
| **Confidence (1.3)** | `overall_confidence`, exploitability — noise vs keep thresholds |
| **Evidence (1.5)** | `evidence_bundle.quality` / `verification_status` — weak evidence permits noise triage; unresolved → review |
| **Secret Intelligence (1.4)** | `secret_intelligence.status` — validated/real → visible; FP/doc/generated → hidden |
| **Reachability** | `reachability` — reachable findings are never noise |

---

## 8. Future compatibility

Designed to feed: **Bug Bounty Mode** (show only Highlight/Show + reproducible),
**Attack Chain v2** (chain only Show/Highlight/Review links), **AI Reviewer**
(focus on NeedsHumanReview; register override rules), **Enterprise Reports**
(visibility-driven sections, noise-reduction metrics), **Dynamic Analysis** (a
runtime-reachability rule), **Golden Regression Suite** (decisions are
deterministic and versioned), and a **Policy Engine** (org-specific rules via
`register`).

---

## 9. Compatibility & testing

* **Additive, non-destructive.** `annotate()` writes only `triage` (+ the scan-
  level `triage_summary`); it never removes, hides, re-severities or reorders.
* **Tests:** `backend/tests/test_triage_engine.py` (20 cases) — the five worked
  examples, application/framework/SDK/generated/secret/certificate/permission/
  manifest/native/Flutter/RN/Cordova/Unity/Apple-framework/mixed findings, false
  positives, every SAFE-BY-DESIGN guarantee, determinism, modular rule
  registration, explainability, and the regression guarantee that no findings are
  lost. Runnable on stdlib or pytest. The Phase 1.1–1.5 suites continue to pass.

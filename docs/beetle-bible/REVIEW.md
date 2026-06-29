# Beetle Bible — Documentation Review Report

**Reviewer perspective:** an external security engineer using Beetle for the first time.
**Method:** read all 25 chapters end-to-end, then cross-checked every load-bearing claim
against the live code (`trust_engine.py`, `scoring.py`, `confidence/config.py`,
`masvs_intel.py`, the workspace panel registry, `panels.jsx`, `panels2.jsx`,
`evidence-model.js`).

This report lists every issue found, grouped by the requested categories, with a
**Status** for each: **Fixed** (markdown updated in this pass), **Noted** (documented as a
known limitation / left for a future pass with rationale).

---

## Summary of verification

| Claim checked | Verdict |
|---------------|---------|
| Trust Score weights 35/30/20/15, ratings ≥75/≥50 | ✅ matches `trust_engine.py` |
| Confidence weights 0.30/0.20/0.25/0.15/0.10 | ✅ matches `confidence/config.py` |
| Security Score weights 15/8/3/1/0, 3× cap, chain penalty, bonuses, grades | ✅ matches `scoring.py` |
| MASVS = 8 v2 categories, coverage = controls(≤60)+hygiene(≤40) | ✅ matches `masvs_intel.py` |
| Workspace section list | ✅ matches `workspace-registry.js` |
| **Per-finding "Trust" vs "Confidence" vs report Trust Score** | ❌ **conflated in the docs — fixed** |
| iOS deep-analysis sections (Entitlements/Frameworks/Storage/Crypto/WebView) | ❌ **legacy-only; not in active workspace — clarified** |

The numeric claims were accurate. The defects were about **terminology, first-run
guidance, and UI completeness** — exactly where a first-time external user struggles.

---

## 1. Missing explanations

| # | Issue | Status |
|---|-------|--------|
| 1.1 | **No getting-started / first-scan path.** A first-time user cannot tell how to log in, upload an artifact, or read the first result. | **Fixed** — added Ch 2 §2.0 "Getting Started (your first scan)" with login, upload, progress, and where to look first. |
| 1.2 | **The per-finding "Trust" number is never defined.** The finding card shows a 0–100 "Trust" chip computed as `0.6·confidence + 0.25·fusion + 0.15·evidence` — distinct from both report Trust Score and Confidence. | **Fixed** — defined in new Ch 6 §6.10 ("Three numbers named trust/confidence") and cross-referenced from Ch 5, 8, 10. |
| 1.3 | **Where iOS deep-analysis results appear was unstated.** An iOS user could hunt for a "Data Storage / Entitlements" tab that doesn't exist in the active workspace. | **Fixed** — Ch 5 §5.1 and §5.21 now state iOS findings surface through the shared sections (Findings/Manifest/Certificates/Binary), not dedicated iOS panels. |
| 1.4 | **Finding state workflow (open / suppressed / false-positive) and the "App Only" toggle were not documented.** | **Fixed** — Ch 5 §5.4.1 now documents the state filter, App-Only toggle, suppressed-view, and search. |
| 1.5 | **"Canonical Finding" is used in Ch 1 before it is defined** (Ch 2 §2.6 / glossary). | **Fixed** — Ch 1 §1.6 now forward-references the definition; README conventions note that terms are defined in the Glossary. |

## 2. Inconsistent terminology

| # | Issue | Status |
|---|-------|--------|
| 2.1 | **"Trust Score" is overloaded.** It means (a) the report-level score (Ch 8), but the UI also shows a per-finding **Trust** chip (different formula) and a **Trust ≥** filter. The docs treated "Trust" as one thing. | **Fixed** — new Ch 6 §6.10 disambiguation table; Ch 8 opens with a "two different things called Trust" note; Ch 5 §5.4.2 labels the chip precisely. |
| 2.2 | **Per-finding "Confidence" chip band thresholds (70/40) differ from the Confidence engine bands (75/50/25).** The UI chip uses `evidence_quality` or a 70/40 banding; Ch 10 documented only the engine bands. | **Fixed** — Ch 10 §10.6 now notes the UI chip's banding differs from the engine's display bands and why. |
| 2.3 | "Beetle Bible" vs "Beetle — Official Documentation" vs "this document" used interchangeably. | **Noted** — harmless; "Beetle Bible" is the informal name, "Beetle Documentation" the formal title. Left as-is. |
| 2.4 | Findings filter labels: "minimum trust/confidence" in prose vs the UI's "Trust ≥". | **Fixed** — Ch 5 §5.4.1 now uses the exact UI label "Trust ≥" and links the definition. |

## 3. Chapters that assume prior knowledge

| # | Issue | Status |
|---|-------|--------|
| 3.1 | **Ch 4 uses CWE / MASVS / OWASP / taint before their chapters (7, 17, 18).** | **Fixed** — Ch 4 §4.0 adds a "standards & terms used here" forward-reference line. |
| 3.2 | Ch 1–2 assume Docker familiarity. | **Noted** — acceptable for the stated audience (security engineers/operators); the README points to the project README for Docker basics. |
| 3.3 | The intelligence-pipeline ordering is shown before the reader knows the engines. | **Noted** — intentional: Ch 2 is the map, Ch 4 the detail; each pipeline diagram links forward. |

## 4. Missing diagrams

| # | Issue | Status |
|---|-------|--------|
| 4.1 | **No navigation-hierarchy diagram** in Ch 5. | **Fixed** — added a Mermaid nav tree to Ch 5 §5.1. |
| 4.2 | **No visual for the three "trust/confidence" numbers.** | **Fixed** — Ch 6 §6.10 includes a diagram + table. |
| 4.3 | Ch 7 (Risk Rating) had no severity-refinement diagram. | **Fixed** — added a severity-refinement flow to Ch 7 §7.3. |
| 4.4 | Getting-started has no flow. | **Fixed** — Ch 2 §2.0 includes a first-scan sequence. |

## 5. Places where screenshots significantly help (and are now wired in)

Eight real screenshots exist under `docs/screenshots/`. Generic placeholders were replaced
with the actual images where available:

| Location | Screenshot | Status |
|----------|------------|--------|
| Ch 1 §1.1 home/scan list | `home.png` | **Fixed** |
| Ch 5 §5.3 Overview dashboard | `overview.png` | **Fixed** |
| Ch 5 §5.4 Findings + drawer | `findings.png` | **Fixed** |
| Ch 5 §5.6 Secrets | `secrets.png` | **Fixed** |
| Ch 5 §5.8 Permissions | `permissions.png` | **Fixed** |
| Ch 22 AI Assistant | `ask-ai.png` | **Fixed** |
| Ch 22 AI providers | `ai-options.png` | **Fixed** |
| Ch 22 AI analysis | `ai-response.png` | **Fixed** |
| MASVS radar, Source Explorer, Network IPs, Attack Chains, upload | — (no capture yet) | **Noted** — placeholders retained with explicit capture instructions. |

## 6. Repeated content that should be consolidated

| # | Issue | Status |
|---|-------|--------|
| 6.1 | The engine boilerplate ("pure, deterministic, cached singleton; data in config.py, logic in engine.py; additive-only; versioned") is restated in Ch 4 §4.12 and in Ch 13/14/15. | **Noted** — kept one canonical statement in Ch 4 §4.12 and made the dedicated chapters reference it rather than re-explain; some restatement is intentional so each chapter stands alone in the PDF. |
| 6.2 | The intelligence-pipeline diagram appears in Ch 1, Ch 2 §2.5, Ch 4 §4.12. | **Noted** — intentional (orientation → architecture → detail, at three altitudes); each is captioned to clarify why it recurs. |
| 6.3 | The score-family is summarized in both Ch 5 §5.3.1 and Ch 6 §6.1. | **Noted** — Ch 5 is "what the card shows," Ch 6 is the master reference; Ch 5 now links to Ch 6 instead of re-deriving. |

## 7. Ambiguous scoring explanations

| # | Issue | Status |
|---|-------|--------|
| 7.1 | **Trust Score edge cases unstated:** no findings → 100/HIGH; no chains → chain factor = 100 (no drag); evidence-quality value map HIGH=100/MED=60/LOW=25. | **Fixed** — added to Ch 8 §8.3 / §8.4. |
| 7.2 | **Per-finding Trust formula undocumented** (see 1.2). | **Fixed** — Ch 6 §6.10. |
| 7.3 | Security Score: the "diminishing-returns cap" wording could read as a global cap rather than per-severity-class. | **Fixed** — Ch 9 §9.2 clarifies the cap is per-severity-class and applies independently to findings and secrets. |

## 8. UI sections not documented

| # | Issue | Status |
|---|-------|--------|
| 8.1 | Finding card chips list (Severity, **Confidence**, **Trust**, Evidence, Fusion, Ownership, Reachability, Attack Chain) was incomplete/imprecise. | **Fixed** — Ch 5 §5.4.2 now lists the exact chips. |
| 8.2 | State filter / suppressed view / App-Only toggle / in-list search. | **Fixed** — Ch 5 §5.4.1. |
| 8.3 | iOS scans: no dedicated panels (data flows through shared sections). | **Fixed** — Ch 5 §5.21. |

## 9. Features that have changed since the documentation was written

The documentation was written directly from the current code, so most claims were current.
The cross-check surfaced two places where the prose reflected an **older or idealized**
description rather than the shipped UI:

| # | Issue | Status |
|---|-------|--------|
| 9.1 | **The active workspace dropped the legacy "iOS Deep Analysis" sections** (Entitlements, Frameworks, Data Storage, Cryptography, WebView/Bridges) that older architecture notes describe. The Bible correctly documented the *active* registry but didn't call out the change. | **Fixed** — Ch 5 §5.21 and Ch 19 §19.3 now explicitly state these are surfaced via findings, not dedicated panels (legacy sections retired). |
| 9.2 | **The per-finding "Trust" composite chip** is a newer frontend signal (`evidence-model.js`) layered over `overall_confidence` + fusion + evidence; its existence post-dates the engine-only confidence model the docs described. | **Fixed** — documented in Ch 6 §6.10. |
| 9.3 | A code comment ("`trustScore` never used for filtering") is now stale — the **Trust ≥ filter does use it.** Not a docs error, but noted so the docs describe shipped behavior. | **Fixed** — Ch 5 §5.4.1 documents the filter as it actually behaves. |

---

## Disposition

All **Fixed** items have been applied to the Markdown in this pass. **Noted** items are
intentional design choices or out-of-scope (e.g. capturing new screenshots), each with a
rationale above. The documentation is consistent with the shipped code as of this review
and ready for PDF generation.

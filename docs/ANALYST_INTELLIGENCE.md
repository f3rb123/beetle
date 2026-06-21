# Analyst Intelligence

> Skeleton — Phase 11.5. Expand with template catalog before GA.

## What it answers

"Why does this finding matter, how would it be attacked, and how do I fix it?" —
explainable, rule-driven analyst narrative. No external LLM, no network.

## Where it lives

`backend/analyzers/analyst_intel.py` → `annotate(results)`:
- attaches `analyst_explanation` to every finding and cloud attack path
- builds `results["analyst_summary"]` (top_risks, most_exploitable_chains,
  high_confidence_findings)

## AnalystExplanation model

`{title, why_it_matters, attack_scenario, prerequisites, impact,
remediation{summary,masvs,owasp}, references, false_positive_notes,
confidence_reason}`.

## Category templates (12)

WebView · Crypto · Network · Secrets · Firebase · S3 · Certificate · Root
Detection · Deep Links · Intent Injection · SQL Injection · File Storage (+ generic).

## Confidence reasoning

Built deterministically from source resolution, evidence presence, ownership,
validation and reachability — feeds [[TRUST_SCORE]] context.

## TODO

- [ ] Document each category template
- [ ] Tie false-positive notes to the FP inventory

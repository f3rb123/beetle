# Trust Score

> Skeleton — Phase 11.5. Expand with worked examples and screenshots before GA.

## What it answers

"Can an analyst trust these findings?" — a 0–100 report-trustworthiness score,
distinct from severity (how bad) and reachability (how exploitable).

## Where it lives

`backend/analyzers/trust_engine.py` → `annotate_trust(results)` →
`results["trust_score"]` (`{score, rating, factors, meaning}`) and
`results["resolution_scores"]`.

## Factors & weights

| Factor | Weight | Source |
|--------|--------|--------|
| Evidence quality | 35% | `evidence_quality` (HIGH/MEDIUM/LOW) per finding |
| Source resolution | 30% | share of findings with a resolved source file+line |
| Ownership certainty | 20% | share of findings with a known ownership label |
| Chain confidence | 15% | attack-chain `chain_confidence` |

Reachability is intentionally **not** a factor (it answers exploitability, a
separate concern).

## Ratings

- `HIGH` ≥ 75 · `MEDIUM` 50–74 · `LOW` < 50

## TODO

- [ ] Worked example per Tier-1 app
- [ ] Rationale for weight choices
- [ ] How obfuscation affects ownership certainty

# Cortex Benchmark Report

_Generated 2026-06-20T18:23:04.712152Z · tool: Cortex / Beetle_

**Merge gate (regression + PDF): PASS ✅**
**Absolute quality targets (Task 7): 1/3 apps meet all targets**

## Success criteria

| Metric | Threshold |
|---|---|
| trust_score | > 80 |
| evidence_coverage_pct | > 95 |
| source_resolution_pct | > 95 |
| view_code_coverage_pct | > 95 |
| pdf_success | == True |

## Per-app results

| App | Type | Findings | Chains | Trust | Evidence | Source | ViewCode | Signal Ratio | FP% | PDF | Targets |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Damn Vulnerable Bank (DVBA) | vulnerable | 40 | 2 | 77 | 100% | 100% | 100% | 0.525 | 50.6% | OK | below |
| InsecureShop | vulnerable | 45 | 5 | 84 | 100% | 100% | 100% | 0.489 | 45.5% | OK | MET |
| Washington Post | real_world | 74 | 4 | 80 | 100% | 97% | 97% | 0.527 | 2.6% | OK | below |

### Damn Vulnerable Bank (DVBA)  (com.app.damnvulnerablebank v1.0, 4 MB)

- Findings: **40** · suppressed: 43 · signal: 21 · noise: 62 · signal ratio: **0.525**
- Attack chains: **2** ['crypto_failure', 'webview_rce'] · coverage 100%
- Trust: **77/100 (HIGH)** · evidence 100% · source 100% · view-code 100% (n/a source: 4)
- Ownership certainty: 57% · breakdown: {'APPLICATION': 21, 'UNKNOWN': 17, 'JETPACK': 2}
- False-positive rate: 50.6% · PDF: True (43 KB)
- ⚠️ below absolute target(s): ['trust_score=77 (need > 80)']

### InsecureShop  (com.insecureshop v1.0, 5 MB)

- Findings: **45** · suppressed: 40 · signal: 22 · noise: 63 · signal ratio: **0.489**
- Attack chains: **5** ['crypto_failure', 'debug_backup_exfil', 'intent_injection', 'permission_data_leak', 'webview_rce'] · coverage 100%
- Trust: **84/100 (HIGH)** · evidence 100% · source 100% · view-code 100% (n/a source: 3)
- Ownership certainty: 98% · breakdown: {'APPLICATION': 22, 'JETPACK': 15, 'UNKNOWN': 1, 'ANDROID_FRAMEWORK': 4, 'THIRD_PARTY_LIBRARY': 1, 'GOOGLE_SDK': 2}
- False-positive rate: 45.5% · PDF: True (48 KB)

### Washington Post  (com.washingtonpost.android v7.4.1, 85 MB)

- Findings: **74** · suppressed: 2 · signal: 39 · noise: 37 · signal ratio: **0.527**
- Attack chains: **4** ['crypto_failure', 'intent_injection', 'permission_data_leak', 'webview_rce']
- Trust: **80/100 (HIGH)** · evidence 100% · source 97% · view-code 97% (n/a source: 6)
- Ownership certainty: 66% · breakdown: {'APPLICATION': 39, 'UNKNOWN': 25, 'GOOGLE_SDK': 4, 'THIRD_PARTY_LIBRARY': 3, 'ANDROID_FRAMEWORK': 3}
- False-positive rate: 2.6% · PDF: True (82 KB)
- ⚠️ below absolute target(s): ['trust_score=80 (need > 80)']

## Skipped (APK not present)

- **Signal** (real_world) — APK not found in /tmp/cortex
- **Firefox Android** (real_world) — APK not found in /tmp/cortex
- **Banking App (template)** (template) — template profile — supply an APK to run
- **Enterprise App (template)** (template) — template profile — supply an APK to run

## Cortex vs MobSF (capability matrix)

> MobSF column reflects documented capabilities, not a live run.

| Dimension | Cortex | MobSF | Notes |
|---|---|---|---|
| detection_coverage | 3/3 | 3/3 | Both cover manifest/code/cert/secrets/deps broadly. |
| evidence_quality | 3/3 | 2/3 | Cortex: exact file+line+snippet per finding. |
| view_code_quality | 3/3 | 1/3 | Cortex resolves findings to decompiled source + jump-to-line. |
| false_positive_rate | 3/3 | 1/3 | Cortex suppresses library/framework noise by ownership. |
| ownership_awareness | 3/3 | 0/3 | Cortex classifies app vs library/SDK/framework. |
| attack_chain_detection | 3/3 | 0/3 | Cortex correlates findings into exploit chains. |
| analyst_usability | 3/3 | 1/3 | Cortex adds reachability, exploitability, prioritization. |
| report_quality | 3/3 | 2/3 | Cortex: robust PDF + executive/trust summaries. |
| **TOTAL** | **24** | **10** | |

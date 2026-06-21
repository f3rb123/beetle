# Release Readiness — Phase 11.5

> Computed from the Tier-1 corpus (DVBA / InsecureShop / Washington Post) via the
> offline validation harness, plus static review of the container-only paths.

## Dimension scores

| Dimension | Score | Basis |
|-----------|------:|-------|
| Stability | 85 | Offline pipeline ran clean (exit 0, no crashes) on all 3; full pipeline unverified on this host |
| Determinism | 100 | Byte-deterministic across repeated runs on all 3; secret pipeline proven identical across Phases 9.1.5–10 |
| Coverage | 100 | Source resolution / evidence / view-code all **100 %** (goal >95 %) |
| False Positives | 85 | Suppression working (SDK/low-conf/refine); 0 unresolved, 0 view-code failures; noise classes documented |
| Performance | 75 | Bounded + capped; WaPo offline ~165 s; container JADX/APKTool timing + large-APK SLA still TBD |
| Export Reliability | 72 | Secrets masked + escaped (static PASS); PDF **render not executed here**; 1 low-risk strings-escaping item |

**Overall Release Readiness Score: 86 / 100**

## Tier: **BETA**

Although the numeric score sits at the BETA/RC boundary, the tier is held at
**BETA** because the gating RELEASE_CANDIDATE criteria are not yet met:

- ❌ Full pipeline (taint, Semgrep, manifest, LIEF) end-to-end validated in the
  container for the Tier-1 corpus.
- ❌ PDF render executed and confirmed (reportlab is container-only here).
- ❌ Benchmark baseline regenerated to include the Phase 9–11 additive keys.

What is already strong (RC-grade):

- ✅ Deterministic, network-free benchmark mode.
- ✅ 100 % source-resolution / view-code / evidence coverage on the corpus.
- ✅ HIGH trust scores (89 / 99 / 91) with no credential/key/token leaks.
- ✅ Working ownership suppression, secret pairing, masking, MASVS coverage, and
  analyst explanations on real APK data.

## Path to RELEASE_CANDIDATE (short)

1. Container CI job: run the three Tier-1 apps end-to-end; publish `scan_metrics`
   and a rendered PDF per app (closes Stability + Performance + Export gaps).
2. Regenerate + commit the benchmark baseline with the new result keys.
3. Close the LOW PDF strings-escaping item.
4. Decide + document the Firebase-URL-in-snippets masking policy.

Completing (1)–(2) is expected to move every gated dimension to ≥ 90 and the tier
to RELEASE_CANDIDATE.

# Source-Resolution Quality Report — Tier-1 Corpus

> Phase 11.5. Offline harness; `finding_model.validate_source_resolution`.

## Goal: > 95 % source resolution

| App | Source Res % | Evidence Coverage % | Source-applicable | classes.dex-attributed | Unknown ownership | Status |
|-----|-------------:|--------------------:|------------------:|-----------------------:|------------------:|:------:|
| DVBA | **100 %** | 100 % | 16 / 16 | 0 | ~56 % (obfuscation) | ✅ |
| InsecureShop | **100 %** | 100 % | 21 / 21 | 0 | ~5 % | ✅ |
| Washington Post | **100 %** | 100 % | 31 / 31 | 0 | ~45 % (obfuscation) | ✅ |

**All three exceed the >95 % goal at 100 % source resolution and 100 % evidence
coverage.**

## classes.dex findings

- **0** findings attributed to a raw `classes.dex` / binary-dump path across all
  three apps. The cross-section noise scrub (`finding_model.scrub_noise`) re-points
  any binary-dump evidence to the best non-binary source path, and the precise
  source scanner prioritizes jadx Java over smali/dex.

## Unknown ownership

- Ownership certainty is the one factor below 100 (trust factor: DVBA 44, WaPo 55,
  InsecureShop 95). The lower numbers track **ProGuard/R8 obfuscation** in DVBA and
  WaPo — obfuscated single/double-letter packages classify as `UNKNOWN` (kept
  visible, not suppressed). This is expected and is **not** a resolution failure:
  the source still resolves and renders; only the *package owner* is uncertain.
- InsecureShop (unobfuscated) reaches 95 % ownership certainty.

## Method

- `source_resolved = True` when the finding's `file_path` resolves to a persisted
  source file. Denominator = source-applicable findings (native/cert-metadata
  excluded).
- Evidence coverage = share of findings carrying at least one concrete evidence
  artifact (snippet, file_evidence, taint chain, or resolvable path).

## Caveats (container-only)

- Taint/Semgrep/manifest findings are not present in this offline harness; the real
  pipeline's resolution % should be re-confirmed in the container (Phase 8
  previously reported 100 % view-code on the full pipeline).

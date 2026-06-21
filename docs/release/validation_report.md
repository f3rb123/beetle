# Validation Report — Tier-1 Corpus

> Phase 11.5 release hardening. Generated from the offline validation harness
> (`.tools/release_harness.py`) over jadx-decompiled DVBA / InsecureShop /
> Washington Post, with `CORTEX_BENCHMARK=1` (deterministic, network-free).

## Harness scope (read first)

This board reflects the **offline-runnable** pipeline: regex SAST
(`code_analyzer`) + secret detection (`evidence_scanner`) + the full Phase 9–11
secret/exposure/MASVS/analyst stack + source resolution + trust score. The
following require the Docker container and are **not** measured here: taint
analysis (androguard), Semgrep, manifest-evidence enforcement, native/Mach-O
(LIEF), live validation/cloud probing (network), PDF render (reportlab), and the
real JADX/APKTool decompile timing. Those are flagged as "container-only" in the
relevant reports.

## Summary

| App | Trust | Src Res % | Evidence % | View Code % | Findings (kept) | App Secrets | Cred Pairs | MASVS Overall | Determinism |
|-----|------:|----------:|-----------:|------------:|----------------:|------------:|-----------:|--------------:|:-----------:|
| DVBA | **89 / HIGH** | 100 | 100 | 100 | 16 | 1 | 1 (Firebase) | 31 (weak) | ✅ |
| InsecureShop | **99 / HIGH** | 100 | 100 | 100 | 21 | 0 | 0 | 27 (weak) | ✅ |
| Washington Post | **91 / HIGH** | 100 | 100 | 100 | 31 | 3 | 1 (Firebase) | 21 (weak) | ✅ |

All three: Trust **HIGH**, source resolution / evidence / view-code **100 %**
(exceeds the >95 % goals), output **byte-deterministic** across repeated runs,
and **zero credential/key/token leaks**.

## Per-app detail

### DVBA — `com.app.damnvulnerablebank`
- Trust score **89 (HIGH)** — factors: evidence 100, source 100, ownership 44, chain 100.
- SAST findings 19 → 16 kept, 3 suppressed (refine).
- Secrets: 1 application secret; **Firebase configuration pair** (Google API key +
  Firebase URL), 1 validation candidate, 2 paired members hidden.
- Cloud exposures / attack chains: 0 (live probing OFF in benchmark mode).
- MASVS overall 31 (weak); weakest category **MASVS-NETWORK** (weak).

### InsecureShop — `com.insecureshop`
- Trust score **99 (HIGH)** — factors: evidence 100, source 100, ownership 95, chain 100.
- SAST findings 22 → 21 kept, 1 suppressed.
- Secrets: 0 detected by the current pattern set (see false-positive inventory —
  detection-coverage note, out of 11.5 scope).
- MASVS overall 27 (weak); weakest category **MASVS-PLATFORM** (weak).

### Washington Post — `com.washingtonpost.android`
- Trust score **91 (HIGH)** — factors: evidence 99, source 100, ownership 55, chain 100.
- SAST findings 33 → 31 kept, 2 suppressed.
- Secrets: 3 application secrets, **Firebase configuration pair**, 2 unpaired
  (lone Twilio SIDs, correctly not-eligible), **4 SDK secrets suppressed**,
  **3 low-confidence suppressed**.
- MASVS overall 21 (weak); weakest category **MASVS-NETWORK** (weak).

## Attack chains, secrets, MASVS

- **Attack chains:** cloud attack-path correlation requires live exposure
  confirmation (network), which is OFF in benchmark mode — so 0 chains here. The
  credential **pairs** (Firebase config pairs on DVBA + WaPo) are the chain
  precursors; with `CORTEX_ENABLE_CLOUD_INTELLIGENCE`/`_CORRELATION` they would be
  probed and correlated (validated synthetically in Phases 9.4/9.5).
- **Secrets:** masking, pairing, ownership suppression, and the executive summary
  all functioned on real APK data with no credential leakage.
- **MASVS:** all three apps score **weak** overall — consistent with deliberately
  vulnerable apps (DVBA, InsecureShop) and a large consumer app with broad
  third-party surface (WaPo).

## PDF export status

Render not executed here (reportlab is container-only). The PDF code path reads
the **masked** secret `value` field; static verification + the dedicated PDF
report cover this. See `pdf_validation_report.md`.

## Reproduce

```bash
# in the backend venv, with the three APKs decompiled under .tools/decompiled/
CORTEX_BENCHMARK=1 python .tools/release_harness.py
```

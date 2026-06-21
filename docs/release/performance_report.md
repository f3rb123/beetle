# Performance Report — Tier-1 Corpus

> Phase 11.5. Timings are from the **offline validation harness** on this host
> (Windows, Python 3.14, no container). They measure SAST + secret/exposure/MASVS/
> analyst + source-resolution over persisted jadx sources — **not** a real
> container scan. JADX/APKTool decompile timing is container-only.

## Offline-harness duration (analyze-lite)

| App | APK size | Offline analyze-lite | Notes |
|-----|---------:|---------------------:|-------|
| DVBA | 3.7 MB | ~13.6 s | small; dominated by SAST over ~2.2k decompiled files |
| InsecureShop | 4.6 MB | ~35.2 s | ~3.5k files |
| Washington Post | 86 MB | ~164.7 s | ~38.8k decompiled files; SAST file-walk dominates |

Durations include first-run source persistence (idempotent thereafter). They are
**not** comparable to container scan times — they exclude JADX/APKTool, taint
(androguard), and Semgrep, and include no parallelism tuning.

## JADX / APKTool duration

- **Container-only.** Measured separately during decompile for this corpus (jadx
  `-j 4 --no-debug-info`): DVBA and InsecureShop completed in well under a minute
  each; Washington Post (86 MB) was the long pole (still under the 8-minute budget
  used for decompile). Exact per-tool split is recorded by
  `decompiler.py` / `scan_metrics` in a real container run and should be captured
  there, not here.

## Large-APK performance

- Washington Post (86 MB → 38.8k decompiled files) is the corpus stress case.
  Offline analyze-lite scaled roughly linearly with file count; the evidence/SAST
  walkers honor `CORTEX_EVIDENCE_MAX_FILES` (15k) and `_SAST_MAX_FILES` caps, so
  worst-case work is bounded.
- **Recommendation:** capture `results["scan_metrics"]` (per-module durations) from
  a container run of WaPo to set a real large-APK SLA; the harness here cannot
  measure JADX heap behavior or the `mem_limit` (6 GB) OOM boundary.

## Bounds already in place

- Evidence/secret walk: `CORTEX_EVIDENCE_MAX_FILES=15000`, 2 MB/file cap.
- SAST: `_SAST_MAX_FILES`, per-file byte cap, stdlib-prefix skips.
- Scan queue: `ThreadPoolExecutor(max_workers=3)`.
- JADX heap: `CORTEX_JADX_HEAP` (kept below the 6 GB container `mem_limit`).

## Open items

- [ ] Capture real per-module timing (`scan_metrics`) for all three in the container.
- [ ] Record JADX vs APKTool split for WaPo.
- [ ] Establish a large-APK duration SLA + alert threshold.

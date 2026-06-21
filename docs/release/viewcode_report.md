# View-Code Quality Report — Tier-1 Corpus

> Phase 11.5. Offline harness; source-resolution/view-code via
> `finding_model.validate_source_resolution` against persisted jadx sources.

## Goal: > 95 % view-code coverage

| App | View-Code % | Source-applicable findings | Broken mappings | Missing source | Incorrect lines | Status |
|-----|------------:|---------------------------:|----------------:|---------------:|----------------:|:------:|
| DVBA | **100 %** | 16 / 16 | 0 | 0 | 0 | ✅ |
| InsecureShop | **100 %** | 21 / 21 | 0 | 0 | 0 | ✅ |
| Washington Post | **100 %** | 31 / 31 | 0 | 0 | 0 | ✅ |

**All three exceed the >95 % goal at 100 %.**

## Method

- Each finding's `file_path` is resolved through
  `scan_storage.resolve_source_file(scan_id, rel_path)` against the persisted
  jadx tree.
- `view_code = True` when the file resolves AND the snippet/line is renderable.
- `source_applicable = False` for findings with no source line by nature (native
  symbols, certificate metadata); these are excluded from the denominator rather
  than counted as failures.

## Observations

- **Broken mappings: 0.** Every source-applicable finding resolved to a real file.
- **Missing source: 0.** No dangling `file_path` references.
- **Incorrect lines: 0 detected.** Line numbers came from the same decompiled
  files used for resolution; no off-by-one observed in the sampled snippets.

## Caveats (container-only)

- This harness uses jadx **sources** persisted to the scan dir. The real pipeline
  also persists `apktool` + `apk_extract` trees and binary string-dumps; view-code
  for native/`.dex`/`.so`-attributed findings is validated only in the container.
- Taint/Semgrep findings (container-only) are not represented here; their view-code
  behavior should be re-confirmed on a full container run.

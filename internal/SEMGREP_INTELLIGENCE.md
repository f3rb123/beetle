# Semgrep Intelligence Integration (Beetle 2.0 — Phase 2.4)

> Semgrep is integrated as **another detection source**, exactly like APKLeaks — never a
> parallel pipeline. Beetle owns **intelligence**; Semgrep owns **detection**; a thin
> **adapter** isolates Beetle from Semgrep's internals.
>
> `Rules → Semgrep Engine → Semgrep Adapter → Canonical Findings → the one pipeline`
> (Finding Fusion · Ownership · Confidence · Evidence · Attack Chains · Bug Bounty ·
> Source/Security Explorer · Reports).

---

## 1. Architecture

```
analyzers/sast/
  config.py           central, data-driven rule-pack registry + project detection
  adapter.py          SastAdapter ABC (future-engine seam) + sarif_to_canonical (SARIF→Canonical)
  semgrep_adapter.py  SemgrepAdapter: execute Semgrep, parse SARIF, convert. ONLY that.
analyzers/semgrep_runner.py   thin back-compat shim → analyzers.sast.semgrep
```

The adapter does **only** what the spec allows — execute the engine, parse output,
normalize, convert to canonical findings — and **nothing else** (no vendored rules, no
copied logic, no Semgrep-specific reporting). Beetle never embeds or modifies Semgrep
rules; a "pack" is just a `--config` value Semgrep resolves itself.

---

## 2. Execution flow

```
android_analyzer / ios_analyzer  (gated on semgrep availability — cached)
  → semgrep_runner.run_semgrep(scan_dirs, results, platform, framework)
      → SemgrepAdapter.run_into(results, …)
          available()?           cached shutil.which — instant skip when absent
          configs_for_project()  project detection → only relevant rule packs
          subprocess semgrep --sarif --config … <dirs>   (timeouts, --jobs, --max-memory)
          sarif_to_canonical()   → canonical findings (detected_by:["Semgrep"])
      results["findings"] += findings          (no cross-engine de-dup here)
  → unchanged finalize: Fusion → Ownership → Confidence → Evidence → … → Reports/Explorer
```

Android runs it after native SAST; iOS runs it after `run_ios_sast`. Both pass the
detected `framework`, so a Flutter/React-Native app runs the Dart/JS-relevant packs too.

---

## 3. The adapter & canonical conversion

`sarif_to_canonical(sarif, scan_dirs, source_name)` (engine-agnostic) preserves exactly
what the spec lists and nothing else:

| Preserved | From SARIF |
|---|---|
| Rule ID / Rule Name | `result.ruleId`, `rule.name` |
| Message / Description | `result.message.text`, `rule.fullDescription` |
| Severity | `result.level` → high/medium/low |
| File / Line / Snippet | `physicalLocation` |
| CWE | `rule.properties.cwe` / tags / message |
| OWASP / MASVS | tag mapping |
| References | `rule.properties.references` + `helpUri` |
| Metadata | `rule.properties.tags`, engine name |

It stamps `detected_by:["Semgrep"]` / `source_module:"Semgrep"` so Finding Fusion credits
the engine. It de-dups only **within** one engine's output (rule+file+line); cross-engine
merge is Fusion's job — never a silent drop.

---

## 4. Finding Fusion (no duplicates)

Canonical Semgrep findings carry `detected_by` + CWE, so the **Finding Fusion Engine's**
semantic identity (CWE + file + line-bucket, with the Phase-1.95 broad-CWE guard) merges a
Semgrep finding that overlaps a Beetle-native / APKLeaks one into **ONE** canonical
finding **"Detected By ✓ Beetle Native ✓ APKLeaks ✓ Semgrep."** The old runner's local
pre-drop (which silently discarded such overlaps) was removed so Fusion is the single
de-dup authority.

---

## 5. Source Explorer navigation

Automatic and free: Semgrep findings carry `file_path`/`line`, so `source_explorer.annotate`
indexes them (tree badges + Security-Explorer category) and the existing
`nav.openSource` / `explorerTarget` seam expands the tree → opens the file → jumps to the
line → highlights the snippet. No Semgrep-specific navigation.

---

## 6. Rule configuration (no code change to add packs)

`sast/config.py` is the central, data-driven registry. A pack = `{id, tier, config,
languages, enabled}` across tiers **Official → Enterprise → Organization → Community →
Experimental**. **Project detection** maps platform/framework → languages and selects only
the relevant packs (Android → java/kotlin/android, iOS → swift, Flutter → +dart\*, React
Native → +js/ts), so an iOS scan never runs Java rules. Configuration surfaces — **no code
change required**:

| Env / file | Effect |
|---|---|
| `CORTEX_SEMGREP_PACKS` | whitelist pack ids |
| `CORTEX_SEMGREP_DISABLE_PACKS` | disable pack ids |
| `CORTEX_SEMGREP_EXTRA_CONFIG` | add org/enterprise `--config` values (paths/URLs) |
| `CORTEX_SEMGREP_CONFIG_FILE` | JSON of additional/override packs |
| `CORTEX_SEMGREP_TIMEOUT` / `…_MAX_FINDINGS` | runtime caps |

\* Semgrep ships no official Dart pack today; the Dart language is a reserved seam — add a
pack via config when one exists, no code change.

---

## 7. Performance

`available()` is **cached** (one `shutil.which`), so a scan without Semgrep on PATH
short-circuits with zero subprocess cost — the existing Android/iOS scan performance is
unchanged. Only project-relevant packs run (no wasted Java scan on iOS). Per-file +
overall timeouts, `--max-memory` and `--jobs` bound the run; it executes after native SAST
and never blocks the core pipeline.

---

## 8. Future extensibility (seams only — not implemented)

* **`SastAdapter` ABC** — any future engine (CodeQL, other SAST) implements
  `available / languages_for / run` and is wired exactly like Semgrep; the Canonical
  Finding Pipeline never changes.
* **`sarif_to_canonical`** — engine-agnostic, so it is the **SARIF-import** seam: any tool
  that emits SARIF becomes a source by passing output through it (proven by a `source_name="CodeQL"`
  test).
* **Reserved config fields** (documented, not acted on): `priority` (rule-pack priorities),
  `offline_path` (offline rule bundles), `version` (rule version management / pins), `repo`
  (organization rule repositories), plus automatic rule updates and custom rules via the
  same config surfaces.

---

## 9. Engineering Workspace

The Semgrep card (`engineering-modules.js`) is flipped to **`AVAILABLE`**. Semgrep is a
detection source that runs automatically during a scan, so the card is a navigation module
(`nav: 'findings'`) that opens the latest scan's findings, where Semgrep results appear
credited as "Detected By: Semgrep." No workspace redesign.

---

## 10. Testing

`backend/tests/test_semgrep_adapter.py` (12 tests, **no Semgrep binary required**):
project-aware pack selection (Android/iOS/Flutter/RN, no unnecessary scans), SARIF →
canonical conversion (Rule ID/Name/Severity/File/Line/CWE/OWASP/References/`detected_by`
preserved), severity mapping, **Finding Fusion** merge of a Semgrep+native duplicate (one
finding, both engines credited) and non-over-merge, flow through the **real** Ownership /
Confidence / Evidence / **Source Explorer** engines, **configurable packs** via env, the
**SARIF-import seam** for future engines, and graceful zero-cost no-op when Semgrep is
absent. Full suite **361 passed**; frontend build green.

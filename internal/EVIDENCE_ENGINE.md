# Beetle 2.0 — Unified Evidence Intelligence Engine

**Phase:** 1.5 · **Branch:** `beetle-2.0` · **Scope:** evidence quality only.

> *"A security finding is only as valuable as the evidence supporting it."*

The Evidence Engine makes evidence a **first-class, structured, reusable**
component. For every finding it builds one aggregated, multi-source `Evidence`
bundle — typed evidence items with quality, verification status, reproduction
steps, correlation, a data-flow view and a deterministic content hash — so every
finding is explainable, reproducible and easy to verify by humans, AI,
consultants and bug bounty hunters.

This phase **only** improves evidence representation: no new detectors, no
suppression, no filtering, no severity/report/UI changes.

---

## 1. Architecture

```
analyzers/evidence/
  __init__.py   public API (build, annotate, get_engine, EvidenceEngine, …)
  config.py     THE tuning file — evidence types, sources, ext→type map,
                per-source confidence, quality/verification thresholds
  model.py      EvidenceItem + Evidence dataclasses (the structured model)
  engine.py     logic — collection, classification, scoring, aggregation, annotate()
```

Same shape as the Ownership/Confidence/Secret engines: pure, deterministic,
cached singleton; data in `config.py`, model in `model.py`, logic in `engine.py`.

### Where it lives on a finding
A new `evidence_bundle` dict on `CanonicalFinding` (named so it never collides
with the legacy string `evidence` snippet or the `file_evidence` list — **both
preserved**). The bundle is the structured, normalized view; the loose fields
remain for backward compatibility.

---

## 2. The unified evidence model

**`EvidenceItem`** — one verifiable piece of evidence:
`id, type, source, confidence, file_path, relative_path, line, column,
end_line/end_column (highlighted region), snippet, decompiler_status,
source_availability, generated_code, locator{class, method, package, namespace,
component, permission, intent, uri, deep_link, resource_name, property, field,
function, native_library, swift_module, objc_class, jni_library, source, sink,
caller, callee}, metadata`.

The long, sparse list of named locations lives in `locator` (a dict), so new
locator kinds are added without breaking compatibility.

**`Evidence`** — the aggregated bundle: `evidence_id, version, items[], primary,
evidence_types[], sources[], quality, quality_reason, verification_status,
verification_reason, source_availability, generated_code, reproducible,
reproduction{}, correlation[], data_flow{}, cross_references[], ownership{},
confidence{}, secret{}, content_hash, timestamp, item_count, location_count`.

### Evidence types
SourceCode, DecompiledJava, Kotlin, Smali, Swift, ObjectiveC, Manifest,
InfoPlist, ResourceXML, StringsXML, NetworkSecurityConfig, JSON, YAML, Gradle,
Configuration, Properties, Database, SharedPreferences, Assets, RawResources,
Binary, MachO, DEX, NativeLibrary, JNI, Certificate, CodeSignature, WebView,
JavaScript, HTML, CSS, SQL, CallGraph, TaintFlow, Dependency, APK/IPA-Metadata,
Flutter, ReactNative, Cordova, Capacitor, Unity, Secret, Unknown. Type is
resolved from basename → path token → extension → finding category.

---

## 3. Evidence lifecycle

```
finding (dict)
  → CanonicalFinding.from_legacy()
     → collect_items()      file_evidence / file_path+snippet / taint chain /
                            manifest / certificate / secret-metadata → typed items
        → classify type + source + decompiler status + availability
        → score each item   (source prior + line/snippet/symbol/region; unresolved cap)
        → aggregate         quality · verification · reproduction · correlation ·
                            data-flow · cross-refs · content hash
           → Evidence.to_dict() → finding["evidence_bundle"]
```

`annotate(results)` runs in both orchestrators **after** ownership and confidence
(so it can summarize their metadata), guarded, additive-only. It also emits
`results["evidence_summary"]` (quality distribution).

---

## 4. Collection & aggregation (multi-source — never overwrite)

A finding can carry evidence from many places; the engine **aggregates** them
into deduplicated items rather than overwriting:
* every `file_evidence` entry → a code/resource item (N items, N locations);
* a taint/call chain → a `TaintFlow` item with entry/exit/path;
* manifest-derived findings → a `Manifest`/`InfoPlist` item (with the real
  manifest path even when the finding carried none);
* certificate findings → a `Certificate` item;
* secret findings → a `Secret` item linking the Phase 1.4 assessment.

`cross_references` lists the non-primary locations; `location_count` counts
distinct (file, line) pairs.

---

## 5. Correlation

Deterministic relationships a reviewer would draw by hand are emitted as
`correlation` edges between items: `manifest_declares_source` (an exported
component's manifest entry ↔ its implementing class), `same_class`,
`source_participates_in_flow` (source line ↔ taint flow), `same_file`. This
realizes the *Manifest → Activity → Source → Intent → Permission → Deep Link*
and *Secret → BuildConfig → Package → Ownership* chains from the brief, on the
evidence already present (Git-history and dynamic correlation are future inputs).

---

## 6. Quality model

| Quality | Meaning |
|---------|---------|
| Excellent | exact file + line + snippet + symbol, source resolved — reproducible by line |
| Good | exact file + line + snippet (no symbol), or a manifest line |
| Moderate | located evidence without a pinned line, class-level, or a taint chain |
| Weak | reference/heuristic location only, no verifiable snippet |
| Missing | no evidence at all |

The band is decided structurally (with an explanation) and **capped by the
primary item's numeric confidence** so it never over-claims. Every decision
carries `quality_reason`.

---

## 7. Verification

`Verified` (resolved source + exact line + snippet) · `Partially Verified` ·
`Decompiler Only` · `Manifest Only` · `Binary Only` · `Generated` (machine-
generated code) · `Needs Review` (a claimed location could not be resolved) ·
`Unknown`. Each carries `verification_reason`.

---

## 8. Reproducibility

`reproduction` gives an analyst the exact recipe: `file, line, class, method,
manifest_entry, call_path, snippet` plus tailored `steps` (decompile→open→line
for code; decode-manifest→locate-entry for manifest; extract→inspect-symbol for
binary; source→path→sink for taint). `reproducible` is true for Excellent/Good
items with a file+line.

---

## 9. Determinism & hashing

Pure and deterministic: same finding → identical bundle. `content_hash` is the
SHA-256 of the normalized item set (type|file|line|snippet) and seeds
`evidence_id` (`EV-<hash[:12]>`, or `EV-empty`). The only injected value is the
scan **timestamp** (from scan metadata), which is excluded from the hash so the
hash stays stable across re-scans of the same artifact — ideal for a golden
regression suite.

---

## 10. Extensibility & future integration

* New evidence type / file kind → one line in `config.py`.
* New locator kind → a key in `EvidenceItem.locator` (no schema change).
* New collection source (e.g. runtime) → add an item producer in `collect_items`.

| Consumer | Uses the evidence bundle for |
|----------|------------------------------|
| **SDK Suppression** | `verification_status` + ownership to group library/framework evidence |
| **Bug Bounty Mode** | surface only Excellent/Good, Verified, reproducible findings |
| **Attack Chain v2** | `correlation` + `data_flow` to build evidence-linked chains |
| **AI Reviewer** | feed items + reproduction + verification as grounded context |
| **Report Engine v2** | typed evidence cards, "how to reproduce", quality/verification badges |
| **Dynamic Analysis / Frida / Objection** | attach runtime items to the same bundle (new source), corroborating static evidence |
| **Golden Regression Suite** | `content_hash` to detect evidence drift between releases |

---

## 11. Compatibility & testing

* **Additive only.** `annotate()` writes `evidence_bundle` (and the scan-level
  `evidence_summary`); the loose `file_evidence` / `snippet` / `evidence` fields,
  severity, suppression, reports and the UI are untouched.
* **Tests:** `backend/tests/test_evidence_engine.py` (23 cases) — Android/iOS,
  decompiled Java/Kotlin/Swift/Obj-C/smali, manifest/permission/deep-link/
  exported-component, taint/data-flow, certificate, binary-only/native,
  Flutter/RN/Cordova/Capacitor/Unity, WebView, secrets, generated/obfuscated/
  unresolved, multi-source aggregation, correlation, reproduction, determinism,
  and the non-destructive guarantee. Runnable on stdlib or pytest. The Phase
  1.1/1.15/1.2/1.3/1.4 suites continue to pass.

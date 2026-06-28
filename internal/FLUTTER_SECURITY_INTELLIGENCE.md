# Flutter Security Intelligence (Beetle 2.0 — Phase 2.1)

> Makes Flutter a **first-class Beetle platform** by integrating into the existing
> intelligence pipeline — **not** by building a parallel one. A Flutter app is just an
> Android APK (`libflutter.so` + `libapp.so` + `flutter_assets`) or an iOS IPA
> (`Flutter.framework` + `flutter_assets`), so Flutter analysis is a **sub-analyzer**
> inside the current Android/iOS flow, exactly like the React Native bundle analyzer.

---

## 1. Architecture

```
APK / IPA → existing Android / iOS analyzer
   ├─ framework detection (already present): framework == "flutter"
   │        ↓ (gated)
   ├─ flutter_analyzer.analyze(roots, results, platform)   ← NEW sub-analyzer
   │        contributes to the EXISTING streams:
   │          results["findings"]   (canonical dicts, Detected By "Flutter Intelligence")
   │          results["secrets"]    (via reused scan_text_for_secrets)
   │          results["endpoints"]  (via reused extract_urls)
   │          results["flutter"]    (metadata: deps, channels, project structure)
   └─ unchanged finalize pipeline runs over those streams:
        Ownership → Confidence → Evidence → Evidence Selection → Finding Fusion →
        Triage → Attack Chains → Bug Bounty → Network Intelligence → Reports
```

`analyzers/flutter_analyzer.py` is the only new backend module. It calls **no**
intelligence engine itself — it just produces canonical-shaped detections and lets the
existing engines do their job, so Flutter findings are treated identically to
Android/iOS findings. The public entry point `analyze(roots, results, platform=…)`
accepts **arbitrary roots**, so a future "Flutter project source directory" input is a
thin add-on, not a rewrite.

Integration points (gated on the pre-existing `framework == "flutter"` flag):
* Android: `android_analyzer.py`, immediately after `_analyze_rn_bundle`.
* iOS: `ios_analyzer.py`, after framework detection completes.

Both are wrapped in `try/except` — a Flutter failure never breaks a scan.

---

## 2. Flutter detection

The Android/iOS analyzers already classify `framework == "flutter"` via
`libflutter.so` / `libapp.so` (Android) and the `flutter_assets` directory (iOS). The
sub-analyzer runs only then. `flutter_analyzer.detect(roots)` adds a standalone check
(`pubspec.yaml` declaring the Flutter SDK, or any Flutter artifact) used by the tests
and the future source-directory path.

**Analysis sources** (whichever are present): `pubspec.yaml` / `pubspec.lock`, `.dart`
source (source-dir / debug builds), `flutter_assets` (`AssetManifest.json`,
`kernel_blob.bin`), and the **printable strings of `libapp.so` / the App snapshot**
(release AOT Dart) via the existing `_printable_strings` helper. Harvesting is bounded
(file count / size caps) so a pathological app cannot stall the scan.

---

## 3. Finding generation

A small **data-driven rule catalog** (regex → canonical finding) covers the spec's
surface; adding coverage is adding a tuple, not logic:

| Area | Detected |
|---|---|
| **Platform channels** | `MethodChannel` / `EventChannel` / `BasicMessageChannel` (+ channel name) — native bridge attack surface |
| **Storage** | Flutter Secure Storage (good), SharedPreferences (plaintext), unencrypted `Hive.openBox`, SQLite/`sqflite` |
| **Network** | `badCertificateCallback => true` / `onBadCertificate => true` (TLS validation disabled, **high**), Dio client, WebSocket / `ws://` |
| **Build/debug** | `kDebugMode` branches, sensitive logging |
| **Dependencies** | pubspec inventory + capability labels (Dio, Hive, Firebase, …) |

Every finding is a canonical dict — `title / severity / category / description /
recommendation / file_path / line / snippet / cwe / masvs` — tagged
`detected_by: ["Flutter Intelligence"]` and `source_module: "Flutter Intelligence"` so
**Finding Fusion** renders the correct "Detected By".

**Secrets** are NOT detected by a Flutter-specific detector: harvested Dart text is
passed to the existing `scan_text_for_secrets`, and the hits enter `results["secrets"]`
where the **Secret Intelligence Engine v2** classifies, scores, masks and fuses them
like any other secret.

---

## 4. Pipeline integration (how Flutter findings become Canonical Findings)

Because the analyzer only appends to `results["findings"]` / `["secrets"]` /
`["endpoints"]`, the **unchanged** finalize phase processes them automatically:

* **Ownership** — each finding's `file_path` is classified by the Ownership Engine.
* **Confidence** — explainable per-finding confidence (incl. multi-engine agreement).
* **Evidence / Evidence Selection** — the best proof file + snippet are chosen.
* **Finding Fusion** — dedup + "Detected By"; a Flutter finding that overlaps a native
  detection fuses into one canonical finding crediting both engines.
* **Triage / Attack Chains / Bug Bounty / Reports** — all run unchanged.
* **Network Intelligence** — Flutter endpoints/IPs flow through the existing URL/IP
  model.

Result: a Flutter finding in a report shows **Detected By, Owner, Confidence, Evidence,
Attack Chain, Bug Bounty, Source** — exactly like Android/iOS, with no separate
reporting model. This is proven in the tests, which run the real Fusion / Ownership /
Confidence / Evidence Selection engines over generated Flutter findings.

---

## 5. Future Source Explorer support

This phase **exposes the metadata** a future tree-view needs, but does **not** build the
explorer. `results["flutter"]` carries:

```
detected, platform, build_mode (debug/release), has_libapp_snapshot,
has_flutter_assets, dart_source_files, dependencies, dependency_capabilities,
platform_channels, has_pubspec, has_pubspec_lock,
project_structure: { lib, assets, android, ios, test, windows, linux, macos, web },
key_files: { "pubspec.yaml", "pubspec.lock" },
stats: { findings, secrets, endpoints }
```

`project_structure` preserves the canonical Flutter project directories so a future
Source Explorer can render the tree directly from scan metadata. For compiled APK/IPA
inputs most source dirs are absent (Dart is AOT-compiled into `libapp.so`); for a
future source-directory input they are populated from the real tree — the same metadata
shape either way.

---

## 6. Engineering Workspace

The Flutter card (`frontend/src/lib/engineering-modules.js`) is flipped from
`COMING_SOON` to **`AVAILABLE`** with a launch descriptor (`accept: '.apk,.ipa'`,
`platform: 'flutter'`). Flutter ships as an APK or IPA, so it reuses the existing upload
+ auto-detection workflow with zero workspace redesign — exactly the extensibility the
Phase 2.0 config model was built for.

---

## 7. Testing

`backend/tests/test_flutter_intelligence.py` (14 tests): detection / non-detection,
MethodChannel + EventChannel + BasicMessageChannel, pubspec parsing (SDK pseudo-dep
excluded), storage (Secure Storage / SharedPreferences / Hive / SQLite), secrets reuse,
network (endpoints + TLS-validation-disabled + WebSocket), canonical-finding shape, and
**flow through the real Fusion / Ownership / Confidence / Evidence Selection engines**,
plus Source Explorer metadata and empty-input safety. The full suite (**326 passed**)
confirms no Android/iOS regression.

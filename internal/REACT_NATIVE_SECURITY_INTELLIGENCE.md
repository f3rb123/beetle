# React Native Security Intelligence (Beetle 2.0 — Phase 2.2)

> Makes React Native a **first-class Beetle platform** exactly the way Flutter is — a
> SUB-ANALYZER inside the existing Android/iOS flow, gated on the pre-existing
> `framework == "react_native"` detection, contributing canonical findings to the one
> shared intelligence pipeline. **No separate React Native pipeline.**

---

## 1. Architecture

```
APK / IPA → existing Android / iOS analyzer
   ├─ framework detection (already present): framework == "react_native"
   │        ↓ (gated)
   ├─ react_native_analyzer.analyze(roots, results, platform)   ← NEW sub-analyzer
   │        contributes to the EXISTING streams:
   │          results["findings"]   (canonical dicts, Detected By "React Native Intelligence")
   │          results["secrets"]    (via reused scan_text_for_secrets)
   │          results["endpoints"]  (via reused extract_urls)
   │          results["react_native"] (metadata: deps, native modules, project structure)
   └─ unchanged finalize pipeline runs over those streams:
        Ownership → Confidence → Evidence → Evidence Selection → Finding Fusion →
        Triage → Attack Chains → Bug Bounty → Network Intelligence → Reports
```

`analyzers/react_native_analyzer.py` is the only new backend module, modeled directly
on `flutter_analyzer.py`. It calls **no** intelligence engine itself — it produces
canonical detections and lets the existing engines do the work, so RN findings are
treated identically to Android/iOS/Flutter findings.

**Relationship to the existing JS modules (no duplication):**
* Bundle **discovery** is reused from `js_bundle_analyzer.find_js_bundles` — not
  re-implemented.
* **Generic** JS dangerous sinks (`eval` / `Function` / `dangerouslySetInnerHTML`) stay
  in `js_bundle_analyzer` (which runs for every app and is unchanged).
* This module adds the **RN-idiomatic** security analysis and **replaces** the weak
  inline `_analyze_rn_bundle` (now removed).

Integration points (gated on `framework == "react_native"`, `try/except` wrapped):
* Android: `android_analyzer.py` (where `_analyze_rn_bundle` used to be called).
* iOS: `ios_analyzer.py`, beside the Flutter hook.

---

## 2. Framework detection

The Android/iOS analyzers already classify `framework == "react_native"`
(`libreactnativejni.so` / `index.android.bundle` on Android; `main.jsbundle` /
`index.ios.bundle` on iOS). The sub-analyzer runs only then.
`react_native_analyzer.detect(roots)` adds a standalone check (a `package.json`
depending on `react-native`, or any RN bundle/marker) for the tests and the future
source-directory path.

**Analysis sources** (whichever are present): JS/Hermes bundles (located via the reused
`find_js_bundles`), `package.json`, `metro.config.js` / `babel.config.js`, `.env`, and
`.js`/`.jsx`/`.ts`/`.tsx` source. Hermes bytecode is detected and recorded; its string
literals (URLs, identifiers, channel names) are pattern-matched. Harvesting is bounded
(file count / size caps).

---

## 3. Finding generation

A data-driven rule catalog (regex → canonical finding) covers the spec's surface:

| Area | Detected |
|---|---|
| **Native bridge** | `NativeModules.<X>` (+ name), `TurboModuleRegistry`/TurboModules, `requireNativeComponent`/`codegenNativeComponent` (Fabric), `NativeEventEmitter` |
| **Storage** | AsyncStorage (plaintext), `new MMKV()` without `encryptionKey`, Realm without `encryptionKey`, SQLite/WatermelonDB, EncryptedStorage/SecureStore/Keychain (good) |
| **Network** | `rejectUnauthorized:false` / `trustAllCerts` (TLS disabled, **high**), `react-native-ssl-pinning` (pinning present), axios, WebSocket / `ws://` |
| **Platform** | Deep links (`Linking.*`), Firebase, environment config (`react-native-config` / `process.env`), `__DEV__` |
| **Dependencies** | `package.json` inventory + capability labels |

Every finding is a canonical dict (`title / severity / category / description /
recommendation / file_path / line / snippet / cwe / masvs`) tagged
`detected_by: ["React Native Intelligence"]` so **Finding Fusion** renders the correct
"Detected By".

**Secrets** are NOT detected by an RN-specific detector: harvested bundle/source text is
passed to the existing `scan_text_for_secrets`, and hits enter `results["secrets"]` where
the **Secret Intelligence Engine v2** classifies, scores, masks and fuses them.

---

## 4. Pipeline integration (how RN findings become Canonical Findings)

Because the analyzer only appends to `results["findings"]` / `["secrets"]` /
`["endpoints"]`, the **unchanged** finalize phase processes them automatically: Ownership,
Confidence (incl. multi-engine agreement), Evidence + Evidence Selection, **Finding
Fusion** (dedup + "Detected By"; an RN finding overlapping a native detection fuses into
one finding crediting both engines), Triage, Attack Chains, Bug Bounty, Reports, and
Network Intelligence over RN endpoints/IPs.

A React Native finding in a report therefore shows **Detected By, Owner, Confidence,
Evidence, Attack Chain, Bug Bounty, Source** — exactly like Android/iOS/Flutter, with no
separate reporting model. The tests prove this by running the real Fusion / Ownership /
Confidence / Evidence Selection engines over generated RN findings.

---

## 5. Source Explorer preparation

`results["react_native"]` exposes the metadata a future tree-view needs (the explorer
itself is NOT built here):

```
detected, platform, hermes, bundles, src_files, dependencies,
dependency_capabilities, native_modules, has_package_json,
project_structure: { android, ios, src, app, assets, node_modules },
key_files: { "package.json", "metro.config.js", "babel.config.js" },
stats: { findings, secrets, endpoints }
```

`project_structure` preserves the canonical RN project directories. For compiled APK/IPA
inputs most source dirs are absent (logic is in the JS/Hermes bundle); for a future
source-directory input they are populated from the real tree — the same metadata shape
either way.

---

## 6. Engineering Workspace

The React Native card (`frontend/src/lib/engineering-modules.js`) is flipped from
`COMING_SOON` to **`AVAILABLE`** with a launch descriptor (`accept: '.apk,.ipa'`,
`platform: 'react_native'`). RN ships as an APK or IPA, so it reuses the existing upload
+ auto-detection workflow with zero workspace redesign — the same one-field enablement
the Phase 2.0 config model was built for, identical to how Flutter was enabled.

---

## 7. Testing

`backend/tests/test_react_native_intelligence.py` (14 tests): detection / non-detection,
bundle + Hermes metadata, NativeModules + TurboModules, storage (AsyncStorage / MMKV /
Realm / SQLite / secure), secrets reuse, network (endpoints + TLS-disabled + axios +
WebSocket), `package.json` parsing, canonical-finding shape, and **flow through the real
Fusion / Ownership / Confidence / Evidence Selection engines**, plus Source Explorer
metadata and empty-input safety. The full suite (**340 passed**) confirms no Android/iOS
regression, and the weak inline `_analyze_rn_bundle` was removed (no duplication).

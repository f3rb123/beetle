# Beetle 2.0 — Ownership Engine

**Phase:** 1.2 · **Branch:** `beetle-2.0` · **Scope:** ownership classification only.

The Ownership Engine answers one question for every finding: **who owns the code
this points at?** — Application, ThirdPartySDK, AndroidFramework, GoogleSDK,
AppleFramework, VendorSDK, OpenSourceLibrary, GeneratedCode, or Unknown — with an
explainable reason and confidence. It is the substrate that Confidence Scoring,
SDK Suppression, Bug Bounty Mode, Attack Chains, the AI Reviewer and the Report
Engine will all read.

This phase **only** classifies. It does not filter, suppress, score findings, or
change severity.

---

## 1. Architecture

```
analyzers/ownership/
  __init__.py        public API (classify, enrich, annotate, OwnershipEngine, …)
  types.py           OwnerType, Stage, Confidence, OwnershipResult, OwnershipContext
  fingerprints.py    DATA — the fingerprint database (no logic)
  engine.py          multi-stage classifier + signal derivation + pipeline glue
```

Separation of concerns is deliberate: **`fingerprints.py` is data, `engine.py`
is logic.** Adding or correcting an SDK never requires touching the engine.

The engine is a pure, reusable service. Build once (`get_engine()` caches a
process-wide singleton with pre-built indices) and classify many. It has no
network calls and no side effects except `annotate()`, which writes ownership
fields back onto findings additively.

### Ownership metadata on `CanonicalFinding`

```
owner_type             OwnerType value, e.g. "ThirdPartySDK"
owner_name             "AndroidX WorkManager"
owner_confidence       0-100, explainable
owner_reason           "Matched SDK fingerprint"
matched_package_prefix "androidx.work"
matched_rule           "fp:AndroidX WorkManager"
matched_signature      the concrete signal matched (prefix / class prefix / path token)
classification_stage   "Exact Fingerprint"
```
(plus convenience `sdk_name` / `framework_name` / `package_prefix` when relevant).

---

## 2. Pipeline

```
finding (dict)
   └─ CanonicalFinding.from_legacy()          # canonical model (Phase 1.1/1.15)
        └─ derive_signals()                   # package / class / path / platform
             └─ OwnershipEngine.classify()    # layered stages → OwnershipResult
                  └─ result.to_fields()       # additive owner_* keys
                       └─ dict.update(finding) # legacy dict at the edge
```

`annotate(results)` is wired into both orchestrators' finalize step
(`android_analyzer` / `ios_analyzer`), right after the finding set is finalized,
following the established `analyst_intel`/`masvs_intel` annotation pattern. It is
guarded — a failure logs and leaves findings without ownership metadata rather
than breaking the scan. It enriches both `findings` and `suppressed_findings`,
and emits `results["ownership_summary"]`.

---

## 3. Fingerprint database

Each record (built by `fp(...)`) carries:

| field | purpose |
|-------|---------|
| `name` | human owner name |
| `type` | `OwnerType` value |
| `platform` | `android` / `ios` / `both` — gates matching to prevent cross-platform false positives |
| `confidence`, `stage`, `reason` | explainability (sensible per-type defaults) |
| `package_prefixes` | dotted prefixes (Android/JVM/Kotlin packages **and** Swift module names) |
| `class_prefixes` | Obj-C / Swift class-name prefixes (`FIR`, `NS`, `AF`, …) |
| `path_tokens` | substrings expected in a `file_path` (`/Alamofire.framework/`, `libflutter.so`) |
| `framework_name`, `sdk_name` | convenience labels |

Coverage (140+ records): Android & JVM/Kotlin runtime; AndroidX/Jetpack (per
module + catch-all); Google (Play Services, Firebase, Crashlytics, Maps, ML Kit,
Material, AdMob, SafetyNet, Sign-In); open source (OkHttp, Retrofit, Okio,
BouncyCastle, Jackson, Gson, Moshi, RxJava, Dagger/Hilt, Koin, Glide, Picasso,
Coil, LeakCanary, Timber, gRPC, protobuf, ExoPlayer, …); hybrid frameworks
(React Native, Flutter, Cordova, Capacitor, Ionic, Unity, Xamarin/.NET MAUI,
NativeScript, KMP); vendor SDKs (Lookout, Branch, Adjust, AppsFlyer, OneSignal,
MoEngage, CleverTap, Stripe, RevenueCat, Razorpay, Paytm, AWS, Azure, Facebook,
Huawei HMS, MSAL, Sentry, Amplitude, Mixpanel, Braze, Segment, AppLovin,
ironSource, Bugsnag, Datadog, New Relic, …); Apple frameworks (Foundation, UIKit,
SwiftUI, CoreData, CoreLocation, Security, CryptoKit, StoreKit, CloudKit,
Network, WebKit, AVFoundation, MapKit, Combine, Swift stdlib); iOS third-party
(Alamofire, AFNetworking, Kingfisher, SDWebImage, Realm, RxSwift, PromiseKit, …).

---

## 4. Matching strategy

* **Longest-prefix wins.** All `package_prefixes` are flattened into one index
  sorted by length, so the most specific module always beats a general
  catch-all (`androidx.work` > `androidx.`; `com.google.android.gms.maps` >
  `com.google.android.gms`; `com.facebook.react` > `com.facebook`). Order in the
  data file is irrelevant.
* **No bare `com.google.*` catch-all** — so `com.google.gson` correctly resolves
  to the open-source Gson, not a Google SDK.
* **Platform gating.** iOS records never match Android findings and vice-versa,
  eliminating a whole class of false positives (e.g. the Obj-C `SK` prefix vs an
  Android package).
* **Class-prefix matching is case-sensitive with an uppercase/digit boundary**
  (`FIR` matches `FIRApp`, never `Firmware`). Applied to iOS/unknown platforms
  only (Android identity comes from packages).
* **Swift modules are package prefixes** — a Swift FQN like `Alamofire.Session`
  derives package `alamofire`, matched as a single-segment prefix.

Signals are derived (`derive_signals`) from, in order: explicit `package`, a
dotted/JVM class reference in `class_name`, the `file_path` (source path, JVM
signature, or framework/pods path), and finally raw `component`/`method`.

---

## 5. Classification stages

Layered; each stage classifies or defers to the next:

1. **Package-prefix fingerprint** → framework / Google / OSS / vendor / Jetpack
   (stage label `Exact Fingerprint` / `Known Framework` / `Vendor SDK` / `Open Source Library`).
2. **Generated code** → R, BuildConfig, Manifest, Data/View Binding, Dagger/Hilt,
   SafeArgs, protobuf, iOS generated sources. *Runs before application namespace*
   so generated code under the app's package is labeled `GeneratedCode`, not
   `Application`.
3. **Application namespace** → matches a declared app package/bundle id, or an
   app manifest/configuration finding.
4. **Embedded-framework path** → `*.framework` / `Pods/` on disk; unknown bundled
   frameworks become `ThirdPartySDK` (named from the path) rather than `Unknown`.
5. **Class signature** → Obj-C/Swift class prefixes (iOS).
6. **iOS application heuristic** → code inside `Payload/*.app` that is not an
   embedded framework.
7. **Heuristic fallback** → obfuscation detection → `Unknown`.

The stage list lives in `OwnershipEngine.classify`; **adding an ownership
category does not change stage logic** — it is a new `OwnerType` value plus data.

---

## 6. Confidence model

Every decision uses one of a small set of justified anchors (`types.Confidence`):

| confidence | meaning |
|-----------:|---------|
| 100 | exact SDK/library fingerprint (specific module prefix) |
| 98 | platform framework signature (`android.*`, Foundation, …) |
| 95 | vendor SDK / open-source library / unambiguous generated code |
| 90 | declared application namespace / app configuration |
| 85 | bundled framework on disk, name not in the DB |
| 80 | strong heuristic (iOS app-bundle code) |
| 60 | weak heuristic (obfuscated package — owner indeterminate) |
| 30 | fallback — nothing matched (`Unknown`) |

No arbitrary numbers: the confidence is always paired with `owner_reason` and
`classification_stage` explaining *why*.

---

## 7. Extensibility

* **Add an SDK:** append one `fp(...)` record to the right list in
  `fingerprints.py`. No engine change, no test change required (existing tests
  keep passing; add one if you want a guarantee).
* **Add an ownership category:** add a constant to `OwnerType` and tag records
  with it. Stage logic is category-agnostic.
* **Custom engine:** `OwnershipEngine(my_fingerprints, my_generated_rules)` for
  tenant-specific or experimental fingerprint sets.
* **Application detection inputs:** `OwnershipContext` carries multiple app
  packages, bundle ids and module names — feature/dynamic modules, flavors and
  split APKs are handled by adding namespaces, not code.

---

## 8. Future integration

| Consumer | How it will use ownership |
|----------|---------------------------|
| **Confidence Engine** | weight finding confidence by `owner_type` (app code > third-party noise); `owner_confidence` feeds the model |
| **SDK Suppression** | hide/group `ThirdPartySDK` / `OpenSourceLibrary` / framework findings by `owner_name` |
| **Bug Bounty Mode** | show only `Application` (and high-value `GeneratedCode`) findings |
| **Attack Chains** | prefer chains whose links are app-owned; de-prioritize cross-library noise |
| **AI Reviewer** | feed `owner_type` + `owner_name` + `owner_reason` as context to reduce hallucinated ownership |
| **Report Engine** | a "third-party components" inventory from `ownership_summary`; per-finding ownership badges |

All of these **read** ownership metadata; none require re-running the engine.

---

## 9. Compatibility & testing

* **Additive only.** `annotate()` writes `owner_*` keys via `dict.update` and
  never reads or rewrites existing finding data. Reports, SARIF/SBOM exports and
  the UI (which read specific keys) are unaffected. The legacy `ownership` /
  `ownership_label` fields used by the current default-view filtering are
  untouched — the Ownership Engine runs in parallel.
* **Tests:** `backend/tests/test_ownership_engine.py` (22 cases) covers the full
  required matrix and the non-destructive guarantee; runnable on stdlib
  (`python tests/test_ownership_engine.py`) or pytest. The Phase 1.1/1.15 suites
  continue to pass.

# 14. Ownership Engine

The Ownership Engine (`analyzers/ownership/`) answers one question for every finding: **who
owns the code this points at?** That single classification is the substrate the entire
intelligence stack reads — Confidence, Triage, Secret Intelligence, Attack Chains, Bug
Bounty and the Trust Score all depend on it. If you understand ownership, you understand why
Beetle's noise reduction works the way it does.

---

## 14.1 What ownership answers

> **"Is this finding in the application's own code, in a third-party SDK, in a platform
> framework, or in generated code?"**

The owner types:

| OwnerType | Meaning | Example |
|-----------|---------|---------|
| **Application** | The app's own code (declared package/bundle id). | `com.example.app.LoginActivity` |
| **ThirdPartySDK** | A bundled vendor SDK. | AppsFlyer, OneSignal, Stripe |
| **OpenSourceLibrary** | A bundled OSS library. | OkHttp, Retrofit, Gson |
| **GoogleSDK** | A Google/Firebase component. | Play Services, Firebase, ML Kit |
| **AndroidFramework** | Android platform code. | `android.*`, AndroidX/Jetpack |
| **AppleFramework** | Apple platform code. | Foundation, UIKit, CryptoKit |
| **VendorSDK** | A named commercial SDK. | Lookout, Branch, Datadog |
| **GeneratedCode** | Machine-generated code. | `R`, `BuildConfig`, Dagger/Hilt, protobuf |
| **Unknown** | Couldn't attribute (often obfuscation). | `a.b.c` (ProGuard/R8) |

Why it matters: a `setJavaScriptEnabled(true)` in *application* code is a real issue; the
same call inside an *ad SDK* is library noise the app team can't fix. Same pattern, very
different value — and ownership is what tells them apart. The guiding rule (echoed in Triage,
[Ch 4 §4.17](04-intelligence-engines.md)) is *suppress for lack of value, never for being a
library.*

---

## 14.2 Architecture

```
analyzers/ownership/
  types.py          OwnerType, Stage, Confidence, OwnershipResult, OwnershipContext
  fingerprints.py   DATA — the fingerprint database (no logic)
  engine.py         multi-stage classifier + signal derivation + pipeline glue
```

The separation is deliberate: **`fingerprints.py` is data, `engine.py` is logic.** Adding or
correcting an SDK never touches the engine. The engine is a pure, cached process-wide
singleton — no network, no side effects except `annotate()`, which writes ownership fields
onto findings additively.

---

## 14.3 The metadata it writes

```
owner_type             e.g. "ThirdPartySDK"
owner_name             e.g. "AndroidX WorkManager"
owner_confidence       0-100, explainable
owner_reason           e.g. "Matched SDK fingerprint"
matched_package_prefix e.g. "androidx.work"
matched_rule           e.g. "fp:AndroidX WorkManager"
matched_signature      the concrete signal matched
classification_stage   e.g. "Exact Fingerprint"
```

(plus convenience `sdk_name` / `framework_name` / `package_prefix`). It enriches both
`findings` and `suppressed_findings`, and emits a scan-level `ownership_summary`.

---

## 14.4 The fingerprint database

140+ records, each built by `fp(...)` with: human `name`, `type`, `platform`
(`android`/`ios`/`both` — gates matching to prevent cross-platform false positives),
`confidence`/`stage`/`reason`, `package_prefixes` (dotted JVM/Kotlin packages **and** Swift
modules), `class_prefixes` (ObjC/Swift class-name prefixes like `FIR`, `NS`, `AF`),
`path_tokens` (`/Alamofire.framework/`, `libflutter.so`), and convenience labels.

Coverage spans: Android & JVM/Kotlin runtime; AndroidX/Jetpack (per module + catch-all);
Google (Play Services, Firebase, Crashlytics, Maps, ML Kit, Material, AdMob, …); open source
(OkHttp, Retrofit, Okio, BouncyCastle, Jackson, Gson, Moshi, RxJava, Dagger/Hilt, Glide,
gRPC, protobuf, …); hybrid frameworks (React Native, Flutter, Cordova, Capacitor, Ionic,
Unity, Xamarin/.NET MAUI, NativeScript, KMP); vendor SDKs (Lookout, Branch, Adjust,
AppsFlyer, OneSignal, Stripe, AWS, Azure, Facebook, Sentry, Amplitude, Mixpanel, Braze,
Segment, Datadog, New Relic, …); Apple frameworks (Foundation, UIKit, SwiftUI, CoreData,
Security, CryptoKit, WebKit, …); and iOS third-party (Alamofire, AFNetworking, Kingfisher,
Realm, RxSwift, …).

---

## 14.5 Matching strategy

- **Longest-prefix wins.** All `package_prefixes` are flattened into one length-sorted index,
  so the most specific module always beats a catch-all (`androidx.work` > `androidx.`;
  `com.google.android.gms.maps` > `com.google.android.gms`; `com.facebook.react` >
  `com.facebook`). Order in the data file is irrelevant.
- **No bare `com.google.*` catch-all** — so `com.google.gson` correctly resolves to the OSS
  Gson, not a Google SDK.
- **Platform gating.** iOS records never match Android findings and vice-versa — eliminating
  a whole class of false positives (e.g. ObjC `SK` prefix vs an Android package).
- **Class-prefix matching is case-sensitive with an uppercase/digit boundary** (`FIR` matches
  `FIRApp`, never `Firmware`); applied to iOS/unknown platforms only.
- **Swift modules are package prefixes** — `Alamofire.Session` derives package `alamofire`.

Signals are derived (`derive_signals`) in order from: explicit `package` → a dotted/JVM class
reference in `class_name` → the `file_path` (source path, JVM signature, framework/pods path)
→ raw `component`/`method`.

---

## 14.6 Classification stages

Layered; each stage classifies or defers to the next:

1. **Package-prefix fingerprint** → framework / Google / OSS / vendor / Jetpack.
2. **Generated code** → R, BuildConfig, Manifest, Data/View Binding, Dagger/Hilt, SafeArgs,
   protobuf, iOS generated sources. *Runs before application namespace* so generated code
   under the app's package is `GeneratedCode`, not `Application`.
3. **Application namespace** → matches a declared app package/bundle id, or an app
   manifest/configuration finding.
4. **Embedded-framework path** → `*.framework` / `Pods/` on disk; an unknown bundled framework
   becomes `ThirdPartySDK` (named from the path), not `Unknown`.
5. **Class signature** → ObjC/Swift class prefixes (iOS).
6. **iOS application heuristic** → code inside `Payload/*.app` that isn't an embedded
   framework.
7. **Heuristic fallback** → obfuscation detection → `Unknown`.

Adding an ownership *category* does not change stage logic — it's a new `OwnerType` value plus
data.

---

## 14.7 Confidence model

Every decision uses one of a small set of justified anchors, always paired with
`owner_reason` and `classification_stage`:

| Confidence | Meaning |
|-----------:|---------|
| 100 | exact SDK/library fingerprint (specific module prefix) |
| 98 | platform framework signature (`android.*`, Foundation, …) |
| 95 | vendor SDK / OSS library / unambiguous generated code |
| 90 | declared application namespace / app configuration |
| 85 | bundled framework on disk, name not in the DB |
| 80 | strong heuristic (iOS app-bundle code) |
| 60 | weak heuristic (obfuscated package — owner indeterminate) |
| 30 | fallback — nothing matched (`Unknown`) |

`owner_confidence` flows directly into the Confidence engine's ownership dimension
([Ch 10 §10.2](10-finding-confidence.md)) and the Trust Score's ownership-certainty factor
([Ch 8 §8.3](08-trust-score.md)).

---

## 14.8 Obfuscation and Unknown ownership

ProGuard/R8 rename packages to single/double letters that match no fingerprint and no app
namespace, so they fall to the heuristic fallback → **Unknown** (confidence ~30–60). This is
*kept visible, never suppressed* — Beetle does not hide a finding just because it can't name
the owner. The consequence is a lower **Trust Score** (the ownership factor), not a lower
Security Score and not a dropped finding. On the Tier-1 corpus, obfuscated apps (DVBA ~56%
Unknown, WaPo ~45%) still reached 100% source resolution; only owner attribution was
uncertain ([Ch 11 §11.4](11-source-resolution.md), [Ch 8 §8.6](08-trust-score.md)).

---

## 14.9 How each consumer uses ownership

| Consumer | Use |
|----------|-----|
| **Confidence** | `owner_type` weights relevance; `owner_confidence` feeds the model directly. |
| **Triage** | app vs framework vs SDK vs generated drives Show / Review / hidden-by-default. |
| **Secret Intelligence** | the same bytes are a high-value secret in app code, a constant inside BouncyCastle/GeneratedCode. |
| **Attack Chains** | prefer app-owned required links; framework/SDK can only be *supporting*. |
| **Bug Bounty** | application-owned is a strong positive signal; framework/SDK a negative. |
| **Network Intelligence** | application-owned IPs/endpoints score higher; SDK/framework demoted ([Ch 20](20-network-intelligence.md)). |
| **Reports** | a "third-party components" inventory from `ownership_summary`; per-finding ownership badges. |

All of these **read** ownership metadata; none re-run the engine.

---

## 14.10 Extensibility

- **Add an SDK:** append one `fp(...)` record to `fingerprints.py`. No engine or test change
  required.
- **Add an ownership category:** add a constant to `OwnerType` and tag records. Stage logic is
  category-agnostic.
- **Custom fingerprint set:** `OwnershipEngine(my_fingerprints, my_generated_rules)` for
  tenant-specific sets.
- **App-detection inputs:** `OwnershipContext` carries multiple app packages, bundle ids and
  module names, so feature/dynamic modules, flavors and split APKs are handled by adding
  namespaces, not code.

---

*Next: [Chapter 15 — Finding Fusion](15-finding-fusion.md).*

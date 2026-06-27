"""
Ownership Engine tests (Beetle 2.0, Phase 1.2).

Covers the full required matrix: Android applications, iOS applications, Android
Framework, Apple Frameworks, AndroidX/Jetpack, Firebase/Google SDKs, hybrid
frameworks (Flutter/RN/Cordova/Capacitor/Unity/Xamarin), open-source libs
(BouncyCastle, OkHttp, …), vendor SDKs (Lookout, RevenueCat, Stripe), generated
code, obfuscated packages, nested namespaces, mixed ownership and unknowns — plus
the compatibility guarantee that enrichment never changes existing finding data.

Runnable standalone or under pytest:
    python -m tests.test_ownership_engine    # from backend/
    python backend/tests/test_ownership_engine.py
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers.canonical_finding import CanonicalFinding  # noqa: E402
from analyzers.ownership import (  # noqa: E402
    OwnershipContext,
    OwnershipEngine,
    OwnerType,
    annotate,
    get_engine,
)

ENGINE = OwnershipEngine()


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _cls(package="", *, platform="android", file_path="", class_name="",
         category="", evidence_type=""):
    return CanonicalFinding(title="t", package=package, platform=platform,
                            file_path=file_path, class_name=class_name,
                            category=category, evidence_type=evidence_type)


def _pkg(package, platform="android", ctx=None):
    return ENGINE.classify(_cls(package, platform=platform), ctx)


# ── The canonical example from the spec ───────────────────────────────────────
def test_spec_example_androidx_workmanager():
    r = _pkg("androidx.work.WorkManager")
    _check(r.owner_type == OwnerType.THIRD_PARTY_SDK, f"type={r.owner_type}")
    _check(r.owner_name == "AndroidX WorkManager", f"name={r.owner_name}")
    _check(r.owner_confidence == 100, f"conf={r.owner_confidence}")
    _check(r.matched_package_prefix == "androidx.work", f"prefix={r.matched_package_prefix}")
    _check(r.classification_stage == "Exact Fingerprint", f"stage={r.classification_stage}")
    _check(r.owner_reason, "must have a reason")


# ── Android framework ─────────────────────────────────────────────────────────
def test_android_framework():
    for pkg in ("android.app.Activity", "android.os.Bundle", "dalvik.system.DexFile"):
        r = _pkg(pkg)
        _check(r.owner_type == OwnerType.ANDROID_FRAMEWORK, f"{pkg} -> {r.owner_type}")
        _check(r.owner_confidence == 98, f"{pkg} conf {r.owner_confidence}")


def test_java_kotlin_runtime():
    _check(_pkg("java.util.Random").owner_type == OwnerType.ANDROID_FRAMEWORK, "java.* framework")
    _check(_pkg("javax.crypto.Cipher").owner_type == OwnerType.ANDROID_FRAMEWORK, "javax.* framework")
    _check(_pkg("kotlin.collections.ArrayList").owner_type == OwnerType.ANDROID_FRAMEWORK, "kotlin.* framework")


# ── AndroidX / Jetpack ────────────────────────────────────────────────────────
def test_androidx_modules_and_catchall():
    _check(_pkg("androidx.room.RoomDatabase").owner_name == "AndroidX Room", "room")
    _check(_pkg("androidx.compose.material.Button").owner_name == "Jetpack Compose", "compose")
    _check(_pkg("androidx.lifecycle.ViewModel").owner_name == "AndroidX Lifecycle", "lifecycle")
    # Unlisted androidx module falls to the catch-all.
    cat = _pkg("androidx.somethingnew.Thing")
    _check(cat.owner_name == "AndroidX (Jetpack)", f"catchall {cat.owner_name}")
    _check(cat.owner_type == OwnerType.THIRD_PARTY_SDK, "catchall type")


# ── Google SDKs ───────────────────────────────────────────────────────────────
def test_google_sdks():
    _check(_pkg("com.google.firebase.auth.FirebaseAuth").owner_name == "Firebase", "firebase")
    _check(_pkg("com.google.android.gms.location.LocationRequest").owner_type == OwnerType.GOOGLE_SDK, "gms")
    _check(_pkg("com.google.android.material.button.MaterialButton").owner_name == "Material Components", "material")
    # Gson is open-source even though it lives under com.google.* — and there is no
    # bare com.google.* catch-all, so it must classify as OpenSourceLibrary.
    gson = _pkg("com.google.gson.Gson")
    _check(gson.owner_type == OwnerType.OPEN_SOURCE_LIBRARY, f"gson type {gson.owner_type}")
    _check(gson.owner_name == "Gson", "gson name")


def test_nested_namespace_longest_prefix_wins():
    # com.google.android.gms.maps beats com.google.android.gms (Play Services).
    r = _pkg("com.google.android.gms.maps.model.LatLng")
    _check(r.owner_name == "Google Maps", f"expected Google Maps, got {r.owner_name}")


# ── Open-source libraries ─────────────────────────────────────────────────────
def test_open_source_libraries():
    cases = {
        "okhttp3.OkHttpClient": "OkHttp",
        "retrofit2.Retrofit": "Retrofit",
        "org.bouncycastle.jce.provider.BouncyCastleProvider": "BouncyCastle",
        "io.reactivex.Observable": "RxJava / RxAndroid",
        "dagger.internal.DoubleCheck": "Dagger",
        "com.bumptech.glide.Glide": "Glide",
    }
    for pkg, name in cases.items():
        r = _pkg(pkg)
        _check(r.owner_type == OwnerType.OPEN_SOURCE_LIBRARY, f"{pkg} type {r.owner_type}")
        _check(r.owner_name == name, f"{pkg} -> {r.owner_name} (want {name})")


# ── Hybrid / cross-platform frameworks ────────────────────────────────────────
def test_mobile_frameworks_by_package_and_path():
    _check(_pkg("io.flutter.embedding.engine.FlutterEngine").framework_name == "Flutter", "flutter pkg")
    _check(_pkg("com.facebook.react.bridge.ReactContext").framework_name == "React Native", "RN pkg")
    _check(_pkg("org.apache.cordova.CordovaActivity").framework_name == "Cordova", "cordova pkg")
    _check(_pkg("com.getcapacitor.Bridge").framework_name == "Capacitor", "capacitor pkg")
    _check(_pkg("com.unity3d.player.UnityPlayer").framework_name == "Unity", "unity pkg")
    # Path-only signals (native libs / assets).
    flutter_so = ENGINE.classify(_cls(file_path="lib/arm64-v8a/libflutter.so"))
    _check(flutter_so.framework_name == "Flutter", f"flutter .so {flutter_so.owner_name}")
    xamarin = ENGINE.classify(_cls(file_path="lib/armeabi-v7a/libmonodroid.so"))
    _check(xamarin.framework_name == "Xamarin/.NET MAUI", f"xamarin {xamarin.owner_name}")


def test_react_native_beats_facebook_sdk():
    # com.facebook.react (RN) must win over the com.facebook (Facebook SDK) prefix.
    _check(_pkg("com.facebook.react.uimanager.ViewManager").framework_name == "React Native", "RN > FB")
    _check(_pkg("com.facebook.login.LoginManager").owner_name == "Facebook SDK", "FB login")


# ── Vendor SDKs ───────────────────────────────────────────────────────────────
def test_vendor_sdks():
    cases = {
        "com.lookout.security.Scanner": "Lookout",
        "com.revenuecat.purchases.Purchases": "RevenueCat",
        "com.stripe.android.Stripe": "Stripe",
        "com.adjust.sdk.Adjust": "Adjust",
        "com.appsflyer.AppsFlyerLib": "AppsFlyer",
        "io.branch.referral.Branch": "Branch",
    }
    for pkg, name in cases.items():
        r = _pkg(pkg)
        _check(r.owner_type == OwnerType.VENDOR_SDK, f"{pkg} type {r.owner_type}")
        _check(r.owner_name == name, f"{pkg} -> {r.owner_name} (want {name})")
        _check(r.owner_confidence == 95, f"{pkg} conf {r.owner_confidence}")


# ── Apple frameworks (iOS) ────────────────────────────────────────────────────
def test_apple_frameworks_by_class_prefix():
    _check(ENGINE.classify(_cls(class_name="NSMutableArray", platform="ios")).owner_name == "Foundation", "NS")
    _check(ENGINE.classify(_cls(class_name="UIViewController", platform="ios")).owner_name == "UIKit", "UI")
    sec = ENGINE.classify(_cls(class_name="SecTrustEvaluate", platform="ios"))
    _check(sec.owner_name == "Security.framework", f"Sec -> {sec.owner_name}")
    _check(sec.owner_type == OwnerType.APPLE_FRAMEWORK, "apple type")


def test_apple_framework_class_prefix_is_case_sensitive():
    # 'Firmware' must NOT match the 'FIR' (Firebase) prefix.
    r = ENGINE.classify(_cls(class_name="FirmwareUpdater", platform="ios",
                             file_path="Payload/App.app/FirmwareUpdater"))
    _check(r.owner_name != "Firebase", "FIR prefix must be case/boundary sensitive")


# ── iOS third-party ───────────────────────────────────────────────────────────
def test_ios_third_party_module_and_path_and_class():
    # Swift module name behaves as a package prefix.
    af = ENGINE.classify(_cls(package="Alamofire.Session", platform="ios"))
    _check(af.owner_name == "Alamofire", f"alamofire module {af.owner_name}")
    # CocoaPods path.
    af2 = ENGINE.classify(_cls(file_path="Payload/App.app/Frameworks/Alamofire.framework/Alamofire", platform="ios"))
    _check(af2.owner_name == "Alamofire", f"alamofire path {af2.owner_name}")
    # Obj-C class prefix.
    rlm = ENGINE.classify(_cls(class_name="RLMRealm", platform="ios"))
    _check(rlm.owner_name == "Realm", f"realm {rlm.owner_name}")
    fir = ENGINE.classify(_cls(class_name="FIRApp", platform="ios"))
    _check(fir.owner_name == "Firebase", f"firebase ios {fir.owner_name}")


def test_embedded_unknown_framework():
    r = ENGINE.classify(_cls(file_path="Payload/App.app/Frameworks/SuperSecretSDK.framework/SuperSecretSDK",
                             platform="ios"))
    _check(r.owner_type == OwnerType.THIRD_PARTY_SDK, f"embedded type {r.owner_type}")
    _check(r.owner_name == "SuperSecretSDK", f"embedded name {r.owner_name}")
    _check(r.classification_stage == "Embedded Framework", "embedded stage")


# ── Application detection ──────────────────────────────────────────────────────
def test_application_namespace_android():
    ctx = OwnershipContext(platform="android", app_packages=("com.acme.app",), app_name="Acme")
    r = _pkg("com.acme.app.ui.LoginActivity", ctx=ctx)
    _check(r.owner_type == OwnerType.APPLICATION, f"app type {r.owner_type}")
    _check(r.owner_confidence == 90, "app conf")
    # A non-app package with no fingerprint stays Unknown, NOT Application.
    unk = _pkg("com.acme.app.ui.LoginActivity")  # no context => not app
    _check(unk.owner_type != OwnerType.APPLICATION, "must not assume app without namespace")


def test_ios_application_heuristic():
    r = ENGINE.classify(_cls(file_path="Payload/Acme.app/Login.swift", platform="ios"))
    _check(r.owner_type == OwnerType.APPLICATION, f"ios app {r.owner_type}")
    _check(r.classification_stage == "Heuristic", "ios app stage")


def test_manifest_config_is_application():
    ctx = OwnershipContext(platform="android", app_packages=("com.acme.app",))
    r = ENGINE.classify(_cls(category="Network Security", evidence_type="manifest"), ctx)
    _check(r.owner_type == OwnerType.APPLICATION, f"manifest -> {r.owner_type}")


# ── Generated code ────────────────────────────────────────────────────────────
def test_generated_code_beats_application():
    ctx = OwnershipContext(platform="android", app_packages=("com.acme.app",))
    for fp_path, want in (
        ("sources/com/acme/app/R.java", "Android Resources (R)"),
        ("sources/com/acme/app/BuildConfig.java", "Generated BuildConfig"),
        ("sources/com/acme/app/databinding/ActivityMainBinding.java", "Data Binding / View Binding"),
    ):
        r = ENGINE.classify(_cls(file_path=fp_path), ctx)
        _check(r.owner_type == OwnerType.GENERATED_CODE, f"{fp_path} -> {r.owner_type}")
        _check(r.owner_name == want, f"{fp_path} -> {r.owner_name} (want {want})")
    dagger = ENGINE.classify(_cls(class_name="DaggerAppComponent",
                                  file_path="sources/com/acme/app/DaggerAppComponent.java"), ctx)
    _check(dagger.owner_type == OwnerType.GENERATED_CODE, "dagger generated")


# ── Obfuscation & unknown ─────────────────────────────────────────────────────
def test_obfuscated_package():
    r = _pkg("a.b.c.d")
    _check(r.owner_type == OwnerType.UNKNOWN, f"obf type {r.owner_type}")
    _check(r.owner_confidence == 60, f"obf conf {r.owner_confidence}")
    _check("obfuscat" in r.owner_reason.lower(), "obf reason")


def test_unknown_vendor_package():
    r = _pkg("com.totallyrandomvendor.sdk.Client")
    _check(r.owner_type == OwnerType.UNKNOWN, f"unknown type {r.owner_type}")
    _check(r.owner_confidence == 30, f"unknown conf {r.owner_confidence}")


# ── Mixed ownership + pipeline integration ────────────────────────────────────
def test_annotate_mixed_and_non_destructive():
    results = {
        "platform": "android",
        "app_info": {"package": "com.acme.app"},
        "app_name": "Acme",
        "findings": [
            {"title": "A", "severity": "high", "rule_id": "r1",
             "file_path": "sources/com/acme/app/pay/Token.java", "line": 10, "secretval": "x"},
            {"title": "B", "severity": "low", "package": "okhttp3.OkHttpClient"},
            {"title": "C", "severity": "info", "package": "android.app.Activity"},
            {"title": "D", "severity": "medium", "package": "com.lookout.Scanner"},
        ],
    }
    import copy
    before = copy.deepcopy(results["findings"])

    annotate(results)

    f = results["findings"]
    # Every finding now carries ownership metadata.
    for x in f:
        _check(x.get("owner_type"), f"missing owner_type on {x['title']}")
        _check("owner_confidence" in x and "owner_reason" in x, "missing owner meta")
    _check(f[0]["owner_type"] == OwnerType.APPLICATION, f"A -> {f[0]['owner_type']}")
    _check(f[1]["owner_type"] == OwnerType.OPEN_SOURCE_LIBRARY, f"B -> {f[1]['owner_type']}")
    _check(f[2]["owner_type"] == OwnerType.ANDROID_FRAMEWORK, f"C -> {f[2]['owner_type']}")
    _check(f[3]["owner_type"] == OwnerType.VENDOR_SDK, f"D -> {f[3]['owner_type']}")

    # Non-destructive: every pre-existing key/value is unchanged.
    OWNER_KEYS = {"owner_type", "owner_name", "owner_confidence", "owner_reason",
                  "matched_package_prefix", "matched_rule", "matched_signature",
                  "classification_stage", "sdk_name", "framework_name", "package_prefix"}
    for orig, now in zip(before, f):
        for k, v in orig.items():
            _check(k in now and now[k] == v, f"enrichment changed existing key {k}")
        added = set(now) - set(orig)
        _check(added <= OWNER_KEYS, f"unexpected non-owner keys added: {added - OWNER_KEYS}")

    summary = results["ownership_summary"]["by_owner_type"]
    _check(summary[OwnerType.APPLICATION] == 1 and summary[OwnerType.VENDOR_SDK] == 1, "summary counts")


def test_ownership_from_source_path():
    """Package is derived from a decompiled source path when not explicit.

    Regression guard: real top-level package roots (okhttp3, kotlin, retrofit2)
    under a jadx 'sources/' tree must derive correctly, not be blanked out.
    """
    okhttp = ENGINE.classify(_cls(file_path="sources/okhttp3/internal/http/RealCall.java"))
    _check(okhttp.owner_name == "OkHttp", f"okhttp path -> {okhttp.owner_name}")
    retro = ENGINE.classify(_cls(file_path="jadx/sources/retrofit2/Retrofit.java"))
    _check(retro.owner_name == "Retrofit", f"retrofit path -> {retro.owner_name}")
    # JVM signature form (taint flow file_path).
    sig = ENGINE.classify(_cls(file_path="Lcom/google/firebase/auth/FirebaseAuth;"))
    _check(sig.owner_name == "Firebase", f"jvm-sig firebase -> {sig.owner_name}")


def test_engine_singleton():
    _check(get_engine() is get_engine(), "engine should be a cached singleton")


# ── Standalone runner ─────────────────────────────────────────────────────────
def _run_all() -> int:
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"FAIL  {t.__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())

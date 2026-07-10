"""
Ownership Engine — fingerprint database (Beetle 2.0, Phase 1.2).

This is DATA, not logic. The engine in ``engine.py`` reads these records; adding
or correcting an SDK means editing a record here, never the engine.

Each record is a dict produced by :func:`fp` with:
  name           human owner name (e.g. "AndroidX WorkManager")
  type           OwnerType value
  platform       "android" | "ios" | "both"  (gates matching to avoid cross-platform FPs)
  confidence     Confidence anchor for a match
  stage          Stage label stored on the finding
  reason         human-readable justification
  package_prefixes  dotted prefixes (Android/Java/Kotlin packages, Swift modules)
  class_prefixes    Obj-C / Swift class-name prefixes (e.g. "FIR", "AF")
  path_tokens       substrings expected in a file_path (e.g. "/Alamofire.framework/")
  framework_name    optional app-framework label (RN/Flutter/…)
  sdk_name          optional convenience SDK name

The list is intentionally broad ("think like a commercial platform"); extend it
freely. Matching specificity (longest prefix wins) keeps general catch-alls from
shadowing specific modules, so order within this file does not matter.
"""
from __future__ import annotations

from .types import Confidence, OwnerType, Stage


def fp(name, type, *, platform="android", confidence=None, stage=None, reason=None,
       package_prefixes=(), class_prefixes=(), path_tokens=(),
       framework_name="", sdk_name="") -> dict:
    """Build a fingerprint record with sensible per-type defaults."""
    default_conf = {
        OwnerType.ANDROID_FRAMEWORK: Confidence.FRAMEWORK,
        OwnerType.APPLE_FRAMEWORK: Confidence.FRAMEWORK,
        OwnerType.GOOGLE_SDK: Confidence.EXACT,
        OwnerType.VENDOR_SDK: Confidence.VENDOR,
        OwnerType.OPEN_SOURCE_LIBRARY: Confidence.OPEN_SOURCE,
        OwnerType.THIRD_PARTY_SDK: Confidence.EXACT,
    }.get(type, Confidence.EXACT)
    default_stage = {
        OwnerType.ANDROID_FRAMEWORK: Stage.KNOWN_FRAMEWORK,
        OwnerType.APPLE_FRAMEWORK: Stage.KNOWN_FRAMEWORK,
        OwnerType.VENDOR_SDK: Stage.VENDOR_SDK,
        OwnerType.OPEN_SOURCE_LIBRARY: Stage.OPEN_SOURCE,
    }.get(type, Stage.EXACT_FINGERPRINT)
    return {
        "name": name,
        "type": type,
        "platform": platform,
        "confidence": confidence if confidence is not None else default_conf,
        "stage": stage or default_stage,
        "reason": reason or f"Matched {name} fingerprint",
        "package_prefixes": tuple(package_prefixes),
        "class_prefixes": tuple(class_prefixes),
        "path_tokens": tuple(path_tokens),
        "framework_name": framework_name,
        "sdk_name": sdk_name or (name if type in (
            OwnerType.THIRD_PARTY_SDK, OwnerType.VENDOR_SDK,
            OwnerType.OPEN_SOURCE_LIBRARY, OwnerType.GOOGLE_SDK) else ""),
    }


_F = OwnerType

# ════════════════════════════════════════════════════════════════════════════
# ANDROID / JVM PLATFORM FRAMEWORK (provided by the OS/runtime, not bundled)
# ════════════════════════════════════════════════════════════════════════════
FRAMEWORK = [
    fp("Android Framework", _F.ANDROID_FRAMEWORK,
       package_prefixes=["android.", "com.android.internal.", "dalvik.", "libcore."],
       reason="Matched Android platform package"),
    fp("Java Runtime", _F.ANDROID_FRAMEWORK,
       package_prefixes=["java.", "javax.", "sun.", "jdk.", "org.w3c.dom",
                         "org.xml.sax", "org.xmlpull", "org.json"],
       reason="Matched Java/JVM runtime package"),
    fp("Kotlin Runtime", _F.ANDROID_FRAMEWORK,
       package_prefixes=["kotlin.", "kotlinx.coroutines", "kotlinx.serialization",
                         "kotlinx.", "kotlin.reflect"],
       reason="Matched Kotlin runtime/stdlib package"),
    # Old support library (Jetpack predecessor, Google-maintained).
    fp("Android Support Library", _F.ANDROID_FRAMEWORK,
       package_prefixes=["android.support.", "android.arch."],
       reason="Matched legacy Android Support Library"),
]

# ════════════════════════════════════════════════════════════════════════════
# ANDROIDX / JETPACK  (bundled dependency → ThirdPartySDK per spec example)
# ════════════════════════════════════════════════════════════════════════════
ANDROIDX = [
    fp("AndroidX WorkManager", _F.THIRD_PARTY_SDK, package_prefixes=["androidx.work"]),
    fp("AndroidX Room", _F.THIRD_PARTY_SDK, package_prefixes=["androidx.room", "androidx.sqlite"]),
    fp("AndroidX Navigation", _F.THIRD_PARTY_SDK, package_prefixes=["androidx.navigation"]),
    fp("Jetpack Compose", _F.THIRD_PARTY_SDK,
       package_prefixes=["androidx.compose", "androidx.activity.compose"]),
    fp("AndroidX Paging", _F.THIRD_PARTY_SDK, package_prefixes=["androidx.paging"]),
    fp("AndroidX Lifecycle", _F.THIRD_PARTY_SDK, package_prefixes=["androidx.lifecycle"]),
    fp("AndroidX App Startup", _F.THIRD_PARTY_SDK, package_prefixes=["androidx.startup"]),
    fp("AndroidX ProfileInstaller", _F.THIRD_PARTY_SDK, package_prefixes=["androidx.profileinstaller"]),
    fp("AndroidX Core KTX", _F.THIRD_PARTY_SDK, package_prefixes=["androidx.core"]),
    fp("AndroidX Fragment", _F.THIRD_PARTY_SDK, package_prefixes=["androidx.fragment"]),
    fp("AndroidX AppCompat", _F.THIRD_PARTY_SDK, package_prefixes=["androidx.appcompat"]),
    fp("AndroidX ConstraintLayout", _F.THIRD_PARTY_SDK, package_prefixes=["androidx.constraintlayout"]),
    fp("AndroidX RecyclerView", _F.THIRD_PARTY_SDK, package_prefixes=["androidx.recyclerview"]),
    fp("AndroidX ViewPager2", _F.THIRD_PARTY_SDK, package_prefixes=["androidx.viewpager2", "androidx.viewpager"]),
    fp("AndroidX DataStore", _F.THIRD_PARTY_SDK, package_prefixes=["androidx.datastore"]),
    fp("AndroidX CameraX", _F.THIRD_PARTY_SDK, package_prefixes=["androidx.camera"]),
    fp("AndroidX Biometric", _F.THIRD_PARTY_SDK, package_prefixes=["androidx.biometric"]),
    fp("AndroidX Security", _F.THIRD_PARTY_SDK, package_prefixes=["androidx.security"]),
    fp("AndroidX Hilt", _F.THIRD_PARTY_SDK, package_prefixes=["androidx.hilt"]),
    # The WebView support library (the Chromium WebKit boundary interfaces live under
    # org.chromium.support_lib_boundary; androidx.webkit is its public surface). Library
    # code — never app code, so it can never anchor an attack chain as an entry.
    fp("AndroidX WebKit", _F.THIRD_PARTY_SDK, package_prefixes=["androidx.webkit"]),
    # Generic catch-all (lowest specificity → only fires when no module above matched).
    fp("AndroidX (Jetpack)", _F.THIRD_PARTY_SDK, confidence=Confidence.FRAMEWORK,
       package_prefixes=["androidx."], reason="Matched AndroidX/Jetpack package"),
]

# ════════════════════════════════════════════════════════════════════════════
# GOOGLE SDKs
# ════════════════════════════════════════════════════════════════════════════
GOOGLE = [
    fp("Firebase", _F.GOOGLE_SDK, platform="both",
       package_prefixes=["com.google.firebase", "com.google.android.datatransport"],
       class_prefixes=["FIR"], path_tokens=["/Firebase", "Pods/Firebase"],
       reason="Matched Firebase SDK fingerprint"),
    fp("Firebase Crashlytics", _F.GOOGLE_SDK, platform="both",
       package_prefixes=["com.google.firebase.crashlytics", "com.crashlytics", "io.fabric"],
       class_prefixes=["FIRCLS"], path_tokens=["Crashlytics"],
       reason="Matched Crashlytics fingerprint"),
    fp("Google Play Services", _F.GOOGLE_SDK,
       package_prefixes=["com.google.android.gms"],
       reason="Matched Google Play Services fingerprint"),
    fp("Google Play Core / Integrity", _F.GOOGLE_SDK,
       package_prefixes=["com.google.android.play", "com.google.android.gms.tasks"],
       reason="Matched Google Play Core/Integrity fingerprint"),
    fp("Google AdMob / Ads", _F.GOOGLE_SDK,
       package_prefixes=["com.google.android.gms.ads", "com.google.ads", "com.google.android.ump"],
       reason="Matched Google Ads/AdMob fingerprint"),
    fp("Google ML Kit", _F.GOOGLE_SDK, platform="both",
       package_prefixes=["com.google.mlkit", "com.google.android.gms.vision"],
       path_tokens=["MLKit"], reason="Matched ML Kit fingerprint"),
    fp("Google Maps", _F.GOOGLE_SDK, platform="both",
       package_prefixes=["com.google.android.gms.maps", "com.google.maps", "com.google.android.libraries.maps"],
       class_prefixes=["GMS"], path_tokens=["GoogleMaps"],
       reason="Matched Google Maps fingerprint"),
    fp("Google SafetyNet", _F.GOOGLE_SDK,
       package_prefixes=["com.google.android.gms.safetynet"],
       reason="Matched SafetyNet fingerprint"),
    fp("Material Components", _F.GOOGLE_SDK,
       package_prefixes=["com.google.android.material"],
       reason="Matched Material Components fingerprint"),
    fp("Google Sign-In", _F.GOOGLE_SDK, platform="both",
       package_prefixes=["com.google.android.gms.auth"], class_prefixes=["GID"],
       path_tokens=["GoogleSignIn"], reason="Matched Google Sign-In fingerprint"),
    fp("Google Utilities (iOS)", _F.GOOGLE_SDK, platform="ios",
       class_prefixes=["GUL", "GTM", "GDT"], path_tokens=["GoogleUtilities"],
       reason="Matched Google Utilities fingerprint"),
]

# ════════════════════════════════════════════════════════════════════════════
# OPEN-SOURCE LIBRARIES (Android/JVM + Swift modules where applicable)
# ════════════════════════════════════════════════════════════════════════════
OPEN_SOURCE = [
    fp("OkHttp", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["okhttp3.", "com.squareup.okhttp"]),
    fp("Okio", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["okio."]),
    fp("Retrofit", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["retrofit2.", "retrofit."]),
    fp("Gson", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["com.google.gson"]),
    fp("Moshi", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["com.squareup.moshi"]),
    fp("Jackson", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["com.fasterxml.jackson"]),
    fp("BouncyCastle", _F.OPEN_SOURCE_LIBRARY,
       package_prefixes=["org.bouncycastle", "org.spongycastle"]),
    fp("Apache Commons", _F.OPEN_SOURCE_LIBRARY,
       package_prefixes=["org.apache.commons", "org.apache.http", "org.apache."]),
    fp("RxJava / RxAndroid", _F.OPEN_SOURCE_LIBRARY,
       package_prefixes=["io.reactivex", "rx."]),
    fp("RxKotlin", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["io.reactivex.rxkotlin"]),
    fp("Dagger", _F.OPEN_SOURCE_LIBRARY,
       package_prefixes=["dagger.", "com.google.dagger", "javax.inject"]),
    fp("Hilt", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["dagger.hilt"]),
    fp("Koin", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["org.koin", "io.insert-koin"]),
    fp("Glide", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["com.bumptech.glide"]),
    fp("Picasso", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["com.squareup.picasso"]),
    fp("Coil", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["coil.", "io.coil-kt"]),
    fp("LeakCanary", _F.OPEN_SOURCE_LIBRARY,
       package_prefixes=["com.squareup.leakcanary", "leakcanary."]),
    fp("Timber", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["timber.log", "com.jakewharton.timber"]),
    fp("ButterKnife", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["butterknife."]),
    fp("EventBus (greenrobot)", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["org.greenrobot.eventbus", "de.greenrobot"]),
    fp("Lottie", _F.OPEN_SOURCE_LIBRARY, platform="both",
       package_prefixes=["com.airbnb.lottie"], path_tokens=["Lottie"]),
    fp("JUnit", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["junit.", "org.junit"]),
    fp("Mockito", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["org.mockito"]),
    fp("Conscrypt", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["org.conscrypt"]),
    fp("Protocol Buffers", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["com.google.protobuf"]),
    fp("gRPC", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["io.grpc"]),
    fp("Guava", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["com.google.common"]),
    fp("Joda-Time", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["org.joda.time"]),
    fp("ThreeTenABP", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["org.threeten", "com.jakewharton.threetenabp"]),
    fp("Apollo GraphQL", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["com.apollographql"]),
    fp("ZXing", _F.OPEN_SOURCE_LIBRARY, package_prefixes=["com.google.zxing", "com.journeyapps.barcodescanner"]),
    fp("ExoPlayer / Media3", _F.OPEN_SOURCE_LIBRARY,
       package_prefixes=["com.google.android.exoplayer2", "androidx.media3"]),
    # Chromium — the open-source engine behind Android System WebView and its support
    # library (org.chromium.support_lib_boundary.*). Bundled library code, not the app;
    # covers org.chromium.support_lib_boundary via the org.chromium. prefix.
    fp("Chromium / Android WebView", _F.OPEN_SOURCE_LIBRARY,
       package_prefixes=["org.chromium."]),
]

# ════════════════════════════════════════════════════════════════════════════
# CROSS-PLATFORM / HYBRID APP FRAMEWORKS
# ════════════════════════════════════════════════════════════════════════════
MOBILE_FRAMEWORKS = [
    fp("React Native", _F.THIRD_PARTY_SDK, platform="both", framework_name="React Native",
       package_prefixes=["com.facebook.react", "com.facebook.hermes", "com.swmansion", "com.th3rdwave"],
       class_prefixes=["RCT", "RNS"], path_tokens=["/ReactNativeApp/", "node_modules/react-native"],
       reason="Matched React Native framework"),
    fp("Flutter", _F.THIRD_PARTY_SDK, platform="both", framework_name="Flutter",
       package_prefixes=["io.flutter", "io.flutter.plugins"],
       path_tokens=["/flutter_assets/", "libflutter.so", "/Flutter.framework/", "App.framework"],
       reason="Matched Flutter framework"),
    fp("Apache Cordova", _F.THIRD_PARTY_SDK, platform="both", framework_name="Cordova",
       package_prefixes=["org.apache.cordova"], class_prefixes=["CDV"],
       path_tokens=["/www/cordova.js", "cordova_plugins.js"], reason="Matched Cordova framework"),
    fp("Capacitor", _F.THIRD_PARTY_SDK, platform="both", framework_name="Capacitor",
       package_prefixes=["com.getcapacitor"], class_prefixes=["CAP"],
       path_tokens=["capacitor.config", "/public/cordova.js"], reason="Matched Capacitor framework"),
    fp("Ionic", _F.THIRD_PARTY_SDK, platform="both", framework_name="Ionic",
       package_prefixes=["com.ionicframework"], path_tokens=["/www/ionic"]),
    fp("Unity", _F.THIRD_PARTY_SDK, platform="both", framework_name="Unity",
       package_prefixes=["com.unity3d"], path_tokens=["libunity.so", "/Data/Managed/", "UnityFramework"],
       reason="Matched Unity engine"),
    fp("Xamarin / .NET MAUI", _F.THIRD_PARTY_SDK, platform="both", framework_name="Xamarin/.NET MAUI",
       package_prefixes=["mono.", "md5", "crc64", "microsoft.maui", "xamarin."],
       path_tokens=["libmonodroid.so", "/assemblies/", "libxamarin"],
       reason="Matched Xamarin/.NET MAUI runtime"),
    fp("NativeScript", _F.THIRD_PARTY_SDK, platform="both", framework_name="NativeScript",
       package_prefixes=["org.nativescript"], path_tokens=["/app/tns_modules/"]),
    fp("Kotlin Multiplatform", _F.THIRD_PARTY_SDK, platform="both", framework_name="KMP",
       path_tokens=["/kotlin/", "default.kotlin_module"]),
]

# ════════════════════════════════════════════════════════════════════════════
# VENDOR / COMMERCIAL SDKs (analytics, attribution, payments, security, MBaaS)
# ════════════════════════════════════════════════════════════════════════════
VENDOR = [
    fp("Lookout", _F.VENDOR_SDK, platform="both",
       package_prefixes=["com.lookout"], path_tokens=["Lookout"],
       reason="Matched Lookout SDK package signature"),
    fp("Branch", _F.VENDOR_SDK, platform="both",
       package_prefixes=["io.branch"], class_prefixes=["BNC", "Branch"],
       path_tokens=["Branch.framework"], reason="Matched Branch SDK"),
    fp("Adjust", _F.VENDOR_SDK, platform="both",
       package_prefixes=["com.adjust.sdk"], class_prefixes=["ADJ"],
       path_tokens=["AdjustSdk"], reason="Matched Adjust SDK"),
    fp("AppsFlyer", _F.VENDOR_SDK, platform="both",
       package_prefixes=["com.appsflyer"], class_prefixes=["AppsFlyer"],
       path_tokens=["AppsFlyerLib"], reason="Matched AppsFlyer SDK"),
    fp("OneSignal", _F.VENDOR_SDK, platform="both",
       package_prefixes=["com.onesignal"], class_prefixes=["OneSignal", "OS"],
       path_tokens=["OneSignal"], reason="Matched OneSignal SDK"),
    fp("MoEngage", _F.VENDOR_SDK, platform="both",
       package_prefixes=["com.moengage"], path_tokens=["MoEngage"]),
    fp("CleverTap", _F.VENDOR_SDK, platform="both",
       package_prefixes=["com.clevertap"], class_prefixes=["CleverTap"], path_tokens=["CleverTapSDK"]),
    fp("Stripe", _F.VENDOR_SDK, platform="both",
       package_prefixes=["com.stripe.android", "com.stripe"], class_prefixes=["STP"],
       path_tokens=["/Stripe.framework/", "Pods/Stripe"], reason="Matched Stripe SDK"),
    fp("RevenueCat", _F.VENDOR_SDK, platform="both",
       package_prefixes=["com.revenuecat.purchases"], class_prefixes=["RC"],
       path_tokens=["/Purchases.framework/", "RevenueCat"], reason="Matched RevenueCat SDK"),
    fp("Razorpay", _F.VENDOR_SDK, platform="both",
       package_prefixes=["com.razorpay"], path_tokens=["Razorpay"]),
    fp("Paytm", _F.VENDOR_SDK, platform="android", package_prefixes=["com.paytm", "net.one97.paytm"]),
    fp("AWS SDK", _F.VENDOR_SDK, platform="both",
       package_prefixes=["com.amazonaws", "software.amazon.awssdk", "aws."],
       class_prefixes=["AWS"], path_tokens=["AWSCore", "Pods/AWS"], reason="Matched AWS SDK"),
    fp("Azure SDK", _F.VENDOR_SDK, platform="both",
       package_prefixes=["com.azure", "com.microsoft.azure"], path_tokens=["AzureCore"]),
    fp("Facebook SDK", _F.VENDOR_SDK, platform="both",
       package_prefixes=["com.facebook.android", "com.facebook.login", "com.facebook.appevents",
                         "com.facebook.internal", "com.facebook.applinks", "com.facebook"],
       class_prefixes=["FB"], path_tokens=["FBSDK"], reason="Matched Facebook SDK"),
    fp("Huawei HMS", _F.VENDOR_SDK, platform="android",
       package_prefixes=["com.huawei.hms", "com.huawei.agconnect"], reason="Matched Huawei HMS"),
    fp("Microsoft Authentication Library (MSAL)", _F.VENDOR_SDK, platform="both",
       package_prefixes=["com.microsoft.identity"], class_prefixes=["MSAL", "MSID"],
       path_tokens=["MSAL"], reason="Matched MSAL"),
    fp("Sentry", _F.VENDOR_SDK, platform="both",
       package_prefixes=["io.sentry"], class_prefixes=["Sentry"],
       path_tokens=["/Sentry.framework/", "Pods/Sentry"], reason="Matched Sentry SDK"),
    fp("Amplitude", _F.VENDOR_SDK, platform="both",
       package_prefixes=["com.amplitude"], class_prefixes=["AMP"], path_tokens=["Amplitude"]),
    fp("Mixpanel", _F.VENDOR_SDK, platform="both",
       package_prefixes=["com.mixpanel.android", "com.mixpanel"], class_prefixes=["Mixpanel"],
       path_tokens=["Mixpanel"]),
    fp("Braze", _F.VENDOR_SDK, platform="both",
       package_prefixes=["com.braze", "com.appboy"], class_prefixes=["ABK"], path_tokens=["BrazeKit"]),
    fp("Segment", _F.VENDOR_SDK, platform="both",
       package_prefixes=["com.segment.analytics"], class_prefixes=["SEG"], path_tokens=["Segment"]),
    fp("AppLovin", _F.VENDOR_SDK, platform="both", package_prefixes=["com.applovin"], class_prefixes=["ALSdk", "MA"]),
    fp("ironSource", _F.VENDOR_SDK, platform="both", package_prefixes=["com.ironsource"], class_prefixes=["ISA"]),
    fp("Vungle", _F.VENDOR_SDK, platform="both", package_prefixes=["com.vungle"], class_prefixes=["Vungle"]),
    fp("Bugsnag", _F.VENDOR_SDK, platform="both", package_prefixes=["com.bugsnag"], class_prefixes=["BugsnagBSG", "BSG"]),
    fp("Datadog", _F.VENDOR_SDK, platform="both", package_prefixes=["com.datadog"], path_tokens=["DatadogCore"]),
    fp("New Relic", _F.VENDOR_SDK, platform="both", package_prefixes=["com.newrelic"], class_prefixes=["NRMA"]),
    fp("Instabug", _F.VENDOR_SDK, platform="both", package_prefixes=["com.instabug"], class_prefixes=["IBG"]),
    fp("Flurry", _F.VENDOR_SDK, platform="both", package_prefixes=["com.flurry"]),
    fp("Kochava", _F.VENDOR_SDK, platform="both", package_prefixes=["com.kochava"]),
    fp("Singular", _F.VENDOR_SDK, platform="both", package_prefixes=["com.singular.sdk"]),
    fp("Smartlook", _F.VENDOR_SDK, platform="both", package_prefixes=["com.smartlook"]),
    fp("PayPal", _F.VENDOR_SDK, platform="both", package_prefixes=["com.paypal"], class_prefixes=["PYPL"]),
    fp("Twilio", _F.VENDOR_SDK, platform="both", package_prefixes=["com.twilio"], class_prefixes=["TWS", "TVO"]),
    fp("Zendesk", _F.VENDOR_SDK, platform="both", package_prefixes=["com.zendesk", "zendesk."]),
    fp("Intercom", _F.VENDOR_SDK, platform="both", package_prefixes=["io.intercom"], class_prefixes=["ICM"]),
    fp("Amazon Publisher Services (APS/TAM)", _F.VENDOR_SDK, platform="android",
       package_prefixes=["com.amazon.aps", "com.amazon.device.ads"],
       reason="Matched Amazon Publisher Services / Mobile Ads SDK"),
    fp("Amazon In-App Purchasing", _F.VENDOR_SDK, platform="android",
       package_prefixes=["com.amazon.device.iap"],
       reason="Matched Amazon In-App Purchasing SDK"),
    fp("Login with Amazon", _F.VENDOR_SDK, platform="android",
       package_prefixes=["com.amazon.identity"],
       reason="Matched Login with Amazon / Amazon Identity SDK"),
    fp("OneTrust CMP", _F.VENDOR_SDK, platform="both",
       package_prefixes=["com.onetrust"], path_tokens=["onetrust"],
       reason="Matched OneTrust consent-management SDK"),
    fp("Radaee PDF", _F.VENDOR_SDK, platform="android",
       package_prefixes=["com.radaee"], path_tokens=["librdpdf"],
       reason="Matched Radaee PDF SDK"),
    fp("IAB Open Measurement SDK", _F.VENDOR_SDK, platform="both",
       package_prefixes=["com.iab.omid"], path_tokens=["omsdk"],
       reason="Matched IAB Open Measurement SDK"),
]

# ════════════════════════════════════════════════════════════════════════════
# APPLE PLATFORM FRAMEWORKS (Swift modules as package prefixes + Obj-C class prefixes)
# ════════════════════════════════════════════════════════════════════════════
APPLE = [
    fp("Foundation", _F.APPLE_FRAMEWORK, platform="ios",
       package_prefixes=["foundation", "corefoundation"], class_prefixes=["NS", "CF"],
       reason="Matched Foundation framework"),
    fp("UIKit", _F.APPLE_FRAMEWORK, platform="ios",
       package_prefixes=["uikit"], class_prefixes=["UI"], reason="Matched UIKit framework"),
    fp("SwiftUI", _F.APPLE_FRAMEWORK, platform="ios", package_prefixes=["swiftui"]),
    fp("Combine", _F.APPLE_FRAMEWORK, platform="ios", package_prefixes=["combine"]),
    fp("CoreData", _F.APPLE_FRAMEWORK, platform="ios",
       package_prefixes=["coredata"], class_prefixes=["NSManaged", "NSFetch", "NSPersistent"]),
    fp("CoreLocation", _F.APPLE_FRAMEWORK, platform="ios",
       package_prefixes=["corelocation"], class_prefixes=["CL"]),
    fp("Security.framework", _F.APPLE_FRAMEWORK, platform="ios",
       package_prefixes=["security"], class_prefixes=["Sec", "SecKey", "kSec"],
       reason="Matched Security.framework"),
    fp("CryptoKit", _F.APPLE_FRAMEWORK, platform="ios", package_prefixes=["cryptokit", "commoncrypto"]),
    fp("StoreKit", _F.APPLE_FRAMEWORK, platform="ios", package_prefixes=["storekit"], class_prefixes=["SK"]),
    fp("CloudKit", _F.APPLE_FRAMEWORK, platform="ios", package_prefixes=["cloudkit"], class_prefixes=["CK"]),
    fp("Network.framework", _F.APPLE_FRAMEWORK, platform="ios", package_prefixes=["network"], class_prefixes=["NW"]),
    fp("WebKit", _F.APPLE_FRAMEWORK, platform="ios", package_prefixes=["webkit"], class_prefixes=["WK"]),
    fp("AuthenticationServices", _F.APPLE_FRAMEWORK, platform="ios",
       package_prefixes=["authenticationservices"], class_prefixes=["AS"]),
    fp("AVFoundation", _F.APPLE_FRAMEWORK, platform="ios", package_prefixes=["avfoundation"], class_prefixes=["AV"]),
    fp("MapKit", _F.APPLE_FRAMEWORK, platform="ios", package_prefixes=["mapkit"], class_prefixes=["MK"]),
    fp("CoreGraphics / QuartzCore", _F.APPLE_FRAMEWORK, platform="ios",
       package_prefixes=["coregraphics", "quartzcore"], class_prefixes=["CG", "CA"]),
    fp("Swift Standard Library", _F.APPLE_FRAMEWORK, platform="ios",
       package_prefixes=["swift"], class_prefixes=["_Swift", "Swift."],
       reason="Matched Swift standard library / runtime"),
]

# ════════════════════════════════════════════════════════════════════════════
# iOS THIRD-PARTY (Swift modules + Obj-C class prefixes + CocoaPods/Carthage paths)
# ════════════════════════════════════════════════════════════════════════════
IOS_THIRD_PARTY = [
    fp("Alamofire", _F.OPEN_SOURCE_LIBRARY, platform="ios",
       package_prefixes=["alamofire"], path_tokens=["/Alamofire.framework/", "Pods/Alamofire"]),
    fp("AFNetworking", _F.OPEN_SOURCE_LIBRARY, platform="ios",
       class_prefixes=["AFHTTP", "AFURL", "AFNetwork"], path_tokens=["Pods/AFNetworking", "AFNetworking.framework"]),
    fp("Kingfisher", _F.OPEN_SOURCE_LIBRARY, platform="ios",
       package_prefixes=["kingfisher"], path_tokens=["/Kingfisher.framework/", "Pods/Kingfisher"]),
    fp("SDWebImage", _F.OPEN_SOURCE_LIBRARY, platform="ios",
       class_prefixes=["SD"], path_tokens=["Pods/SDWebImage", "SDWebImage.framework"]),
    fp("Realm", _F.OPEN_SOURCE_LIBRARY, platform="ios",
       package_prefixes=["realmswift", "realm"], class_prefixes=["RLM"],
       path_tokens=["/Realm.framework/", "Pods/Realm"]),
    fp("RxSwift", _F.OPEN_SOURCE_LIBRARY, platform="ios",
       package_prefixes=["rxswift", "rxcocoa", "rxrelay"], path_tokens=["Pods/RxSwift"]),
    fp("PromiseKit", _F.OPEN_SOURCE_LIBRARY, platform="ios",
       package_prefixes=["promisekit"], path_tokens=["Pods/PromiseKit"]),
    fp("SnapKit", _F.OPEN_SOURCE_LIBRARY, platform="ios", package_prefixes=["snapkit"]),
    fp("SwiftyJSON", _F.OPEN_SOURCE_LIBRARY, platform="ios", package_prefixes=["swiftyjson"]),
    fp("Lottie (iOS)", _F.OPEN_SOURCE_LIBRARY, platform="ios",
       package_prefixes=["lottie"], path_tokens=["/Lottie.framework/", "Pods/lottie-ios"]),
    fp("Charts", _F.OPEN_SOURCE_LIBRARY, platform="ios", package_prefixes=["charts", "dgcharts"]),
]

# ════════════════════════════════════════════════════════════════════════════
# GENERATED CODE (precise, high-precision patterns only — see engine for matching)
# ════════════════════════════════════════════════════════════════════════════
# Each rule matches on the simple class name and/or a package segment. Kept
# precise so real application code is never mislabeled as generated.
GENERATED_CODE_RULES = [
    {"name": "Android Resources (R)", "reason": "Generated resource accessor (R class)",
     "exact_class": {"R", "R2"}, "class_prefix_dollar": ("R",)},
    {"name": "Generated BuildConfig", "reason": "Generated BuildConfig",
     "exact_class": {"BuildConfig"}},
    {"name": "Generated Manifest constants", "reason": "Generated Manifest permission constants",
     "exact_class": {"Manifest"}},
    {"name": "Data Binding / View Binding", "reason": "Generated Data/View Binding class",
     "package_segments": {"databinding"}, "class_suffix": ("BindingImpl",), "exact_class": {"BR"}},
    {"name": "Dagger / Hilt (generated)", "reason": "Dagger/Hilt generated component",
     "class_prefix": ("Dagger", "Hilt_"),
     "class_suffix": ("_Factory", "_MembersInjector", "_GeneratedInjector",
                      "_HiltModules", "_ComponentTreeDeps", "_Impl")},
    {"name": "Navigation SafeArgs", "reason": "Generated Navigation SafeArgs",
     "class_suffix": ("Directions", "FragmentArgs")},
    {"name": "Protocol Buffers (generated)", "reason": "Generated protobuf message",
     "class_suffix": ("OuterClass",), "package_segments": {"proto"}},
    {"name": "iOS Generated Sources", "reason": "Generated Swift/Obj-C bridge or asset symbols",
     "path_tokens": ("-Swift.h", "GeneratedAssetSymbols", "/DerivedSources/")},
]


# ── Aggregated database (order does not matter; longest-prefix wins) ──────────
FINGERPRINTS: list[dict] = (
    FRAMEWORK + ANDROIDX + GOOGLE + OPEN_SOURCE + MOBILE_FRAMEWORKS
    + VENDOR + APPLE + IOS_THIRD_PARTY
)

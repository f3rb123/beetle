# Cortex Tracker Detection
# Based on Exodus Privacy tracker database (https://reports.exodus-privacy.eu.org)

TRACKER_SIGNATURES = [
    # Analytics
    {"name": "Google Firebase Analytics",       "pkg": "com.google.firebase.analytics",     "category": "Analytics",        "url": "https://firebase.google.com"},
    {"name": "Google Firebase Crashlytics",     "pkg": "com.google.firebase.crashlytics",  "category": "Crash Reporting",  "url": "https://firebase.google.com/crashlytics"},
    {"name": "Google Firebase",                 "pkg": "com.google.firebase",               "category": "Analytics/Backend","url": "https://firebase.google.com"},
    {"name": "Amplitude Analytics",             "pkg": "com.amplitude",                     "category": "Analytics",        "url": "https://amplitude.com"},
    {"name": "Mixpanel",                        "pkg": "com.mixpanel.android",              "category": "Analytics",        "url": "https://mixpanel.com"},
    {"name": "Segment",                         "pkg": "com.segment.analytics",             "category": "Analytics",        "url": "https://segment.com"},
    {"name": "Intercom",                        "pkg": "io.intercom.android",               "category": "Analytics",        "url": "https://intercom.com"},
    {"name": "Heap Analytics",                  "pkg": "io.heap.android",                   "category": "Analytics",        "url": "https://heap.io"},
    {"name": "Pendo",                           "pkg": "sdk.pendo.io",                      "category": "Analytics",        "url": "https://pendo.io"},
    {"name": "Pendo (Alt)",                     "pkg": "com.pendo",                         "category": "Analytics",        "url": "https://pendo.io"},
    {"name": "Leanplum",                        "pkg": "com.leanplum",                      "category": "Analytics",        "url": "https://leanplum.com"},
    {"name": "CleverTap",                       "pkg": "com.clevertap.android",             "category": "Analytics",        "url": "https://clevertap.com"},
    {"name": "MoEngage",                        "pkg": "com.moengage",                      "category": "Analytics",        "url": "https://moengage.com"},
    {"name": "Woopra",                          "pkg": "com.woopra",                        "category": "Analytics",        "url": "https://woopra.com"},
    {"name": "Countly",                         "pkg": "ly.count.android",                  "category": "Analytics",        "url": "https://count.ly"},
    {"name": "New Relic",                       "pkg": "com.newrelic.agent.android",        "category": "Analytics",        "url": "https://newrelic.com"},
    {"name": "Datadog",                         "pkg": "com.datadog.android",               "category": "Analytics",        "url": "https://datadoghq.com"},
    {"name": "Glassbox",                        "pkg": "com.glassbox",                      "category": "Session Replay",   "url": "https://www.glassbox.com"},
    {"name": "Clarabridge Session Replay",      "pkg": "com.clarabridge",                   "category": "Session Replay",   "url": "https://www.clarabridge.com"},
    {"name": "FullStory",                       "pkg": "com.fullstory",                     "category": "Session Replay",   "url": "https://www.fullstory.com"},
    {"name": "FullStory (Alt)",                 "pkg": "io.fullstory",                      "category": "Session Replay",   "url": "https://www.fullstory.com"},
    {"name": "UXCam",                           "pkg": "com.uxcam",                         "category": "Session Replay",   "url": "https://uxcam.com"},
    {"name": "Appsee",                          "pkg": "com.appsee",                        "category": "Session Replay",   "url": "https://www.appsee.com"},

    # Crash Reporting
    {"name": "Google Firebase Crashlytics",     "pkg": "com.google.firebase.crashlytics",  "category": "Crash Reporting",  "url": "https://firebase.google.com/crashlytics"},
    {"name": "Sentry",                          "pkg": "io.sentry",                         "category": "Crash Reporting",  "url": "https://sentry.io"},
    {"name": "Bugsnag",                         "pkg": "com.bugsnag.android",               "category": "Crash Reporting",  "url": "https://bugsnag.com"},
    {"name": "Instabug",                        "pkg": "com.instabug",                      "category": "Crash Reporting",  "url": "https://instabug.com"},
    {"name": "Rollbar",                         "pkg": "com.rollbar",                       "category": "Crash Reporting",  "url": "https://rollbar.com"},
    {"name": "Embrace",                         "pkg": "io.embrace.android",                "category": "Crash Reporting",  "url": "https://embrace.io"},

    # Advertising
    {"name": "Google AdMob",                    "pkg": "com.google.android.gms.ads",        "category": "Advertising",      "url": "https://admob.google.com"},
    {"name": "Facebook Audience Network",       "pkg": "com.facebook.ads",                  "category": "Advertising",      "url": "https://audiencenetwork.com"},
    {"name": "AppLovin",                        "pkg": "com.applovin",                      "category": "Advertising",      "url": "https://applovin.com"},
    {"name": "IronSource",                      "pkg": "com.ironsource",                    "category": "Advertising",      "url": "https://ironsource.com"},
    {"name": "Unity Ads",                       "pkg": "com.unity3d.ads",                   "category": "Advertising",      "url": "https://unity.com/solutions/unity-ads"},
    {"name": "Vungle",                          "pkg": "com.vungle",                        "category": "Advertising",      "url": "https://vungle.com"},
    {"name": "MoPub",                           "pkg": "com.mopub",                         "category": "Advertising",      "url": "https://mopub.com"},
    {"name": "Chartboost",                      "pkg": "com.chartboost",                    "category": "Advertising",      "url": "https://chartboost.com"},
    {"name": "InMobi",                          "pkg": "com.inmobi",                        "category": "Advertising",      "url": "https://inmobi.com"},
    {"name": "Criteo",                          "pkg": "com.criteo",                        "category": "Advertising",      "url": "https://criteo.com"},
    {"name": "Taboola",                         "pkg": "com.taboola",                       "category": "Advertising",      "url": "https://taboola.com"},

    # Attribution / Marketing
    {"name": "AppsFlyer",                       "pkg": "com.appsflyer",                     "category": "Attribution",      "url": "https://appsflyer.com"},
    {"name": "Adjust",                          "pkg": "com.adjust.sdk",                    "category": "Attribution",      "url": "https://adjust.com"},
    {"name": "Branch.io",                       "pkg": "io.branch",                         "category": "Attribution",      "url": "https://branch.io"},
    {"name": "Kochava",                         "pkg": "com.kochava",                       "category": "Attribution",      "url": "https://kochava.com"},
    {"name": "Singular",                        "pkg": "com.singular.sdk",                  "category": "Attribution",      "url": "https://singular.net"},
    {"name": "Braze (Appboy)",                  "pkg": "com.braze",                         "category": "Marketing/Push",   "url": "https://braze.com"},
    {"name": "Braze Legacy",                    "pkg": "com.appboy",                        "category": "Marketing/Push",   "url": "https://braze.com"},
    {"name": "OneSignal",                       "pkg": "com.onesignal",                     "category": "Push/Marketing",   "url": "https://onesignal.com"},
    {"name": "Airship",                         "pkg": "com.urbanairship",                  "category": "Push/Marketing",   "url": "https://airship.com"},

    # Social
    {"name": "Facebook SDK",                    "pkg": "com.facebook",                      "category": "Social",           "url": "https://developers.facebook.com"},
    {"name": "Twitter SDK",                     "pkg": "com.twitter",                       "category": "Social",           "url": "https://developer.twitter.com"},
    {"name": "Google Sign-In",                  "pkg": "com.google.android.gms.auth",       "category": "Identity",         "url": "https://developers.google.com/identity"},
    {"name": "Auth0",                           "pkg": "com.auth0.android",                 "category": "Identity",         "url": "https://auth0.com"},

    # Payments
    {"name": "Stripe",                          "pkg": "com.stripe.android",                "category": "Payments",         "url": "https://stripe.com"},
    {"name": "PayPal",                          "pkg": "com.paypal.android",                "category": "Payments",         "url": "https://developer.paypal.com"},
    {"name": "Braintree",                       "pkg": "com.braintreepayments",             "category": "Payments",         "url": "https://braintreepayments.com"},
    {"name": "Square",                          "pkg": "com.squareup",                      "category": "Payments",         "url": "https://developer.squareup.com"},
    {"name": "Razorpay",                        "pkg": "com.razorpay",                      "category": "Payments",         "url": "https://razorpay.com"},

    # Messaging / Chat
    {"name": "Sendbird",                        "pkg": "com.sendbird",                      "category": "Messaging",        "url": "https://sendbird.com"},
    {"name": "Twilio",                          "pkg": "com.twilio",                        "category": "Messaging",        "url": "https://twilio.com"},
    {"name": "Zendesk",                         "pkg": "com.zendesk",                       "category": "Support/Chat",     "url": "https://zendesk.com"},
    {"name": "Freshchat",                       "pkg": "com.freshchat",                     "category": "Support/Chat",     "url": "https://freshworks.com"},

    # Maps / Location
    {"name": "Google Maps SDK",                 "pkg": "com.google.android.gms.maps",       "category": "Maps",             "url": "https://developers.google.com/maps"},
    {"name": "Mapbox",                          "pkg": "com.mapbox",                        "category": "Maps",             "url": "https://mapbox.com"},
    {"name": "HERE Maps",                       "pkg": "com.here",                          "category": "Maps",             "url": "https://here.com"},

    # Debug (should not be in production)
    {"name": "Stetho (Debug Bridge)",           "pkg": "com.facebook.stetho",               "category": "Debug",            "url": "https://facebook.github.io/stetho"},
    {"name": "LeakCanary",                      "pkg": "com.squareup.leakcanary",            "category": "Debug",            "url": "https://square.github.io/leakcanary"},
    {"name": "Flipper",                         "pkg": "com.facebook.flipper",              "category": "Debug",            "url": "https://fbflipper.com"},

    # ML / AI
    {"name": "Google ML Kit",                   "pkg": "com.google.mlkit",                  "category": "ML/AI",            "url": "https://developers.google.com/ml-kit"},
    {"name": "TensorFlow Lite",                 "pkg": "org.tensorflow",                    "category": "ML/AI",            "url": "https://tensorflow.org"},

    # Other
    {"name": "Google Play Core",                "pkg": "com.google.android.play.core",      "category": "App Updates",      "url": "https://developer.android.com/guide/playcore"},
    {"name": "WorkManager",                     "pkg": "androidx.work",                     "category": "Background Work",  "url": "https://developer.android.com/topic/libraries/architecture/workmanager"},
]

# Known malware-abused permissions (from MobSF malware permission DB)
MALWARE_PERMISSIONS = {
    # Top 25 malware permissions
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.INTERNET",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
}

# Other common malware permissions (44 total)
COMMON_MALWARE_PERMISSIONS = {
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.CALL_PHONE",
    "android.permission.MODIFY_AUDIO_SETTINGS",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    "com.google.android.c2dm.permission.RECEIVE",
    "com.google.android.gms.permission.AD_ID",
    "com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE",
    "com.google.android.gms.permission.ACTIVITY_RECOGNITION",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.GET_ACCOUNTS",
    "android.permission.MANAGE_ACCOUNTS",
    "android.permission.AUTHENTICATE_ACCOUNTS",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.NFC",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BODY_SENSORS",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.FOREGROUND_SERVICE_LOCATION",
}

# Android API categories for API analysis tab
ANDROID_API_CATEGORIES = {
    "Android Notifications":         [r"NotificationManager", r"NotificationCompat", r"NotificationChannel"],
    "Base64 Decode":                 [r"Base64\.decode"],
    "Base64 Encode":                 [r"Base64\.encode"],
    "Certificate Handling":          [r"X509Certificate", r"TrustManager", r"KeyStore", r"SSLContext"],
    "Content Provider":              [r"getContentResolver\(\)", r"ContentProvider", r"ContentValues"],
    "Crypto":                        [r"Cipher\.getInstance", r"MessageDigest", r"SecretKeySpec", r"KeyGenerator"],
    "Dynamic Class and Dexloading":  [r"DexClassLoader", r"PathClassLoader", r"InMemoryDexClassLoader", r"BaseDexClassLoader"],
    "Execute OS Command":            [r"Runtime\.exec\(", r"Runtime\.getRuntime\(\)\.exec"],
    "Get Cell Information":          [r"TelephonyManager", r"getDeviceId\(\)", r"getCellInfo"],
    "Get Installed Applications":    [r"getInstalledPackages\(", r"getInstalledApplications\(", r"PackageManager"],
    "Get SMS Messages":              [r"SmsManager", r"Telephony\.Sms", r"readSms"],
    "Get Subscriber ID":             [r"getSubscriberId\(", r"getImsi\("],
    "GPS Location":                  [r"LocationManager", r"getLastKnownLocation\(", r"requestLocationUpdates"],
    "HTTP Connection":               [r"HttpURLConnection", r"OkHttpClient", r"HttpClient", r"HttpsURLConnection"],
    "Intent":                        [r"new Intent\(", r"startActivity\(", r"sendBroadcast\(", r"startService\("],
    "JAR Loading":                   [r"URLClassLoader", r"JarFile", r"jarInputStream"],
    "Java Reflection":               [r"\.invoke\(", r"getDeclaredMethod\(", r"getDeclaredField\(", r"Class\.forName\("],
    "Network Operations":            [r"Socket\(", r"ServerSocket\(", r"InetAddress", r"DatagramSocket"],
    "Phone Call":                    [r"ACTION_CALL", r"TelecomManager", r"CALL_PHONE"],
    "Read/Write Contacts":           [r"ContactsContract", r"Contacts\.People"],
    "Send SMS":                      [r"sendTextMessage\(", r"sendMultipartTextMessage\("],
    "Shared Preferences":            [r"getSharedPreferences\(", r"SharedPreferences"],
    "SQLite":                        [r"SQLiteDatabase", r"SQLiteOpenHelper", r"rawQuery\("],
    "WebView":                       [r"WebView", r"setJavaScriptEnabled\(", r"loadUrl\(", r"addJavascriptInterface\("],
    "Audio Record":                  [r"MediaRecorder", r"AudioRecord", r"startRecording\("],
    "Bluetooth":                     [r"BluetoothAdapter", r"BluetoothDevice", r"BluetoothSocket"],
    "Camera":                        [r"Camera\.open\(", r"CameraManager", r"takePicture\("],
    "External Storage":              [r"getExternalStorageDirectory\(", r"getExternalFilesDir\("],
    "Read File":                     [r"FileInputStream\(", r"openFileInput\(", r"new File\("],
    "Write File":                    [r"FileOutputStream\(", r"openFileOutput\("],
    "Accessibility Service":         [r"AccessibilityService", r"AccessibilityNodeInfo", r"performAction\("],
    "Device Admin":                  [r"DevicePolicyManager", r"isDeviceOwnerApp\("],
    "KeyStore":                      [r"KeyStore\.getInstance\(", r"AndroidKeyStore", r"KeyPairGenerator"],
    "Network State":                 [r"ConnectivityManager", r"getActiveNetworkInfo\(", r"getNetworkInfo\("],
    "Wifi":                          [r"WifiManager", r"getConnectionInfo\(", r"getScanResults\("],
    "Fingerprint/Biometric":         [r"BiometricPrompt", r"FingerprintManager", r"BiometricManager"],
}


def detect_trackers(package_names: set) -> list:
    """Detect known trackers from package name set."""
    found = []
    seen = set()
    for tracker in TRACKER_SIGNATURES:
        pkg = tracker["pkg"]
        if any(p.startswith(pkg) for p in package_names):
            key = tracker["name"]
            if key not in seen:
                seen.add(key)
                found.append(tracker.copy())
    return found


# ─── SDK name normalization (Phase 2.5.10 #8) ───────────────────────────────
# The same SDK is reported under vendor-prefixed aliases by different detectors
# (e.g. "Firebase" vs "Google Firebase"). Canonicalize so it appears ONCE.
_SDK_ALIASES = {
    "google firebase": "Firebase",
    "firebase": "Firebase",
    "google firebase analytics": "Firebase Analytics",
    "firebase analytics": "Firebase Analytics",
    "google firebase crashlytics": "Firebase Crashlytics",
    "firebase crashlytics": "Firebase Crashlytics",
    "crashlytics": "Firebase Crashlytics",
    "google firebase messaging": "Firebase Cloud Messaging",
    "firebase cloud messaging": "Firebase Cloud Messaging",
    "google admob": "Google AdMob",
    "admob": "Google AdMob",
    "google analytics": "Google Analytics",
    "google play services": "Google Play Services",
    "facebook": "Facebook SDK",
    "facebook sdk": "Facebook SDK",
    "facebook login": "Facebook SDK",
}

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def canonical_sdk_name(name: str) -> str:
    """Map an SDK display name to its canonical form (alias table, else as-is)."""
    n = (name or "").strip()
    return _SDK_ALIASES.get(n.lower(), n)


def normalize_sdks(sdks: list) -> list:
    """Merge duplicate SDK entries by canonical name across platforms. Keeps first
    appearance order, enriches missing url/category, and keeps the highest severity."""
    merged: dict[str, dict] = {}
    order: list[str] = []
    for s in sdks or []:
        if not isinstance(s, dict):
            continue
        canon = canonical_sdk_name(s.get("name", ""))
        key = canon.lower()
        if not key:
            continue
        if key not in merged:
            merged[key] = {**s, "name": canon}
            order.append(key)
            continue
        cur = merged[key]
        for field in ("url", "category", "package", "description"):
            if not cur.get(field) and s.get(field):
                cur[field] = s[field]
        if _SEV_RANK.get(s.get("severity"), 4) < _SEV_RANK.get(cur.get("severity"), 4):
            cur["severity"] = s.get("severity")
    return [merged[k] for k in order]


def analyze_malware_permissions(permissions: list) -> dict:
    """
    Categorize permissions into malware / common malware / normal.
    Returns counts and matched lists.
    """
    malware_matched  = [p for p in permissions if p in MALWARE_PERMISSIONS]
    common_matched   = [p for p in permissions if p in COMMON_MALWARE_PERMISSIONS]

    return {
        "malware_permissions": {
            "matched": malware_matched,
            "count":   len(malware_matched),
            "total":   len(MALWARE_PERMISSIONS),
        },
        "common_malware_permissions": {
            "matched": common_matched,
            "count":   len(common_matched),
            "total":   len(COMMON_MALWARE_PERMISSIONS),
        },
    }


# ─── iOS tracker detection (RUN 11) ──────────────────────────────────────────
# NOT a one-line wire-up of detect_trackers(). Every one of the 73 TRACKER_SIGNATURES above
# keys on an ANDROID PACKAGE PREFIX ("com.google.firebase.crashlytics") and matches with
# `p.startswith(pkg)`. An iOS app has no Java packages: its trackers are identified by CocoaPod /
# framework names ("FirebaseCrashlytics"), by the endpoints they call, and — for SDKs that are
# STATICALLY LINKED into the main executable rather than shipped as a framework — by marker
# strings inside the binary itself. Feeding pod names to detect_trackers() would match nothing.
#
# EVERY tracker below must be proven by at least one of three EVIDENCE signals. Nothing is
# inferred from "this app uses Firebase, so it probably also has X".
#
#   pods    — a framework/pod physically in the bundle (results["sdks"], from RUN 7's real
#             Frameworks/ walk)
#   domains — an endpoint the app actually contains (results["endpoints"], from RUN 1)
#   markers — a symbol/string statically linked into a Mach-O (RUN 8's binary string scan).
#             This is what catches Firebase Analytics in THIS app: it ships no
#             FirebaseAnalytics.framework — it is linked straight into Runner, so a
#             framework-only check would report it as absent.
IOS_TRACKER_SIGNATURES = [
    {"name": "Google Firebase Crashlytics", "category": "Crash Reporting",
     "url": "https://firebase.google.com/crashlytics",
     "pods": ["FirebaseCrashlytics"],
     "domains": ["crashlytics.com", "crashlyticsreports-pa.googleapis.com"],
     "markers": ["FIRCrashlytics", "FirebaseCrashlytics"]},

    {"name": "Google Firebase Analytics", "category": "Analytics",
     "url": "https://firebase.google.com",
     "pods": ["FirebaseAnalytics", "GoogleAppMeasurement"],
     "domains": ["app-measurement.com", "app-analytics-services.com"],
     "markers": ["FirebaseAnalytics", "GoogleAppMeasurement", "FIRAnalytics"]},

    {"name": "Google Ads On-Device Conversion", "category": "Advertising/Attribution",
     "url": "https://developers.google.com/ads",
     "pods": ["GoogleAdsOnDeviceConversion"],
     "domains": ["googleadservices.com", "app-ads-services.com"],
     "markers": ["GoogleAdsOnDeviceConversion", "admob_app_id"]},

    {"name": "Google Firebase Performance Monitoring", "category": "Performance/Telemetry",
     "url": "https://firebase.google.com/products/performance",
     "pods": ["FirebasePerformance"], "domains": ["firebaselogging.googleapis.com"],
     "markers": ["FIRPerformance"]},

    {"name": "Google Firebase Remote Config", "category": "Experimentation",
     "url": "https://firebase.google.com/products/remote-config",
     "pods": ["FirebaseRemoteConfig"],
     "domains": ["firebaseremoteconfig.googleapis.com",
                 "firebaseremoteconfigrealtime.googleapis.com"],
     "markers": ["FIRRemoteConfig"]},

    {"name": "Google Firebase A/B Testing", "category": "Experimentation",
     "url": "https://firebase.google.com/products/ab-testing",
     "pods": ["FirebaseABTesting"], "domains": [], "markers": ["FIRExperiment"]},

    {"name": "Google Firebase Sessions", "category": "Analytics",
     "url": "https://firebase.google.com",
     "pods": ["FirebaseSessions"], "domains": [], "markers": ["FIRSessions"]},

    {"name": "Google DataTransport", "category": "Telemetry Delivery",
     "url": "https://github.com/google/GoogleDataTransport",
     "pods": ["GoogleDataTransport"], "domains": ["firebaselogging.googleapis.com"],
     "markers": ["GDTCORTransport"]},

    {"name": "Apple AdServices (Attribution)", "category": "Advertising/Attribution",
     "url": "https://developer.apple.com/documentation/adservices",
     "pods": [], "domains": ["api-adservices.apple.com", "app-analytics-services-att.com"],
     "markers": ["AAAttribution"]},

    # Common third-party trackers, for apps other than this one.
    {"name": "Facebook SDK", "category": "Advertising/Analytics", "url": "https://developers.facebook.com",
     "pods": ["FBSDKCoreKit", "FacebookCore"], "domains": ["graph.facebook.com"],
     "markers": ["FBSDKCoreKit"]},
    {"name": "AppsFlyer", "category": "Attribution", "url": "https://appsflyer.com",
     "pods": ["AppsFlyerLib"], "domains": ["appsflyer.com"], "markers": ["AppsFlyerLib"]},
    {"name": "Adjust", "category": "Attribution", "url": "https://adjust.com",
     "pods": ["Adjust"], "domains": ["adjust.com"], "markers": ["ADJAdjust"]},
    {"name": "Sentry", "category": "Crash Reporting", "url": "https://sentry.io",
     "pods": ["Sentry"], "domains": ["sentry.io"], "markers": ["SentrySDK"]},
    {"name": "Mixpanel", "category": "Analytics", "url": "https://mixpanel.com",
     "pods": ["Mixpanel"], "domains": ["api.mixpanel.com"], "markers": ["MixpanelInstance"]},
    {"name": "Amplitude", "category": "Analytics", "url": "https://amplitude.com",
     "pods": ["Amplitude"], "domains": ["api.amplitude.com"], "markers": ["AMPAmplitude"]},
    {"name": "Google AdMob", "category": "Advertising", "url": "https://admob.google.com",
     "pods": ["GoogleMobileAds"], "domains": ["googlesyndication.com", "doubleclick.net"],
     "markers": ["GADMobileAds"]},
]


def detect_trackers_ios(sdk_names=None, endpoints=None, binary_markers=None) -> list:
    """Detect iOS trackers from POD names, ENDPOINTS and STATICALLY-LINKED binary markers.

    Each hit records WHICH evidence matched, so a tracker is never asserted without proof. A
    tracker with no matching evidence is simply not reported — the same discipline as RUN 7's
    "unknown stays reachable" and RUN 8.1's "a control with no evidence stays absent".
    """
    pods = {str(s).lower() for s in (sdk_names or []) if s}
    eps = " ".join(str(e).lower() for e in (endpoints or []))
    markers = {str(m) for m in (binary_markers or []) if m}

    found = []
    for sig in IOS_TRACKER_SIGNATURES:
        evidence = []
        hit_pods = [p for p in sig["pods"] if p.lower() in pods]
        if hit_pods:
            evidence.append({"type": "framework", "value": ", ".join(hit_pods)})
        hit_domains = [d for d in sig["domains"] if d.lower() in eps]
        if hit_domains:
            evidence.append({"type": "endpoint", "value": ", ".join(sorted(set(hit_domains)))})
        hit_markers = [m for m in sig["markers"] if m in markers]
        if hit_markers:
            evidence.append({"type": "binary_symbol", "value": ", ".join(hit_markers)})
        if not evidence:
            continue
        found.append({
            "name": sig["name"],
            "category": sig["category"],
            "url": sig["url"],
            # `pkg` is what the existing UI/SBOM renders; on iOS the identifier is the pod (or
            # the marker, when the SDK is statically linked and ships no framework).
            "pkg": (hit_pods or hit_markers or hit_domains or [""])[0],
            "evidence": evidence,
            "statically_linked": bool(hit_markers and not hit_pods),
        })
    found.sort(key=lambda t: t["name"])
    return found


def ios_tracker_markers() -> set:
    """Every marker string worth scanning a Mach-O for (fed by the binary string scan)."""
    return {m for sig in IOS_TRACKER_SIGNATURES for m in sig["markers"]}

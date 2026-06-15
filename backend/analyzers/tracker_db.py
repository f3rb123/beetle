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

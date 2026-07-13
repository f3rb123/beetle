"""iOS embedded-framework categorisation (RUN 7).

Every pod this app actually ships must get a real category — but an UNRECOGNISED pod must
still report "unknown". Categorising is not guessing: the honest answer for a framework
nobody has mapped is "unknown", not a plausible-looking label.
"""
from analyzers.ios_analyzer import _classify_framework, _KNOWN_FRAMEWORKS


def test_unrecognised_pod_stays_unknown():
    category, severity, description, known = _classify_framework("TotallyMadeUpVendorKit")
    assert category == "unknown"
    assert known is False
    assert description == ""


def test_firebase_family_prefix_catches_future_modules():
    # A Firebase module we never enumerated must not fall through to "unknown".
    category, _sev, _desc, known = _classify_framework("FirebaseSomethingNewInSDK14")
    assert category == "backend"
    assert known is True


def test_flutter_runtime_is_not_a_third_party_sdk():
    # "App" is the app's OWN Dart AOT blob and "Flutter" is the engine. Reporting them as
    # third-party dependencies misattributes the app's own code to a vendor.
    for name in ("App", "Flutter"):
        category, _sev, _desc, known = _classify_framework(name)
        assert category == "runtime", name
        assert known is True, name


def test_categorising_a_framework_never_invents_a_finding():
    # _analyze_embedded_frameworks emits a finding for a known framework at medium/high.
    # Everything RUN 7 added is "info" precisely so that categorisation does not create
    # findings about dependencies that were previously silent.
    added = [
        "App", "Flutter", "FirebaseCore", "FirebaseCrashlytics", "GoogleUtilities",
        "IOSSecuritySuite", "flutter_jailbreak_detection_plus", "webview_flutter_wkwebview",
        "flutter_secure_storage", "shared_preferences_foundation", "path_provider_foundation",
        "connectivity_plus", "network_speed", "camera_avfoundation", "image_picker_ios",
        "just_audio", "audio_session", "nfc_manager", "qr_code_scanner_plus",
        "snowfinch_logger", "snowfinch_app_logger", "package_info_plus", "device_info_plus",
        "battery_plus", "flutter_timezone", "fluttertoast", "nanopb", "FBLPromises",
        "Promises", "GoogleDataTransport",
    ]
    for name in added:
        assert _KNOWN_FRAMEWORKS[name][1] == "info", f"{name} would emit a finding"

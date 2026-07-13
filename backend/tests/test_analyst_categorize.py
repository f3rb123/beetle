"""RUN 29 / BUG 3 — analyst_intel.categorize must key on the finding's OWN identity (rule_id,
category field, cwe), NOT on incidental framework/component names in the evidence or title.

Before this, greedy substring matching on a title+description+evidence blob made any finding that
merely MENTIONED a Firebase framework render "Permissive Firebase rules expose the database", and a
deep-link finding titled "… -> WebViewActivity" render as a WebView finding. A wrong narrative is
worse than none, so unconfident findings fall back to GENERIC (neutral).
"""
from analyzers.analyst_intel import categorize


def _f(**kw):
    d = {"rule_id": "", "category": "", "cwe": "", "title": "", "description": ""}
    d.update(kw)
    return d


# ── The false-matches the bug report cited ──────────────────────────────────────
def test_stack_canary_on_firebase_framework_is_not_firebase():
    f = _f(rule_id="macho_missing_stack_canary", category="Resilience",
           title="Framework Binaries Without Stack Canary",
           description="FirebaseCoreExtension, FirebaseCrashlytics ship without a stack canary")
    assert categorize(f) == "GENERIC"


def test_malloc_on_firebase_framework_is_not_firebase():
    f = _f(rule_id="ios_binary_uncontrolled_malloc", category="Code Quality",
           title="Binary Imports Uncontrolled Allocation (malloc)",
           description="_malloc imported by FirebaseCrashlytics")
    assert categorize(f) == "GENERIC"


def test_realm_without_encryption_is_storage_not_crypto_or_webview():
    f = _f(rule_id="ios_realm_no_encryption", category="Data Storage",
           title="Realm Database Without Encryption",
           file_path="Payload/Runner.app/Frameworks/webview_flutter_wkwebview.framework/webview_flutter_wkwebview")
    assert categorize(f) == "FILE_STORAGE"


def test_nsuserdefaults_is_storage():
    assert categorize(_f(rule_id="ios_nsuserdefaults_sensitive", category="Data Storage",
                         title="NSUserDefaults for Sensitive Data")) == "FILE_STORAGE"


def test_deeplink_with_webview_component_in_title_is_deeplinks():
    f = _f(rule_id="manifest_custom_scheme_deeplink", category="Deeplinks", cwe="CWE-926",
           title="Custom Scheme Deeplink Hijacking Surface -> WebViewActivity")
    assert categorize(f) == "DEEP_LINKS"


def test_deserialization_is_not_crypto():
    # "_des" (DES cipher) must not match "_deserialization".
    assert categorize(_f(rule_id="android_insecure_deserialization", category="Code Quality",
                         cwe="CWE-502", title="Object Deserialization")) == "GENERIC"


def test_attack_chain_is_generic():
    assert categorize(_f(rule_id="chain_exported_intent_webview",
                         title="Exported Intent to JS-Enabled WebView Attack Chain")) == "GENERIC"


# ── Genuine matches still work ───────────────────────────────────────────────────
def test_positive_matches_hold():
    assert categorize(_f(rule_id="ios_md5_hash", title="MD5 Hash Function Used")) == "CRYPTO"
    assert categorize(_f(rule_id="cloud_firebase_storage_bucket",
                         title="Firebase Storage Bucket Reference")) == "FIREBASE"
    assert categorize(_f(rule_id="android_webview_js_enabled", category="WebView",
                         title="WebView JavaScript Enabled")) == "WEBVIEW"
    assert categorize(_f(rule_id="ios_jailbreak_detection",
                         title="Jailbreak Detection Logic")) == "ROOT_DETECTION"
    assert categorize(_f(rule_id="manifest_cleartext_traffic", category="Network Security",
                         cwe="CWE-319", title="Cleartext HTTP Traffic Permitted")) == "NETWORK"

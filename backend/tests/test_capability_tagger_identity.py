"""RUN 35 R35-A — capability tags key on IDENTITY, not prose.

The chain capability tagger used to add CODE_LOADING / WEBVIEW from a bare substring in a finding's
title/description. That mislabeled findings that merely MENTION the words and assembled bogus chains:
RUN 32 (StrandHogg "reflection-based task hijacking") and RUN 34 (a low-minSdk note naming "WebView"
/ "addJavascriptInterface"). These tests lock BOTH directions: a genuine reflection/webview finding
still earns the capability (so real chains survive); a prose-only mention does not.
"""
import pytest

from analyzers.attack_chains.engine import tag_capabilities


# ── CODE_LOADING: genuine rules keep it; prose mentions do not ────────────────
def test_reflection_rule_earns_code_loading():
    """InsecureShop's RUN 25 chain requires this exact finding — it MUST stay tagged."""
    f = {"rule_id": "android_reflection", "title": "Java Reflection Usage", "category": "Code Quality"}
    assert "CODE_LOADING" in tag_capabilities(f)


def test_dexclassloader_and_behavior_rules_earn_code_loading():
    assert "CODE_LOADING" in tag_capabilities(
        {"rule_id": "android_dex_class_loader", "title": "Dynamic Code Loading — DexClassLoader"})
    assert "CODE_LOADING" in tag_capabilities(
        {"rule_id": "behavior_dynamic_class_and_dexloading", "title": "Dynamic Code Loading Detected"})


def test_dynamic_code_loading_category_earns_it():
    assert "CODE_LOADING" in tag_capabilities(
        {"rule_id": "x", "category": "Dynamic Code Loading", "title": "Dynamic DEX/code loading"})


def test_reflection_taint_sink_earns_it():
    f = {"rule_id": "TAINT-X", "taint_flow": {"sink_cat": "reflection", "source_cat": "user input"}}
    assert "CODE_LOADING" in tag_capabilities(f)


def test_strandhogg_prose_does_not_earn_code_loading():
    """RUN 32 regression: task hijacking that says 'reflection-based' in prose is NOT code loading."""
    f = {"rule_id": "manifest_strandhogg2", "title": "StrandHogg 2.0 Task Hijacking",
         "category": "Attack Surface",
         "description": "a malicious app can use reflection-based task hijacking to overlay activities"}
    assert "CODE_LOADING" not in tag_capabilities(f)


def test_low_minsdk_prose_does_not_earn_code_loading():
    f = {"rule_id": "manifest_low_min_sdk", "title": "Low Minimum SDK Version",
         "category": "Configuration",
         "description": "known WebView RCEs (addJavascriptInterface) and dynamic code paths remain"}
    assert "CODE_LOADING" not in tag_capabilities(f)


def test_deserialization_is_not_code_loading():
    """android_insecure_deserialization sits next to reflection in the rule table but is NOT code
    loading — it must not be swept into the set."""
    f = {"rule_id": "android_insecure_deserialization", "title": "Object Deserialization",
         "category": "Code Quality"}
    assert "CODE_LOADING" not in tag_capabilities(f)


# ── WEBVIEW: genuine webview findings keep it; prose mentions do not ───────────
def test_webview_rule_and_category_earn_webview():
    assert "WEBVIEW" in tag_capabilities(
        {"rule_id": "android_webview_js_enabled", "title": "WebView JavaScript Enabled",
         "category": "WebView"})
    assert "WEBVIEW" in tag_capabilities({"rule_id": "x", "category": "WebView", "title": "y"})


def test_webview_taint_sink_earns_it():
    f = {"rule_id": "TAINT-WEBVIEW",
         "taint_flow": {"sink_cat": "WebView", "source_cat": "intent"}}
    assert "WEBVIEW" in tag_capabilities(f)


def test_js_interface_subcap_on_real_webview_finding():
    f = {"rule_id": "android_webview_javascript_interface", "category": "WebView",
         "title": "WebView addJavascriptInterface — RCE Surface"}
    caps = tag_capabilities(f)
    assert "WEBVIEW" in caps and "JS_INTERFACE" in caps


def test_low_minsdk_webview_prose_does_not_earn_webview():
    """RUN 34 regression: a config finding mentioning WebView/addJavascriptInterface in prose is NOT
    a webview finding — no WEBVIEW/JS_INTERFACE, so it can't assemble a WebView Bridge chain."""
    f = {"rule_id": "manifest_low_min_sdk", "title": "Low Minimum SDK Version",
         "category": "Configuration",
         "description": "the system WebView is unpatchable; addJavascriptInterface RCEs remain"}
    caps = tag_capabilities(f)
    assert "WEBVIEW" not in caps
    assert "JS_INTERFACE" not in caps

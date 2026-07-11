"""
Strategic coverage — phase-1 deliverables.

A — JNI symbol-level attribution (Android): parse statically-registered native
    methods (Java_* in .dynsym, survive stripping), detect JNI_OnLoad/RegisterNatives,
    attribute native-extracted secrets to the .so's JNI surface, emit an inventory.
B — iOS shallow taint (minimal first pass): same-file source→sink co-occurrence
    (URL-scheme/pasteboard/keychain sources → WebView/file/network sinks).
"""
from __future__ import annotations

import os
import sys
import tempfile

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import elf_analyzer as elf  # noqa: E402
from analyzers import ios_analyzer as ios  # noqa: E402


# ── A: JNI ───────────────────────────────────────────────────────────────────

def test_demangle_jni():
    assert elf._demangle_jni("Java_com_example_app_Crypto_nativeDecrypt") == "com.example.app.Crypto.nativeDecrypt"
    assert elf._demangle_jni("Java_com_ex_Foo_get_1key") == "com.ex.Foo.get_key"  # _1 -> underscore
    # overload signature suffix is dropped
    assert elf._demangle_jni("Java_a_B_m__Ljava_lang_String_2") == "a.B.m"


def test_extract_jni_surface_from_bytes():
    # Java_* symbols live in .dynsym string table → present in raw bytes even stripped.
    data = (b"\x00Java_com_app_Crypto_nativeDecrypt\x00Java_com_app_Net_baseUrl\x00"
            b"JNI_OnLoad\x00RegisterNatives\x00noise")
    jni = elf._extract_jni_surface(data)
    assert jni["static_methods"] == ["com.app.Crypto.nativeDecrypt", "com.app.Net.baseUrl"]
    assert jni["static_method_count"] == 2
    assert jni["has_jni_onload"] is True
    assert jni["uses_register_natives"] is True


def test_extract_jni_surface_empty_when_no_jni():
    assert elf._extract_jni_surface(b"just some strings, no jni here") == {}


def test_emit_jni_surface_attributes_secret_and_emits_finding():
    jni = elf._extract_jni_surface(b"Java_com_app_Crypto_nativeKey\x00JNI_OnLoad\x00RegisterNatives")
    results = {"findings": [],
               "secrets": [{"file_path": "lib/arm64-v8a/libcrypto.so", "name": "AWS Key", "value": "x"}]}
    bins = [{"name": "libcrypto.so", "path": "lib/arm64-v8a/libcrypto.so", "jni": jni}]
    elf._emit_jni_surface(bins, results)
    assert len(results["jni_surface"]) == 1
    # native secret attributed to the library's JNI methods
    sec = results["secrets"][0]
    assert sec["jni_library"] == "libcrypto.so"
    assert "com.app.Crypto.nativeKey" in sec["jni_native_methods"]
    # inventory finding emitted, noting dynamic registration
    f = next(f for f in results["findings"] if f["rule_id"] == "native_jni_surface")
    assert f["severity"] == "info"
    assert f["jni_uses_register_natives"] is True
    assert "RegisterNatives" in f["description"]


def test_no_jni_surface_emits_nothing():
    results = {"findings": [], "secrets": []}
    elf._emit_jni_surface([{"name": "libc.so", "path": "lib/libc.so"}], results)  # no "jni" key
    assert "jni_surface" not in results
    assert results["findings"] == []


# ── B: iOS shallow taint ─────────────────────────────────────────────────────

def _write(root, name, content):
    with open(os.path.join(root, name), "w", encoding="utf-8") as f:
        f.write(content)


def test_ios_url_scheme_to_webview_flow():
    with tempfile.TemporaryDirectory() as root:
        _write(root, "Handler.swift",
               "func application(_ a: UIApplication, open url: URL) -> Bool {\n"
               "  let t = url.absoluteString\n"
               "  webView.loadRequest(URLRequest(url: URL(string: t)!))\n"
               "  return true\n}\n")
        results = {"findings": []}
        ios._ios_shallow_taint(root, results)
    flows = {(t["source_cat"], t["sink_cat"]): t for t in results["taint_flows"]}
    assert ("URL Scheme", "WebView") in flows
    assert flows[("URL Scheme", "WebView")]["risk"] == "high"
    f = next(f for f in results["findings"] if f["rule_id"].endswith("url-scheme-webview")
             or "URL Scheme" in f["title"])
    assert f["severity"] == "high" and f["source"] == "iOS_TAINT"
    assert f["taint_flow"]["source_cat"] == "URL Scheme"


def test_ios_keychain_source_is_sensitive():
    with tempfile.TemporaryDirectory() as root:
        _write(root, "K.swift",
               "func f() {\n  let key = SecItemCopyMatching(q, &r)\n"
               "  FileManager.default.createFile(atPath: p, contents: key)\n}\n")
        results = {"findings": []}
        ios._ios_shallow_taint(root, results)
    flows = {(t["source_cat"], t["sink_cat"]): t for t in results["taint_flows"]}
    assert ("Keychain", "FileSystem") in flows
    assert flows[("Keychain", "FileSystem")]["risk"] == "high"  # sensitive source


def test_ios_forward_flow_only():
    # Sink BEFORE the source (backward) must not be paired.
    with tempfile.TemporaryDirectory() as root:
        _write(root, "B.swift",
               "func f() {\n  FileManager.default.removeItem(atPath: p)\n"  # sink line 2
               + "\n" * 30 +
               "  let key = SecItemCopyMatching(q, &r)\n}\n")            # source ~line 33
        results = {"findings": []}
        ios._ios_shallow_taint(root, results)
    assert ("Keychain", "FileSystem") not in {(t["source_cat"], t["sink_cat"]) for t in results["taint_flows"]}


def test_ios_benign_file_no_flow():
    with tempfile.TemporaryDirectory() as root:
        _write(root, "P.swift", "let x = 1\nprint(\"hello\")\n")
        results = {"findings": []}
        ios._ios_shallow_taint(root, results)
    assert results.get("taint_flows", []) == []
    assert results["findings"] == []


def test_ios_flows_are_android_compatible_shape():
    with tempfile.TemporaryDirectory() as root:
        _write(root, "H.swift",
               "func g(url: URL) {\n  let h = url.host\n"
               "  URLSession.shared.dataTask(with: URLRequest(url: url))\n}\n")
        results = {"findings": []}
        ios._ios_shallow_taint(root, results)
    t = results["taint_flows"][0]
    for k in ("source", "source_cat", "sink", "sink_cat", "risk", "call_chain",
              "class_name", "file", "line", "owner_type"):
        assert k in t, f"missing {k} (Android taint-flow parity)"


# ── display gating: verbose_only (Q3) ────────────────────────────────────────

def test_jni_finding_is_verbose_only():
    jni = elf._extract_jni_surface(b"Java_com_app_A_m\x00JNI_OnLoad")
    results = {"findings": [], "secrets": []}
    elf._emit_jni_surface([{"name": "libx.so", "path": "lib/libx.so", "jni": jni}], results)
    f = next(f for f in results["findings"] if f["rule_id"] == "native_jni_surface")
    assert f.get("verbose_only") is True


def test_ios_taint_finding_is_verbose_only():
    with tempfile.TemporaryDirectory() as root:
        _write(root, "H.swift",
               "func g(url: URL) {\n  let h = url.host\n"
               "  URLSession.shared.dataTask(with: URLRequest(url: url))\n}\n")
        results = {"findings": []}
        ios._ios_shallow_taint(root, results)
    assert results["findings"] and all(f.get("verbose_only") for f in results["findings"])


def test_default_view_hides_verbose_only_full_export_keeps_it():
    import pytest
    pg = pytest.importorskip("report.pdf_generator")
    findings = [
        {"title": "real", "ownership_label": "APPLICATION", "is_app_code": True, "overall_confidence": 90},
        {"title": "jni", "verbose_only": True, "severity": "info"},
        {"title": "iostaint", "verbose_only": True, "overall_confidence": 55, "is_app_code": True},
    ]
    default = pg._visible_findings({"findings": findings, "_report_findings_scope": "application"})
    assert [f["title"] for f in default] == ["real"], "verbose_only hidden in the default view"
    full = pg._visible_findings({"findings": findings, "_report_findings_scope": "all"})
    assert len(full) == 3, "full export retains verbose_only findings"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")

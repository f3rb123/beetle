"""
Regression: iOS MD5/SHA-1 (and other code-pattern) hits inside a COMPILED binary —
the Dart AOT Mach-O (Payload/Runner.app/Runner, libapp.dylib, App.framework/App) or a
bundled Pod framework binary whose evidence path is a bare "Module:offset" — were
classified APPLICATION/UNKNOWN and stayed HIGH. They are offset-only string-table
matches with no reviewable app source, so ownership now classifies them as framework/
library (mirroring Android's libapp.so treatment) and demote_library_code_findings
drops them to INFO. Genuine app-owned Swift/ObjC source keeps its severity.

Android classification must be byte-identical (all additions are platform=="ios"-guarded).
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers.canonical_finding import CanonicalFinding  # noqa: E402
from analyzers.ownership import get_engine  # noqa: E402
from analyzers.ownership.types import OwnerType, OwnershipContext  # noqa: E402
from analyzers import finding_model  # noqa: E402


def _own(path, platform="ios"):
    f = CanonicalFinding(title="Weak Hash Algorithm (MD5/SHA-1) Used",
                         file_path=path, platform=platform)
    return get_engine().classify(f, OwnershipContext(platform=platform)).owner_type


_LIB = {OwnerType.THIRD_PARTY_SDK, OwnerType.GOOGLE_SDK, OwnerType.APPLE_FRAMEWORK,
        OwnerType.OPEN_SOURCE_LIBRARY, OwnerType.VENDOR_SDK, OwnerType.GENERATED_CODE,
        OwnerType.ANDROID_FRAMEWORK}


# ── ownership classification ─────────────────────────────────────────────────

def test_dart_aot_main_binary_is_framework():
    for p in ("Payload/Runner.app/Runner",
              "Payload/Runner.app/Frameworks/App.framework/App",
              "libapp.dylib", "libflutter.dylib"):
        assert _own(p) in _LIB, f"AOT/compiled binary must be library-owned: {p}"


def test_bare_pod_module_offset_path_is_library():
    # Known pod resolves to its SDK; unknown bundled framework → generic third-party.
    assert _own("FirebaseCrashlytics:7173") in _LIB
    assert _own("webview_flutter_wkwebview:412") == OwnerType.THIRD_PARTY_SDK


def test_app_owned_swift_source_keeps_ownership():
    # Real, reviewable source is NOT treated as a compiled binary.
    assert _own("Payload/Runner.app/CryptoUtil.swift") == OwnerType.APPLICATION
    for p in ("Crypto.swift", "Hash.m", "sources/com/app/Hash.swift"):
        assert _own(p) not in _LIB, f"app source must not be library-owned: {p}"


# ── end-to-end: demotion drops severity for AOT/library, keeps app source ─────

def _annotate_and_demote(findings, platform="ios"):
    results = {"platform": platform, "findings": findings,
               "app_info": {"bundle_id": "io.checkin"}}
    from analyzers import ownership
    ownership.annotate(results)
    finding_model.demote_library_code_findings(results)
    return results["findings"]


def test_aot_md5_demoted_app_md5_kept():
    aot = {"rule_id": "ios_weak_hash", "source": "SAST", "severity": "high",
           "title": "Weak Hash Algorithm (MD5/SHA-1) Used",
           "file_path": "Payload/Runner.app/Runner", "line": 7173}
    pod = {"rule_id": "ios_weak_hash", "source": "SAST", "severity": "high",
           "title": "Weak Hash Algorithm (MD5/SHA-1) Used",
           "file_path": "FirebaseCrashlytics:9001", "line": 9001}
    app = {"rule_id": "ios_weak_hash", "source": "SAST", "severity": "high",
           "title": "Weak Hash Algorithm (MD5/SHA-1) Used",
           "file_path": "Payload/Runner.app/CryptoUtil.swift", "line": 12}
    out = _annotate_and_demote([aot, pod, app])
    by_path = {f["file_path"]: f for f in out}
    assert by_path["Payload/Runner.app/Runner"]["severity"] == "info"
    assert by_path["Payload/Runner.app/Runner"].get("library_noise") is True
    assert by_path["FirebaseCrashlytics:9001"]["severity"] == "info"
    assert by_path["Payload/Runner.app/CryptoUtil.swift"]["severity"] == "high"
    assert by_path["Payload/Runner.app/CryptoUtil.swift"].get("library_noise") is not True


def test_app_source_with_reachability_never_demoted():
    # A taint-backed finding is a real reachable weakness — kept even if library-owned.
    reachable = {"rule_id": "ios_weak_hash", "source": "SAST", "severity": "high",
                 "title": "x", "file_path": "libapp.dylib", "line": 1,
                 "taint_flow": {"source": "URL", "sink": "hash"}}
    out = _annotate_and_demote([reachable])
    assert out[0]["severity"] == "high"


# ── Android must be byte-identical ───────────────────────────────────────────

def test_android_classification_unchanged():
    # None of the iOS additions may alter Android ownership.
    assert _own("sources/com/app/Crypto.java", "android") == OwnerType.UNKNOWN
    assert _own("sources/androidx/core/Foo.java", "android") == OwnerType.THIRD_PARTY_SDK
    assert _own("libapp.so", "android") == OwnerType.UNKNOWN  # handled by elf_analyzer, not here


def test_android_md5_severity_untouched():
    # An Android SAST MD5 in app code keeps its severity (UNKNOWN owner → not demoted).
    a = {"rule_id": "android_weak_hash", "source": "SAST", "severity": "high",
         "title": "x", "file_path": "sources/com/app/Crypto.java", "line": 3}
    out = _annotate_and_demote([a], platform="android")
    assert out[0]["severity"] == "high"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))

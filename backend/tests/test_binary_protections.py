"""Per-binary protection table + THE Dart-AOT false-positive guard (RUN 9).

MobSF flags missing stack canary AND missing ARC as HIGH on App.framework/App. That binary is
the Dart AOT snapshot — the app's own compiled Dart code, the iOS twin of Android's libapp.so.
It is produced by the Dart compiler, not clang, so it has no canary and no ARC by construction.
Copying that finding is the false positive Beetle exists to avoid.

RUN 8 locked this guard for IMPORT-SYMBOL findings. These tests lock it from the other angle:
PROTECTION-FLAG findings.
"""
from analyzers import binary_protections as bp

DART_AOT = {
    "binary": "Frameworks/App.framework/App", "is_dart_aot": True,
    "has_stack_canary": False, "has_arc": False, "objc_import_count": 0,
    "has_nx_stack": True, "has_code_signature": True,
}
PURE_C = {   # nanopb: a C protobuf library — zero ObjC runtime imports
    "binary": "Frameworks/nanopb.framework/nanopb", "is_dart_aot": False,
    "has_stack_canary": True, "has_arc": False, "objc_import_count": 0,
    "has_nx_stack": True, "has_code_signature": True,
}
REAL_FRAMEWORK = {   # connectivity_plus: genuine ObjC framework, genuinely missing a canary
    "binary": "Frameworks/connectivity_plus.framework/connectivity_plus", "is_dart_aot": False,
    "has_stack_canary": False, "has_arc": True, "objc_import_count": 10,
    "has_nx_stack": True, "has_code_signature": True,
}
# This app ships no app-owned NATIVE binary that lacks a canary, so (b) below needs a synthetic
# one: the app's own native code (owner == APPLICATION), NOT the Dart-AOT blob.
APP_OWN_NATIVE = {
    "binary": "Frameworks/MyAppCore.framework/MyAppCore", "is_dart_aot": False,
    "has_stack_canary": False, "has_arc": True, "objc_import_count": 12,
    "has_nx_stack": True, "has_code_signature": True,
}
MAIN = {
    "binary": "Runner", "is_dart_aot": False, "has_stack_canary": True, "has_arc": True,
    "objc_import_count": 39, "has_pie": True, "has_nx_stack": True, "has_code_signature": True,
}


def _owner_of(rel):
    """Stand-in for the Ownership Engine: only the synthetic app-own binary is APPLICATION."""
    return "Application" if "MyAppCore" in rel else "ThirdPartySDK"


def _findings(*binaries, main="Runner"):
    rows = bp.build_table(list(binaries), main_binary=main, owner_of=_owner_of)
    return rows, bp.build_findings(rows)


# ── THE GUARD ────────────────────────────────────────────────────────────────
def test_dart_aot_blob_never_produces_a_missing_canary_or_arc_finding():
    _rows, (findings, suppressed) = _findings(MAIN, DART_AOT)
    assert findings == [], "App.framework/App must not produce ANY missing-protection finding"
    reasons = {s["binary"] for lst in suppressed.values() for s in lst}
    assert "Frameworks/App.framework/App" in reasons
    # And it is suppressed with a REASON, not silently dropped.
    assert any("Dart AOT" in s["reason"] for s in suppressed["stack_canary"])


def test_dart_aot_is_detected_by_content_not_filename():
    # A framework literally named "App" that is NOT a Dart snapshot is still a real framework.
    impostor = dict(REAL_FRAMEWORK, binary="Frameworks/App.framework/App", is_dart_aot=False)
    _rows, (findings, _sup) = _findings(MAIN, impostor)
    assert findings, "a real native framework must still be flagged, whatever it is called"


def test_flutter_engine_is_not_mistaken_for_the_dart_aot_blob():
    # Flutter.framework/Flutter exports ObjC classes named FlutterDartProject — a naive "Dart"
    # substring match would suppress a REAL framework. It has a canary, so nothing is flagged,
    # but it must be classified as a native framework, not as the AOT blob.
    flutter = {"binary": "Frameworks/Flutter.framework/Flutter", "is_dart_aot": False,
               "has_stack_canary": True, "has_arc": True, "objc_import_count": 29}
    rows = bp.build_table([flutter])
    assert rows[0]["kind"] == bp.KIND_FRAMEWORK


# ── the second FP class: ARC is meaningless without ObjC ──────────────────────
def test_pure_c_library_is_not_flagged_for_missing_arc():
    _rows, (findings, suppressed) = _findings(MAIN, PURE_C)
    assert not any(f["rule_id"] == "macho_missing_arc" for f in findings), (
        "a library with zero ObjC imports cannot use ARC — 'missing ARC' is meaningless")
    assert any("cannot use ARC" in s["reason"] for s in suppressed["arc"])


# ── genuine gaps ARE reported ────────────────────────────────────────────────
def test_genuine_native_framework_missing_canary_is_reported():
    _rows, (findings, _sup) = _findings(MAIN, REAL_FRAMEWORK)
    canary = [f for f in findings if f["rule_id"] == "macho_missing_stack_canary"]
    assert len(canary) == 1
    assert canary[0]["affected_binaries"] == [REAL_FRAMEWORK["binary"]]


def test_findings_are_consolidated_not_one_per_binary():
    other = dict(REAL_FRAMEWORK, binary="Frameworks/battery_plus.framework/battery_plus")
    _rows, (findings, _sup) = _findings(MAIN, REAL_FRAMEWORK, other)
    canary = [f for f in findings if f["rule_id"] == "macho_missing_stack_canary"]
    assert len(canary) == 1, "one consolidated finding, not one per binary"
    assert len(canary[0]["affected_binaries"]) == 2


# ── severity is OWNERSHIP-based, locked from both sides ──────────────────────
def test_vendor_framework_missing_protection_is_medium_never_high():
    # (a) A vendor framework's missing canary is a real hardening gap in SOMEONE ELSE'S code,
    # not a directly exploitable app weakness. HIGH overstates it (MobSF calls it HIGH).
    _rows, (findings, _sup) = _findings(MAIN, REAL_FRAMEWORK)
    canary = [f for f in findings if f["rule_id"] == "macho_missing_stack_canary"]
    assert canary and canary[0]["severity"] == "medium"
    assert canary[0]["owner_class"] == "vendor"
    assert all(f["severity"] != "high" for f in findings)


def test_app_owned_native_binary_missing_canary_is_high():
    # (b) The app itself shipped unhardened NATIVE code and owns the fix -> HIGH.
    _rows, (findings, _sup) = _findings(MAIN, APP_OWN_NATIVE)
    high = [f for f in findings if f["severity"] == "high"]
    assert len(high) == 1, "app-owned native code missing a canary must be HIGH"
    assert high[0]["owner_class"] == "app"
    assert high[0]["affected_binaries"] == [APP_OWN_NATIVE["binary"]]


def test_app_owned_and_vendor_gaps_are_reported_separately():
    _rows, (findings, _sup) = _findings(MAIN, APP_OWN_NATIVE, REAL_FRAMEWORK)
    by_sev = {f["severity"]: f for f in findings if "canary" in f["rule_id"]}
    assert by_sev["high"]["affected_binaries"] == [APP_OWN_NATIVE["binary"]]
    assert by_sev["medium"]["affected_binaries"] == [REAL_FRAMEWORK["binary"]]


def test_dart_aot_is_never_high_even_though_it_is_the_apps_own_code():
    # The AOT blob IS the app's own code, but it is a Dart snapshot, not clang-compiled native
    # code -- a canary was never applicable. It must stay suppressed, never promoted to HIGH.
    dart_owned = dict(DART_AOT)
    _rows, (findings, suppressed) = _findings(MAIN, dart_owned)
    assert findings == []
    assert any("Dart AOT" in s["reason"] for s in suppressed["stack_canary"])


# ── the table itself ─────────────────────────────────────────────────────────
def test_main_executable_is_first_and_pie_is_main_only():
    rows = bp.build_table([REAL_FRAMEWORK, DART_AOT, MAIN], main_binary="Runner")
    assert rows[0]["binary"] == "Runner"
    assert rows[0]["pie"] is True
    # PIE is meaningless for a dylib/framework — do not report it as "missing".
    assert all(r["pie"] is None for r in rows[1:])

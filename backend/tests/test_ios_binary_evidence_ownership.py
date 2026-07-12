"""The compiled-binary demotion must be narrow: authoritative import-table evidence keeps its
severity, but the Dart-AOT false-positive class stays demoted.

Beetle's core differentiator over MobSF is that App.framework/App and libapp.so (the Dart AOT
blob) never produce HIGH missing-canary/ARC findings. That guard lives in
ownership.engine._match_ios_binary, which demotes any finding whose evidence sits in a compiled
Mach-O. RUN 8 carved ONE narrow exemption out of it — evidence_type == "imported_symbol" —
because a dynamic-import-table entry proves the binary links that function, unlike an
offset-only string-table match.

These tests lock BOTH directions. If a future change widens the exemption (e.g. to "any
high-confidence binary finding"), direction (b) fails and the FP guard is protected.
"""
from analyzers.canonical_finding import CanonicalFinding
from analyzers.ownership import get_engine, is_library_owner
from analyzers.ownership.types import OwnershipContext, OwnerType

IOS = OwnershipContext(platform="ios")


def _classify(**kw):
    return get_engine().classify(CanonicalFinding(platform="ios", **kw), IOS)


# ── (a) authoritative import-table evidence is NOT demoted ───────────────────
def test_imported_symbol_on_main_binary_is_app_owned():
    # Attributed with the FULL bundle-relative path: a bare "Runner" is mistaken for a
    # CocoaPod by the iOS path stage (it synthesises "/Pods/Runner/") and demoted as a
    # third-party SDK -- which misreported the app's own imports as a vendor problem.
    res = _classify(
        title="Binary Imports Insecure C APIs",
        file_path="Payload/Runner.app/Runner",
        evidence_type="imported_symbol",
        severity="medium",
    )
    assert not is_library_owner(res.owner_type), (
        "an import-table hit is authoritative linkage, not offset-only string noise")
    assert res.matched_rule != "ios_compiled_binary"


def test_imported_symbol_never_hits_the_compiled_binary_demotion_rule():
    # The exemption keys on the EVIDENCE KIND, not on which file it landed in.
    res = _classify(
        title="Binary Imports Uncontrolled Allocation (malloc)",
        file_path="Payload/Runner.app/Runner",
        evidence_type="imported_symbol",
        severity="medium",
    )
    assert res.matched_rule != "ios_compiled_binary"


# ── (b) the Dart-AOT FP class IS still demoted (RUN 9 / RUN 15 guard) ────────
def test_dart_aot_protection_flag_finding_is_still_demoted():
    # Missing stack canary / ARC on the Dart AOT blob — the exact false positive class that
    # must NEVER surface as a HIGH application finding. No evidence_type => not exempt.
    # App.framework/App is caught even earlier by the Flutter fingerprint. What must hold is
    # the PROPERTY: it stays library-owned, so it can never be a HIGH application finding.
    for title in ("Missing Stack Canary", "ARC Not Enabled"):
        res = _classify(title=title, file_path="Frameworks/App.framework/App", severity="high")
        assert is_library_owner(res.owner_type), title
        assert res.owner_type != OwnerType.APPLICATION, title


def test_dart_aot_string_index_finding_is_still_demoted():
    # The RUN 4 class: a rule "match" inside the extracted-strings listing of a Mach-O,
    # whose line is really a string index. Still offset-only evidence => still demoted.
    res = _classify(
        title="MD5 Hash Function Used",
        file_path="Payload/Runner.app/Runner",
        evidence_type="code_pattern",
        severity="high",
    )
    assert is_library_owner(res.owner_type)
    assert res.matched_rule == "ios_compiled_binary"


def test_libapp_so_dart_aot_still_demoted():
    res = _classify(title="Missing Stack Canary", file_path="libapp.so", severity="high")
    assert is_library_owner(res.owner_type)


def test_exemption_is_narrow_not_confidence_based():
    # A high-confidence finding that is NOT import-table evidence must stay demoted --
    # the exemption keys on evidence KIND, never on confidence.
    res = _classify(
        title="Weak Crypto In Binary",
        file_path="Payload/Runner.app/Runner",
        evidence_type="code_pattern",
        severity="high",
        confidence=99,
    )
    assert is_library_owner(res.owner_type)
    assert res.matched_rule == "ios_compiled_binary"


# ── RUN 9: protection-flag evidence is authoritative too ─────────────────────
def test_protection_flag_on_the_main_binary_resolves_to_application():
    # RUN 9 keys HIGH-vs-MEDIUM off THIS verdict. If the app's own main executable classified as
    # a library here, an app-owned missing canary could never be HIGH -- the rule would be dead
    # code. A protection flag is read from the Mach-O's load commands / symbol table: a
    # structural fact, exactly like an import-table entry.
    res = _classify(
        title="Framework Binaries Without Stack Canary",
        file_path="Payload/Runner.app/Runner",
        evidence_type="binary_protection",
        severity="high",
    )
    assert res.owner_type == OwnerType.APPLICATION
    assert not is_library_owner(res.owner_type)


def test_protection_flag_on_a_vendor_framework_stays_library_owned():
    # The other side: a bundled vendor framework is still the vendor's code -> MEDIUM, not HIGH.
    res = _classify(
        title="Framework Binaries Without Stack Canary",
        file_path="Payload/Runner.app/Frameworks/connectivity_plus.framework/connectivity_plus",
        evidence_type="binary_protection",
        severity="medium",
    )
    assert is_library_owner(res.owner_type)

"""RUN 26 (L1) — an Android finding whose primary proof is a compiled binary (.dex/.so/.arsc)
must render as BINARY evidence, not as a source file:line.

When an APK has no decompilable source, string_analyzer/scan_storage dump the printable strings of
classes.dex / *.so and scan those. A rule/secret match then carries an INDEX into that strings
listing — not a source line — exactly like an iOS Mach-O match. The evidence view must card it
(artifact=True, line=0, string_index set) so no surface (PDF, panel, SARIF) prints a phantom
file:line. This carding existed for iOS only (RUN 4/20); RUN 26 extends it to Android.
"""
from analyzers.evidence_selection.view import build_evidence_view


def _finding(primary_file, line=1234, snippet="AKIAIOSFODNN7EXAMPLE"):
    return {
        "title": "Hardcoded Credential", "rule_id": "android_hardcoded_secret",
        "evidence_selection": {
            "primary": {"file_path": primary_file, "line": line, "snippet": snippet,
                        "owner_type": "Application"},
            "supporting": [], "rejected": [],
        },
    }


def test_android_dex_primary_is_carded_as_binary():
    view = build_evidence_view(_finding("classes.dex"), platform="android")
    assert view.get("binary") is True, "a .dex primary must render as binary evidence"
    prim = view["primary"]
    assert prim["line"] == 0, "the string-index must never be shown as a source line"
    assert prim.get("string_index") == 1234, "the index is preserved as string_index, not line"
    assert prim.get("artifact") is True


def test_android_so_and_arsc_primary_are_carded():
    for f in ("lib/arm64-v8a/libnative.so", "resources.arsc", "classes.dex.txt"):
        view = build_evidence_view(_finding(f), platform="android")
        assert view.get("binary") is True, f"{f} must render as binary evidence"
        assert view["primary"]["line"] == 0


def test_android_real_source_is_not_carded():
    view = build_evidence_view(_finding("sources/com/app/Login.java", line=42),
                               platform="android")
    assert not view.get("binary"), "a .java primary is real source — never card it"
    assert view["primary"]["line"] == 42, "a real source line must be preserved"


def test_ios_macho_still_carded_regression():
    """The pre-existing iOS carding must be unchanged."""
    view = build_evidence_view(_finding("Payload/Runner.app/Runner", line=7),
                               platform="ios")
    assert view.get("binary") is True, "iOS Mach-O carding must still fire"
    assert view["primary"]["line"] == 0

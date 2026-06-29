"""
Scan Target abstraction (Phase 2.6 refinement) — registry resolution.

Verifies the ingestion layer is data-driven (resolve by extension → target),
so adding a future target needs no change to the upload endpoint or job runner.

Run: ``python -m pytest tests/test_scan_targets.py`` from the backend directory.
"""
from __future__ import annotations

from analyzers import scan_targets


def test_resolve_known_targets():
    apk = scan_targets.resolve_target(".apk")
    assert apk and apk.id == "android" and apk.platform == "android" and apk.needs_decompile

    ipa = scan_targets.resolve_target(".ipa")
    assert ipa and ipa.id == "ios" and ipa.platform == "ios" and not ipa.needs_decompile

    repo = scan_targets.resolve_target(".zip")
    assert repo and repo.id == "repository" and repo.platform == "cicd"
    assert not repo.needs_decompile


def test_resolve_accepts_filename_or_bare_ext():
    assert scan_targets.resolve_target("MyApp.APK").id == "android"   # case-insensitive
    assert scan_targets.resolve_target("repo.zip").id == "repository"
    assert scan_targets.resolve_target("apk").id == "android"         # bare ext, no dot


def test_unknown_target_is_none():
    assert scan_targets.resolve_target(".exe") is None
    assert scan_targets.resolve_target("") is None


def test_accepted_extensions():
    exts = scan_targets.accepted_extensions()
    assert set(exts) == {".apk", ".ipa", ".zip"}


def test_every_target_has_callable_analyze():
    for t in scan_targets.SCAN_TARGETS:
        assert callable(t.analyze)
        assert t.extensions and all(e.startswith(".") for e in t.extensions)
        assert t.platform

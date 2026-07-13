"""RUN 27 — the iOS Source Explorer file tree must enumerate the ipa_extract bundle.

The tree is populated from list_source_files (/api/scans/{id}/files). It listed jadx/apktool/
apk_extract/repo but NEVER ipa_extract, so an iOS scan returned an empty tree and the UI fell back
to sparse finding-evidence paths (mostly Mach-O binaries that correctly card). This lists the
VIEWABLE bundle files (plists, JSON, config, text) so an analyst can browse them; compiled
binaries (Mach-O executables, .dylib, embedded.mobileprovision) are excluded — they only card.
"""
import decompiler


def _make_ipa_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(decompiler, "SCAN_DIR", tmp_path)
    base = tmp_path / "scan-ios" / "ipa_extract" / "Payload" / "Runner.app"
    (base / "Frameworks").mkdir(parents=True)
    # viewable
    (base / "GoogleService-Info.plist").write_bytes(b"bplist00stub")
    (base / "Info.plist").write_text("<plist/>")
    (base / "Frameworks" / "login_config.json").write_text('{"k":1}')
    (base / "en.strings").write_text('"a"="b";')
    # binaries — must NOT be listed
    (base / "Runner").write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 40)
    (base / "embedded.mobileprovision").write_bytes(b"\x30\x82\xff\xff")
    (base / "Frameworks" / "App").write_bytes(b"\xcf\xfa\xed\xfe")
    return "scan-ios"


def test_ipa_extract_lists_viewable_and_excludes_binaries(tmp_path, monkeypatch):
    sid = _make_ipa_scan(tmp_path, monkeypatch)
    listing = decompiler.list_source_files(sid)
    assert "ipa_extract" in listing, "iOS bundle must be enumerated"
    # Normalise the OS separator (production runs in a Linux container → '/'; dev is Windows).
    files = {f.replace("\\", "/") for f in listing["ipa_extract"]}
    # viewable files present
    assert "Payload/Runner.app/GoogleService-Info.plist" in files
    assert "Payload/Runner.app/Info.plist" in files
    assert "Payload/Runner.app/Frameworks/login_config.json" in files
    assert "Payload/Runner.app/en.strings" in files
    # compiled binaries excluded (they render as cards, not source)
    assert not any(f.endswith("/Runner") for f in files)
    assert not any("mobileprovision" in f for f in files)
    assert not any(f.endswith("/App") for f in files)


def test_android_scan_has_no_ipa_extract_key(tmp_path, monkeypatch):
    """An Android-style scan (no ipa_extract dir) must be unaffected."""
    monkeypatch.setattr(decompiler, "SCAN_DIR", tmp_path)
    jadx = tmp_path / "scan-android" / "jadx" / "com" / "app"
    jadx.mkdir(parents=True)
    (jadx / "Main.java").write_text("class Main {}")
    listing = decompiler.list_source_files("scan-android")
    assert "ipa_extract" not in listing
    assert "com/app/Main.java" in {f.replace("\\", "/") for f in listing.get("jadx", [])}

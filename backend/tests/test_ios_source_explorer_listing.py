"""RUN 27/28 — the iOS Source Explorer file tree must enumerate the ipa_extract bundle.

The tree is populated from list_source_files (/api/scans/{id}/files). It listed jadx/apktool/
apk_extract/repo but NEVER ipa_extract, so an iOS scan returned an empty tree. RUN 27 added the
subdir; RUN 28 browses the WHOLE bundle — viewable files (plists/JSON/config) open to content,
compiled binaries (Mach-O, .dylib, embedded.mobileprovision) open to the binary card, and a binary
FINDING opens to its symbol + strings. Only pure media/assets (images, fonts, .car) are skipped.
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
    # binaries — now LISTED (they open to the binary card / strings, and back the security categories)
    (base / "Runner").write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 40)
    (base / "embedded.mobileprovision").write_bytes(b"\x30\x82\xff\xff")
    (base / "Frameworks" / "App").write_bytes(b"\xcf\xfa\xed\xfe")
    # pure media/assets — must NOT be listed (noise, never source)
    (base / "AppIcon.png").write_bytes(b"\x89PNG\r\n")
    (base / "font.ttf").write_bytes(b"\x00\x01\x00\x00")
    (base / "Assets.car").write_bytes(b"CAR\x00")
    return "scan-ios"


def test_ipa_extract_lists_bundle_including_binaries_excluding_media(tmp_path, monkeypatch):
    sid = _make_ipa_scan(tmp_path, monkeypatch)
    listing = decompiler.list_source_files(sid)
    assert "ipa_extract" in listing, "iOS bundle must be enumerated"
    # Normalise the OS separator (production runs in a Linux container → '/'; dev is Windows).
    files = {f.replace("\\", "/") for f in listing["ipa_extract"]}
    # viewable files present
    assert "Payload/Runner.app/GoogleService-Info.plist" in files
    assert "Payload/Runner.app/Frameworks/login_config.json" in files
    assert "Payload/Runner.app/en.strings" in files
    # compiled binaries NOW present (browsable → card / strings)
    assert "Payload/Runner.app/Runner" in files
    assert "Payload/Runner.app/embedded.mobileprovision" in files
    assert "Payload/Runner.app/Frameworks/App" in files
    # pure media/assets excluded (noise)
    assert not any(f.endswith((".png", ".ttf", ".car")) for f in files)


def test_android_scan_has_no_ipa_extract_key(tmp_path, monkeypatch):
    """An Android-style scan (no ipa_extract dir) must be unaffected."""
    monkeypatch.setattr(decompiler, "SCAN_DIR", tmp_path)
    jadx = tmp_path / "scan-android" / "jadx" / "com" / "app"
    jadx.mkdir(parents=True)
    (jadx / "Main.java").write_text("class Main {}")
    listing = decompiler.list_source_files("scan-android")
    assert "ipa_extract" not in listing
    assert "com/app/Main.java" in {f.replace("\\", "/") for f in listing.get("jadx", [])}

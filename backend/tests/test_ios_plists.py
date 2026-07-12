"""Property Lists section (RUN 12).

Locks the three rules this surface must not break:
  1. every plist is read through plistlib (binary bplist00 AND xml) — never as text;
  2. raw bytes are NEVER emitted, and anything image-like goes through the RUN 5.1
     renderable_image_bytes() gate, so a CgBI PNG can never reach a report as a broken image;
  3. it emits NO findings — it cross-links to the sections that already report these things
     (ATS -> RUN 10, Firebase keys -> RUN 3, usage descriptions -> RUN 6).
"""
import json
import plistlib
import struct
import zlib

from analyzers import ios_plists
from analyzers.apple_png import PNG_SIG, is_cgbi_png


def _write(path, obj, fmt=plistlib.FMT_BINARY):
    with open(path, "wb") as f:
        plistlib.dump(obj, f, fmt=fmt)


def _cgbi_png() -> bytes:
    """A minimal Apple CgBI PNG — the format every PNG in a shipped iOS bundle uses."""
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    co = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    idat = co.compress(bytes([0, 0, 0, 255, 255])) + co.flush()
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    return (PNG_SIG + chunk(b"CgBI", b"\x50\x00\x20\x06")
            + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b""))


def test_binary_plist_is_decoded_not_read_as_text(tmp_path):
    _write(tmp_path / "Info.plist", {"CFBundleURLTypes": [{"CFBundleURLSchemes": ["myapp"]}]})
    results = {}
    ios_plists.analyze(str(tmp_path), results)
    pl = results["property_lists"]
    assert pl["binary_count"] == 1
    entry = pl["plists"][0]
    assert entry["format"] == "binary"
    # The scheme was recovered from a BINARY plist — text reading would have produced garbage.
    keys = {k["key"]: k["value"] for k in entry["security_keys"]}
    assert "myapp" in keys["CFBundleURLSchemes"]


def test_xml_plist_also_works(tmp_path):
    _write(tmp_path / "App.plist", {"UIFileSharingEnabled": True}, fmt=plistlib.FMT_XML)
    results = {}
    ios_plists.analyze(str(tmp_path), results)
    entry = results["property_lists"]["plists"][0]
    assert entry["format"] == "xml"
    assert entry["security_keys"][0]["value"] == "true"


def test_raw_bytes_are_never_emitted(tmp_path):
    # A plist carrying an Apple CgBI PNG. Emitting those bytes would put an image no browser
    # can decode into the report (RUN 5). The value must be a SUMMARY, never the bytes.
    png = _cgbi_png()
    assert is_cgbi_png(png)
    _write(tmp_path / "Icon.plist", {"API_KEY": "AIzaFake", "blob": png})
    results = {}
    ios_plists.analyze(str(tmp_path), results)
    blob = ios_plists._summarize(png)
    assert isinstance(blob, str) and blob.startswith("<") and "bytes>" in blob
    # Nothing anywhere in the section is a bytes object.
    def no_bytes(o):
        if isinstance(o, bytes):
            raise AssertionError("raw bytes reached the report")
        if isinstance(o, dict):
            for v in o.values():
                no_bytes(v)
        if isinstance(o, list):
            for v in o:
                no_bytes(v)
    no_bytes(results["property_lists"])


def test_image_bytes_are_identified_via_the_renderable_gate(tmp_path):
    # The CgBI PNG is recognised as an image (it passed the RUN 5.1 converter) rather than
    # being dumped as opaque data.
    assert ios_plists._summarize(_cgbi_png()).startswith("<image:")
    # Undecodable junk is NOT called an image.
    assert ios_plists._summarize(b"\x00\x01not an image").startswith("<data:")


def test_firebase_keys_are_cross_linked_not_re_reported(tmp_path):
    _write(tmp_path / "GoogleService-Info.plist",
           {"API_KEY": "AIzaSyFake", "CLIENT_ID": "123.apps.googleusercontent.com"})
    results = {}
    ios_plists.analyze(str(tmp_path), results)
    keys = results["property_lists"]["plists"][0]["security_keys"]
    api = next(k for k in keys if k["key"] == "API_KEY")
    assert "RUN 3" in api["note"], "must point at the existing secret, not duplicate it"


def test_section_emits_no_findings(tmp_path):
    _write(tmp_path / "Info.plist", {"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
                                     "UIFileSharingEnabled": True})
    results = {"findings": []}
    ios_plists.analyze(str(tmp_path), results)
    assert results["findings"] == [], "Property Lists is an enumeration surface, not a detector"


def test_privacy_manifests_are_rolled_up(tmp_path):
    _write(tmp_path / "PrivacyInfo.xcprivacy", {
        "NSPrivacyTracking": False,
        "NSPrivacyTrackingDomains": [],
        "NSPrivacyAccessedAPITypes": [
            {"NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryUserDefaults"}],
        "NSPrivacyCollectedDataTypes": [
            {"NSPrivacyCollectedDataType": "NSPrivacyCollectedDataTypeCrashData"}],
    })
    results = {}
    ios_plists.analyze(str(tmp_path), results)
    pm = results["property_lists"]["privacy_manifests"]
    assert pm["count"] == 1
    assert pm["declares_tracking"] is False
    assert pm["accessed_api_types"][0][0] == "NSPrivacyAccessedAPICategoryUserDefaults"


def test_unreadable_plist_is_recorded_not_crashed(tmp_path):
    (tmp_path / "broken.plist").write_bytes(b"bplist00\x00garbage")
    results = {}
    ios_plists.analyze(str(tmp_path), results)
    entry = results["property_lists"]["plists"][0]
    assert entry["format"] == "unreadable" and entry["error"]


def test_credential_values_are_masked_never_printed_in_the_clear(tmp_path):
    # Enumerating a plist must not become a way to leak the secret the rest of the pipeline is
    # careful to mask. RUN 3 surfaces this key as a MASKED INFO secret; the secret pipeline's
    # cross-scrub has never heard of results["property_lists"], so this surface must mask it
    # itself -- reusing secret_intel.mask_value, not a second implementation.
    raw = "AIzaSyCw2rXeRTyaNxZ3cBm3gUip5sfZ1fW88rI"
    _write(tmp_path / "GoogleService-Info.plist", {"API_KEY": raw, "PROJECT_ID": "demo"})
    results = {}
    ios_plists.analyze(str(tmp_path), results)
    keys = {k["key"]: k for k in results["property_lists"]["plists"][0]["security_keys"]}
    api = keys["API_KEY"]
    assert api["masked"] is True
    assert raw not in api["value"], "the raw API key must never appear"
    assert raw not in json.dumps(results["property_lists"]), "not anywhere in the section"
    assert api["value"].startswith("AIza")          # recognisable shape survives
    # A non-credential key is still shown in full.
    assert keys["PROJECT_ID"]["value"] == "demo"

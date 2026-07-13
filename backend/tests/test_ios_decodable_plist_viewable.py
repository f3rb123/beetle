"""RUN 20 — a decodable binary plist is VIEWABLE, not a binary-evidence card.

RUN 4 made binary detection content-based (magic bytes) and carded every bplist. But a bplist
that plistlib can decode is viewable: the file server renders it as XML, so a finding on it (e.g.
cloud_firebase_storage_bucket on GoogleService-Info.plist) must show that source and scroll to the
real key — not a "Binary Property List" card at a meaningless raw-bplist line.

A truly-opaque blob (embedded.mobileprovision, a CMS/PKCS#7 container plistlib cannot decode) and a
Mach-O binary stay carded. This is the same "viewable" definition the file server uses, so the
finding card and the source viewer never disagree.
"""
import plistlib

from analyzers.ios_analyzer import (
    _record_binary_format_files, _remap_decodable_plist_finding_lines,
)

_MACHO = b"\xcf\xfa\xed\xfe" + b"\x00" * 60          # 64-bit Mach-O magic + padding


def _bundle(tmp_path):
    app = tmp_path / "Payload" / "Runner.app"
    app.mkdir(parents=True)
    # a decodable binary plist
    with open(app / "GoogleService-Info.plist", "wb") as f:
        plistlib.dump({"STORAGE_BUCKET": "demo-app.appspot.com", "API_KEY": "AIzaFake"},
                      f, fmt=plistlib.FMT_BINARY)
    # a Mach-O binary
    (app / "Runner").write_bytes(_MACHO)
    # a non-decodable "binary" that is not a valid plist (mobileprovision-like CMS blob)
    (app / "embedded.mobileprovision").write_bytes(b"\x30\x82\x0a\x00" + b"\xff" * 200)
    return app


def test_decodable_plist_is_not_binary_evidence(tmp_path):
    app = _bundle(tmp_path)
    results = {}
    _record_binary_format_files(str(app), results, str(tmp_path))
    binset = set(results.get("binary_evidence_files") or [])
    assert not any("GoogleService-Info.plist" in x for x in binset), \
        "a decodable bplist is viewable and must not be carded as binary evidence"
    # the Mach-O binary IS binary evidence
    assert any(x.endswith("/Runner") for x in binset)


def test_macho_and_undecodable_blob_stay_binary(tmp_path):
    app = _bundle(tmp_path)
    results = {}
    _record_binary_format_files(str(app), results, str(tmp_path))
    binset = set(results.get("binary_evidence_files") or [])
    assert any(x.endswith("/Runner") for x in binset)
    # embedded.mobileprovision is not bplist-magic, so it is not in this set (the file server
    # cards it via binary_inspector); the point is it is never mistaken for a viewable plist.
    assert not any("mobileprovision" in x for x in binset)


def test_plist_finding_line_remaps_to_the_decoded_xml_line(tmp_path):
    app = _bundle(tmp_path)
    results = {"findings": [{
        "rule_id": "cloud_firebase_storage_bucket",
        "title": "Firebase Storage Bucket Reference — demo-app.appspot.com",
        "file_path": "Payload/Runner.app/GoogleService-Info.plist",
        "line": 3,          # raw bplist parse artifact
        "snippet": "",
    }]}
    _remap_decodable_plist_finding_lines(str(app), results, str(tmp_path))
    f = results["findings"][0]
    assert f["line"] != 3, "the meaningless raw-bplist line must be replaced"
    assert "demo-app.appspot.com" in f["snippet"], "the snippet must anchor the real value"
    # the line points at the STORAGE_BUCKET value in the decoded XML
    xml = plistlib.dumps(plistlib.load(open(app / "GoogleService-Info.plist", "rb")),
                         fmt=plistlib.FMT_XML).decode().split("\n")
    assert "demo-app.appspot.com" in xml[f["line"] - 1]


def test_remap_clears_line_when_no_anchor_found(tmp_path):
    app = _bundle(tmp_path)
    results = {"findings": [{
        "rule_id": "x", "title": "No value here", "snippet": "",
        "file_path": "Payload/Runner.app/GoogleService-Info.plist", "line": 3,
    }]}
    _remap_decodable_plist_finding_lines(str(app), results, str(tmp_path))
    # nothing to anchor on -> clear the artifact line so the viewer content-searches instead
    assert results["findings"][0]["line"] == 0

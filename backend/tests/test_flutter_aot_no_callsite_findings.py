"""
Regression: flutter_analyzer ran code-PATTERN/call-site rules (SharedPreferences,
Hive, sqflite, …) over the PRINTABLE STRINGS of the compiled AOT snapshot
(libapp.so / kernel_blob). A class-name token in the snapshot is a linked symbol,
not a call site, so this produced repeated "SharedPreferences storage (plaintext)"
findings anchored at a bogus libapp.so:NNNN line, which then flooded attack-chain
supporting evidence with identical rows.

Fixes:
  - code-pattern rules run ONLY on real source (.dart) / asset text, never on a blob;
  - a release AOT app emits at most ONE deduped, NON-CHAINABLE INFO capability note
    per capability (no bogus line, do_not_chain=True);
  - a debug app with a real .dart still gets a real source-anchored finding;
  - the chain engine never pulls a do_not_chain finding as a required/supporting step.
"""
from __future__ import annotations

import os
import sys
import tempfile

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import flutter_analyzer as fl  # noqa: E402
from analyzers.attack_chains import engine as eng  # noqa: E402


def _release_app_with_libapp(strings: bytes) -> str:
    root = tempfile.mkdtemp()
    d = os.path.join(root, "lib", "arm64-v8a")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "libapp.so"), "wb") as f:
        f.write(b"\x7fELF\x00\x01" + strings + b"\x00" * 16)
    return root


def _run(root, platform="android"):
    results = {"platform": platform, "app_info": {"package": "com.demo"},
               "findings": [], "secrets": [], "endpoints": []}
    fl.analyze([root], results, platform=platform)
    return results


def _titles(results):
    return [f["title"] for f in results["findings"]]


# ── release AOT: no per-offset call-site findings ────────────────────────────

def test_release_libapp_no_plaintext_storage_finding():
    # "SharedPreferences" appears 5x in the snapshot strings.
    root = _release_app_with_libapp(b"".join([b"SharedPreferences\x00"] * 5) + b"other\x00")
    results = _run(root)
    titles = _titles(results)
    # The old per-offset code-pattern finding must NOT appear.
    assert not any("storage (plaintext)" in t for t in titles), \
        f"AOT blob must not yield a call-site storage finding: {titles}"
    # Instead: exactly one deduped INFO capability note.
    caps = [f for f in results["findings"] if f.get("evidence_type") == "aot_symbol"
            and "SharedPreferences" in f["title"]]
    assert len(caps) == 1, f"expected one deduped capability note, got {len(caps)}"
    note = caps[0]
    assert note["severity"] == "info"
    assert note["line"] in (0, None), "capability note must not carry a bogus line number"
    assert note.get("do_not_chain") is True, "capability note must be non-chainable"


def test_release_capability_note_deduped_across_symbols():
    root = _release_app_with_libapp(b"SharedPreferences\x00Hive\x00sqflite\x00SharedPreferences\x00")
    results = _run(root)
    aot = [f for f in results["findings"] if f.get("evidence_type") == "aot_symbol"]
    keys = [f["title"] for f in aot]
    assert len(keys) == len(set(keys)), f"capability notes must be deduped: {keys}"
    assert all(f.get("do_not_chain") for f in aot)
    assert all(f["line"] == 0 for f in aot)


# ── chain engine must never pull these ───────────────────────────────────────

def test_do_not_chain_findings_excluded_from_chains():
    root = _release_app_with_libapp(b"SharedPreferences\x00SharedPreferences\x00")
    results = _run(root)
    aot = [f for f in results["findings"] if f.get("evidence_type") == "aot_symbol"]
    assert aot, "expected at least one AOT capability note"
    for f in aot:
        assert eng.chain_role(f) == "excluded", \
            "an AOT-symbol capability note must be excluded from chains (required AND supporting)"


# ── debug source (.dart) still yields a real source-anchored finding ─────────

_MAIN_DART = """
void setup() {
  final prefs = SharedPreferences.getInstance();
}
"""


def test_debug_dart_still_flags_real_source():
    root = tempfile.mkdtemp()
    os.makedirs(os.path.join(root, "lib"))
    with open(os.path.join(root, "lib", "main.dart"), "w", encoding="utf-8") as f:
        f.write(_MAIN_DART)
    results = _run(root)
    storage = [f for f in results["findings"] if "storage (plaintext)" in f["title"]]
    assert storage, "a real .dart SharedPreferences call must still be flagged"
    f = storage[0]
    assert f["file_path"].endswith("main.dart")
    assert f["line"] > 0, "a real source finding must carry a real line number"
    assert not f.get("do_not_chain"), "a real source finding stays chain-eligible"


def test_debug_dart_source_anchored_not_blob():
    # The .dart finding is anchored to main.dart, never libapp.so.
    root = tempfile.mkdtemp()
    os.makedirs(os.path.join(root, "lib"))
    with open(os.path.join(root, "lib", "main.dart"), "w", encoding="utf-8") as f:
        f.write(_MAIN_DART)
    results = _run(root)
    for f in results["findings"]:
        assert "libapp.so" not in (f.get("file_path") or ""), \
            "no finding may be anchored to libapp.so on a source build"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")

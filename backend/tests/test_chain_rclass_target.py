"""
Regression: the Hardcoded-Secret chain resolved its code-viewer target to an
auto-generated R-constants class (N0/a.java — 0x7f resource IDs), not the secret's
real evidence. A resource class can never hold a secret, so it must never be a chain
evidence / viewer target; the chain must fall back to the real evidence file
(res/values/strings.xml or the APKLeaks source).

FAILS on old behavior (R-class becomes evidence_references[0]); PASSES on new.
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers.code_analyzer import is_resource_id_target  # noqa: E402
from analyzers.attack_chains import engine as eng  # noqa: E402


# ── guard unit tests ─────────────────────────────────────────────────────────

def test_guard_rejects_r_classes():
    assert is_resource_id_target("sources/com/app/R.java")
    assert is_resource_id_target("sources/com/app/R$layout.java")
    assert is_resource_id_target("sources/com/app/R2.java")
    # Obfuscated R class — no path signal, matched via the recorded set OR snippet.
    assert is_resource_id_target("N0/a.java", "", {"N0/a.java"})
    assert is_resource_id_target("N0/a.java", "public static final int x = 0x7f0a00b3;")


def test_guard_accepts_real_locations():
    assert not is_resource_id_target("res/values/strings.xml")
    assert not is_resource_id_target("sources/com/app/ApiClient.java", "String key = \"secret\";")
    assert not is_resource_id_target("")


# ── chain evidence aggregation falls back to the real file ───────────────────

def test_chain_evidence_skips_rclass_primary():
    # Secret member's PRIMARY resolves to an obfuscated R class; its real evidence
    # (strings.xml:58) is in file_evidence.
    secret = {
        "file_path": "N0/a.java",
        "snippet": "public static final int x = 0x7f0a00b3;",
        "file_evidence": [{"path": "res/values/strings.xml", "lines": [58],
                           "snippet": "artifactory_password"}],
    }
    files, _classes, _methods, refs = eng._aggregate_evidence([secret], {"N0/a.java"})
    ref_files = [r["file"] for r in refs]
    assert "N0/a.java" not in ref_files, "an R-class must never be a chain evidence ref"
    assert "res/values/strings.xml" in ref_files
    assert refs[0]["line"] == 58
    assert "N0/a.java" not in files


def test_chain_evidence_drops_when_only_rclass():
    # If the ONLY location is an R class, emit no bogus ref rather than pointing at it.
    only_r = {"file_path": "sources/com/app/R.java", "file_evidence": []}
    files, _c, _m, refs = eng._aggregate_evidence([only_r], None)
    assert refs == []
    assert files == []


def test_real_finding_unaffected():
    normal = {"file_path": "sources/com/app/ApiClient.java", "line": 42,
              "snippet": "String key = \"x\";", "file_evidence": []}
    _files, _c, _m, refs = eng._aggregate_evidence([normal], {"N0/a.java"})
    assert refs and refs[0]["file"] == "sources/com/app/ApiClient.java" and refs[0]["line"] == 42


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")

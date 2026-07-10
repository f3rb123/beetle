"""
Analyst Workspaces tests — evidence-model regression coverage.

Regression (v1.3 stabilization): enrich_chains crashed with
`AttributeError: 'str' object has no attribute 'get'` whenever a chain member
resolved to a finding whose `evidence` field is proof TEXT (certificate
findings, synthesized chain findings) instead of a structured dict.
`finding["evidence"]` is polymorphic by design — see
finding_model.evidence_dict — and workspace enrichment must accept both shapes.

Runnable standalone or under pytest:
    python -m tests.test_workspaces       # from backend/
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import workspaces  # noqa: E402
from analyzers.finding_model import evidence_dict  # noqa: E402


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


# ── finding_model.evidence_dict contract ─────────────────────────────────────

def test_evidence_dict_accepts_both_shapes():
    _check(evidence_dict({"evidence": {"file_path": "a.java", "line": 3}}) ==
           {"file_path": "a.java", "line": 3},
           "dict evidence must pass through unchanged")
    _check(evidence_dict({"evidence": "Subject: CN=Android Debug"}) == {},
           "string (proof-text) evidence must yield {} — it has no location")
    _check(evidence_dict({}) == {}, "missing evidence must yield {}")
    _check(evidence_dict({"evidence": None}) == {}, "None evidence must yield {}")


# ── _member_evidence on every evidence shape ─────────────────────────────────

def test_member_evidence_string_evidence_does_not_crash():
    """Production repro: cert finding (evidence = formatted text, no file_path)
    referenced as a chain member."""
    cert_finding = {
        "title": "Certificate Signed with SHA-1 — Collision Risk",
        "evidence": "Subject:           CN=whatever\nSignature algo:    SHA1withRSA",
    }
    member = {"title": "Certificate Signed with SHA-1 — Collision Risk"}
    file, line, _view = workspaces._member_evidence(cert_finding, member)
    _check(file == "", f"cert findings have no source file, got {file!r}")
    _check(line == 0, f"cert findings have no line, got {line!r}")
    _check(cert_finding["evidence"].startswith("Subject:"),
           "proof-text evidence must remain untouched on the finding")


def test_member_evidence_dict_evidence_provides_location():
    finding = {
        "title": "Hardcoded API Key",
        "evidence": {"file_path": "sources/com/app/Config.java", "line": 42},
    }
    file, line, _view = workspaces._member_evidence(finding, {})
    _check(file == "sources/com/app/Config.java", f"got {file!r}")
    _check(line == 42, f"got {line!r}")


def test_member_evidence_prefers_finding_fields_over_evidence_dict():
    finding = {
        "file_path": "sources/com/app/Main.java",
        "line": 7,
        "evidence": {"file_path": "sources/other/File.java", "line": 99},
    }
    file, line, _view = workspaces._member_evidence(finding, {})
    _check(file == "sources/com/app/Main.java", f"got {file!r}")
    _check(line == 7, f"got {line!r}")


def test_member_evidence_member_fields_win():
    member = {"file_path": "sources/com/app/FromMember.java"}
    finding = {"evidence": "text only"}
    file, _line, _view = workspaces._member_evidence(finding, member)
    _check(file == "sources/com/app/FromMember.java", f"got {file!r}")


def test_member_evidence_empty_finding():
    file, line, view = workspaces._member_evidence({}, {})
    _check((file, line, view) == ("", 0, None), f"got {(file, line, view)!r}")


# ── enrich_chains end-to-end with mixed evidence shapes ──────────────────────

def test_enrich_chains_with_mixed_evidence_shapes():
    """A chain whose members map to string-evidence AND dict-evidence findings
    must enrich without error and keep every member in chain_evidence."""
    results = {
        "findings": [
            {
                "title": "Attack Chain: Broken Crypto + Hardcoded Key → Data Decryption",
                "is_attack_chain": True,
                "chain_confidence": "HIGH",
                "evidence": "chain narrative text",  # chain_analyzer emits str
                "attack_chain_members": [
                    {"title": "Certificate Signed with SHA-1 — Collision Risk"},
                    {"title": "Hardcoded Encryption Key"},
                ],
            },
            {
                "title": "Certificate Signed with SHA-1 — Collision Risk",
                "evidence": "Subject: CN=x, O=y",  # cert_analyzer emits str
                "confidence_score": 72,
            },
            {
                "title": "Hardcoded Encryption Key",
                "file_path": "sources/com/app/Crypto.java",
                "line": 11,
                "evidence": {"file_path": "sources/com/app/Crypto.java", "line": 11},
                "confidence_score": 80,
            },
        ],
    }
    workspaces.enrich_chains(results)  # must not raise

    chain = results["findings"][0]
    ev = chain.get("chain_evidence")
    _check(isinstance(ev, list) and len(ev) == 2,
           f"both members must be represented, got {ev!r}")
    by_title = {e["title"]: e for e in ev}
    _check(by_title["Certificate Signed with SHA-1 — Collision Risk"]["file"] == "",
           "cert member has no file — must not crash, must not invent one")
    _check(by_title["Hardcoded Encryption Key"]["file"] == "sources/com/app/Crypto.java",
           "dict-evidence member must resolve its file")
    _check("confidence_explanation" in chain,
           "chain must still get its confidence explanation")


if __name__ == "__main__":
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all workspace tests passed")

"""
Evidence Selection Engine tests (Beetle 2.0, Phase 1.96).

Covers the contract end to end:

* Multiple candidate files → the application-owned proof wins; SDK/framework lose.
* Library vs application code (AndroidX / GMS / generated) is correctly demoted.
* Identical findings / single candidate → still get a primary + full reasoning.
* Third-party SDK, generated code → rejected (file-intrinsic), not "supporting".
* Attack-chain / reachability / validation raise the score but never RESCUE a
  library file from rejection (scope separation).
* Multi-engine corroborated file gets a bonus.
* Cross-finding de-noise: a file already chosen elsewhere is penalized.
* Bug Bounty Mode sharpens toward reachable, application-owned proof.
* Extensibility: a registered contributor influences the score.
* Regression: additive (does not mutate file_path), safe on empty/malformed input.

Runnable standalone or under pytest:
    python -m tests.test_evidence_selection       # from backend/
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import evidence_selection as es  # noqa: E402
from analyzers.evidence_selection import scoring  # noqa: E402
from analyzers.ownership import context_from_results  # noqa: E402


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


APP = "com.company.app"


def _results(*findings):
    return {"platform": "android", "app_info": {"package": APP}, "findings": list(findings)}


def _ctx(pkg=APP):
    return context_from_results({"platform": "android", "app_info": {"package": pkg}})


def _f(**kw):
    base = {"title": "Hardcoded Crypto", "severity": "high", "cwe": "CWE-327",
            "file_path": f"sources/{APP.replace('.', '/')}/Pay.java", "line": 12,
            "snippet": "Cipher.getInstance(\"AES/ECB\")"}
    base.update(kw)
    return base


def _ev(path, line=1, snippet="x"):
    return {"path": path, "lines": [line], "snippet": snippet}


# ── Core selection ────────────────────────────────────────────────────────────
def test_application_proof_beats_library():
    f = _f(file_evidence=[
        _ev("sources/androidx/appcompat/Crypto.java", 5),
        _ev("sources/com/google/android/gms/Crypto.java", 8),
        _ev(f"sources/{APP.replace('.', '/')}/PaymentCrypto.java", 12, "Cipher.getInstance(\"AES/ECB\")"),
    ])
    sel = es.select(f, _ctx())
    _check(sel["primary"]["owner_type"] == "Application",
           "application-owned proof must be selected as primary")
    _check(f"{APP.replace('.', '/')}" in sel["primary"]["file_path"], "wrong primary file")


def test_androidx_and_gms_are_rejected_not_supporting():
    f = _f(reachability="YES", in_attack_chain=True, file_evidence=[
        _ev("sources/androidx/appcompat/Crypto.java", 5),
        _ev("sources/com/google/android/gms/Crypto.java", 8),
        _ev(f"sources/{APP.replace('.', '/')}/PaymentCrypto.java", 12),
    ])
    sel = es.select(f, _ctx())
    rejected_files = {r["file_path"] for r in sel["rejected"]}
    _check(any("androidx" in p for p in rejected_files), "AndroidX must be rejected")
    _check(any("gms" in p for p in rejected_files), "GMS must be rejected")
    support_files = {s["file_path"] for s in sel["supporting"]}
    _check(not any(("androidx" in p or "gms" in p) for p in support_files),
           "library files must NOT be promoted to supporting")


def test_finding_signals_do_not_rescue_library():
    """Reachable + attack-chain must not lift a library file's file_score >= 0."""
    f = _f(file_path="sources/androidx/work/Worker.java", line=3,
           reachability="YES", in_attack_chain=True, validated=True,
           file_evidence=[_ev("sources/androidx/work/Worker.java", 3)])
    sel = es.select(f, _ctx())
    # Only candidate → it stays primary, but its file_score must be negative.
    _check(sel["primary"]["file_score"] < 0,
           "a library file's file-intrinsic score must stay negative despite corroboration")


def test_generated_code_demoted():
    # file_path points at the generated file; the real logic is in file_evidence.
    f = _f(file_path=f"sources/{APP.replace('.', '/')}/BuildConfig.java", line=1, snippet="",
           file_evidence=[
               _ev(f"sources/{APP.replace('.', '/')}/BuildConfig.java", 1, ""),
               _ev(f"sources/{APP.replace('.', '/')}/RealLogic.java", 20, "doPayment()"),
           ])
    sel = es.select(f, _ctx())
    _check("RealLogic" in sel["primary"]["file_path"],
           "generated code must lose to real application logic")
    _check(any("BuildConfig" in r["file_path"] for r in sel["rejected"]),
           "generated BuildConfig must be demoted to rejected")


def test_single_candidate_still_gets_primary_and_reason():
    f = _f(file_evidence=[])
    sel = es.select(f, _ctx())
    _check(sel["primary"]["file_path"], "single-candidate finding must still have a primary")
    _check(sel["reason"], "primary must carry a human reason")
    _check(sel["candidate_count"] == 1, "candidate_count should be 1")


def test_attack_chain_and_reachability_raise_total_score():
    common = dict(file_evidence=[_ev(f"sources/{APP.replace('.', '/')}/Pay.java", 12, "y")])
    plain = es.select(_f(**common), _ctx())["primary"]["score"]
    boosted = es.select(_f(reachability="YES", in_attack_chain=True, validated=True, **common),
                        _ctx())["primary"]["score"]
    _check(boosted > plain, "reachability/attack-chain/validation must raise the total score")


def test_multi_engine_file_bonus():
    appfile = f"sources/{APP.replace('.', '/')}/Pay.java"
    f = _f(detected_by=["Beetle Native", "Semgrep"], detection_count=2,
           merged_files=[appfile], file_path=appfile, file_evidence=[_ev(appfile, 12, "y")])
    bullets = es.select(f, _ctx())["primary"]["selected_because"]
    _check(any("Corroborated by" in b for b in bullets),
           "a file seen by multiple engines must get the corroboration bonus")


# ── Cross-finding de-noise ────────────────────────────────────────────────────
def test_already_selected_penalty_across_findings():
    appfile = f"sources/{APP.replace('.', '/')}/Pay.java"
    shared = _ev(appfile, 12, "y")
    other = _ev(f"sources/{APP.replace('.', '/')}/Other.java", 30, "z")
    crit = _f(severity="critical", file_path=appfile, line=12, file_evidence=[shared])
    high = _f(severity="high", file_path=appfile, line=12,
              file_evidence=[shared, other])
    res = _results(high, crit)  # deliberately out of severity order
    es.annotate(res, platform="android")
    # The critical finding (processed first) should claim the shared file; the high
    # finding should then prefer the un-claimed Other.java for its primary.
    high_primary = high["evidence_selection"]["primary"]["file_path"]
    _check("Other.java" in high_primary,
           "a file already chosen by a higher-severity finding should be de-prioritized")


# ── Bug Bounty Mode ───────────────────────────────────────────────────────────
def test_bug_bounty_mode_amplifies_nonapp_penalty():
    f = _f(file_path="sources/com/facebook/Foo.java", line=2,
           file_evidence=[_ev("sources/com/facebook/Foo.java", 2)])
    normal = es.select(f, _ctx(), bug_bounty=False)["primary"]["file_score"]
    bounty = es.select(f, _ctx(), bug_bounty=True)["primary"]["file_score"]
    _check(bounty < normal, "bug-bounty mode must amplify non-application penalties")


def test_bug_bounty_mode_rewards_reachable_app_code():
    appfile = f"sources/{APP.replace('.', '/')}/Pay.java"
    f = _f(reachability="YES", file_path=appfile, file_evidence=[_ev(appfile, 12, "y")])
    normal = es.select(f, _ctx(), bug_bounty=False)["primary"]["score"]
    bounty = es.select(f, _ctx(), bug_bounty=True)["primary"]["score"]
    _check(bounty > normal, "bug-bounty mode must reward reachable application proof")


def test_bug_bounty_enabled_detection():
    _check(es.bug_bounty_enabled({"bug_bounty_mode": True}), "results flag not honored")
    _check(es.bug_bounty_enabled({"options": {"bug_bounty_mode": True}}), "options flag not honored")
    _check(not es.bug_bounty_enabled({}), "should default off")


# ── Extensibility ─────────────────────────────────────────────────────────────
def test_register_contributor_influences_score():
    appfile = f"sources/{APP.replace('.', '/')}/Pay.java"
    f = _f(file_path=appfile, file_evidence=[_ev(appfile, 12, "y")])
    before = es.select(f, _ctx())["primary"]["score"]
    marker = "future AI reviewer vote"

    def _ai(cand, ctx):
        return [(50, marker)]
    scoring.register_contributor(_ai, scope=scoring.FILE_SCOPE)
    try:
        after_sel = es.select(f, _ctx())["primary"]
        _check(after_sel["score"] == before + 50, "registered contributor must add its delta")
        _check(marker in after_sel["selected_because"], "contributor reason must appear")
    finally:
        scoring._CONTRIBUTORS[:] = [(fn, sc) for fn, sc in scoring._CONTRIBUTORS if fn is not _ai]


# ── Pipeline / regression ─────────────────────────────────────────────────────
def test_annotate_promotes_primary_and_preserves_detection_site():
    """Phase 1.97 keystone: annotate promotes the app primary into file_path (so all
    legacy consumers show the right file) while preserving the original detection
    site under detected_location. This supersedes the 1.96 'never mutate' contract."""
    appfile = f"sources/{APP.replace('.', '/')}/Pay.java"
    f = _f(file_path="sources/androidx/x/A.java", line=1,
           file_evidence=[_ev("sources/androidx/x/A.java", 1), _ev(appfile, 12, "y")])
    res = _results(f)
    es.annotate(res, platform="android")
    _check(f["file_path"] == appfile, "annotate must promote the app primary into file_path")
    _check(f["detected_location"]["file_path"] == "sources/androidx/x/A.java",
           "the original detection site must be preserved under detected_location")
    _check(f["legacy_file_path"] == "sources/androidx/x/A.java", "legacy_file_path must be preserved")
    for k in ("evidence_selection", "primary_evidence", "evidence_view"):
        _check(k in f, f"annotate must add {k}")


def test_library_only_finding_not_falsely_promoted():
    """A finding whose only proof is a library file must NOT have its file_path
    replaced by a fabricated app file — promotion only ever improves."""
    libfile = "sources/androidx/x/A.java"
    f = _f(file_path=libfile, line=1, file_evidence=[_ev(libfile, 1)])
    res = _results(f)
    es.annotate(res, platform="android")
    _check(f["file_path"] == libfile, "library-only finding must keep its location")
    _check("detected_location" not in f, "no correction → no detected_location stamped")


def test_empty_and_malformed_safe():
    res = {"platform": "android", "findings": [None, {"title": "x"}]}
    es.annotate(res, platform="android")  # must not raise
    _check(res["findings"][1]["evidence_selection"]["candidate_count"] == 0,
           "a finding with no location yields zero candidates safely")


def test_summary_emitted():
    res = _results(_f(file_evidence=[_ev(f"sources/{APP.replace('.', '/')}/Pay.java", 12, "y")]))
    es.annotate(res, platform="android")
    s = res["evidence_selection_summary"]
    _check(s["findings_annotated"] == 1 and "bug_bounty_mode" in s, "summary malformed")


# ── Snippet quality & code relevance (Phase 1.96) ─────────────────────────────
def test_import_only_snippet_loses_to_real_code():
    """Between two application candidates, the one whose snippet is only imports must
    lose to the one showing the actual triggering code."""
    base = f"sources/{APP.replace('.', '/')}"
    f = _f(file_path=f"{base}/Imports.java", line=2,
           snippet="import javax.crypto.Cipher;\nimport java.util.*;",
           file_evidence=[
               _ev(f"{base}/Imports.java", 2, "import javax.crypto.Cipher;\nimport java.util.*;"),
               _ev(f"{base}/CryptoManager.java", 40, 'Cipher.getInstance("AES/ECB");'),
           ])
    sel = es.select(f, _ctx())
    _check("CryptoManager" in sel["primary"]["file_path"],
           "import-only snippet must lose to the real usage site")
    # The import-only candidate (now demoted) records an import-only penalty wherever
    # it landed (supporting or rejected — it is still app code, so not auto-rejected).
    others = (sel["supporting"] or []) + (sel["rejected"] or [])
    imp = next((c for c in others if "Imports.java" in c["file_path"]), None)
    _check(imp is not None and any("import" in r.lower() for r in imp["rejected_because"]),
           "the import-only candidate must record an import-only penalty reason")


def test_primary_snippet_refined_from_code_context():
    """A noisy captured snippet (an import line) is refined to the most relevant line
    using the finding's richer code_context."""
    base = f"sources/{APP.replace('.', '/')}"
    f = _f(title="Weak Hash MessageDigest", file_path=f"{base}/Hash.java", line=10,
           cwe="CWE-327", confidence=92,
           snippet="import java.security.MessageDigest;",
           code_context=("import java.security.MessageDigest;\n"
                         "public String hash(String in){\n"
                         '  MessageDigest md = MessageDigest.getInstance("MD5");\n'
                         "  return md.digest();\n}"))
    sel = es.select(f, _ctx())
    snip_text = sel["primary"]["snippet"]
    _check("getInstance" in snip_text and "import" not in snip_text.lower(),
           f"primary snippet should be refined to the real line, got: {snip_text!r}")


def test_accurate_snippet_not_swapped_for_unrelated_neighbour():
    """Regression: when a finding already has an accurate single-line snippet and its
    code_context window contains several equally-plain neighbour lines (e.g. adjacent
    <string> resource entries), refinement must NOT swap the correct matched line for
    an earlier unrelated neighbour. This is the 'Firebase URL evidence points at an
    unrelated strings.xml entry' bug: the matched line ties with its neighbours at the
    same quality and the FIRST neighbour would otherwise win."""
    f = _f(title="Firebase Realtime Database — Unauthenticated Access Risk",
           category="Cloud Configuration",
           file_path="resources/res/values/strings.xml", line=71,
           snippet='<string name="firebase_database_url">https://x.firebaseio.com</string>',
           code_context=(
               '<string name="fingerprint_error_user_canceled">Canceled by user.</string>\n'
               '<string name="fingerprint_not_recognized">Not recognized</string>\n'
               '<string name="firebase_database_url">https://x.firebaseio.com</string>\n'
               '<string name="gcm_defaultSenderId">1234567890</string>'))
    sel = es.select(f, _ctx())
    snip_text = sel["primary"]["snippet"]
    _check("firebase" in snip_text.lower() and "fingerprint" not in snip_text.lower(),
           f"primary snippet must stay on the matched firebase line, got: {snip_text!r}")


def test_relevant_token_bonus_picks_usage_site():
    """The candidate whose snippet contains the flagged value/API outscores a same-
    file candidate that does not."""
    base = f"sources/{APP.replace('.', '/')}"
    f = _f(title="Insecure Cipher Cipher.getInstance", value="AES/ECB",
           file_path=f"{base}/A.java", line=5, snippet="int x = 1;",
           file_evidence=[
               _ev(f"{base}/A.java", 5, "int x = 1;"),
               _ev(f"{base}/A.java", 9, 'Cipher.getInstance("AES/ECB");'),
           ])
    sel = es.select(f, _ctx())
    _check(sel["primary"]["line"] == 9,
           "the line showing the flagged API/value must be the primary")
    _check(any("flagged value" in r for r in sel["primary"]["selected_because"]),
           "relevance reason must be recorded")


def test_rule_specificity_raises_score_not_selection():
    """Rule specificity is finding-wide: it raises the score but does not change which
    file wins (every candidate gets the same finding_score)."""
    base = f"sources/{APP.replace('.', '/')}"
    hi = es.select(_f(file_path=f"{base}/P.java", line=5, confidence=95, cwe="CWE-327",
                      snippet='Cipher.getInstance("AES")'), _ctx())
    lo = es.select(_f(file_path=f"{base}/P.java", line=5, confidence=50, cwe="CWE-200",
                      snippet='Cipher.getInstance("AES")'), _ctx())
    _check(hi["primary"]["finding_score"] > lo["primary"]["finding_score"],
           "a precise, high-confidence rule must raise the finding score")
    _check(hi["primary"]["file_path"] == lo["primary"]["file_path"],
           "rule specificity must not change which file is selected")


def test_snippet_quality_never_rejects_app_code():
    """A weak snippet on application code must not push its file-intrinsic score below
    rejection — 'reject weak relevance UNLESS no better alternative'."""
    base = f"sources/{APP.replace('.', '/')}"
    f = _f(file_path=f"{base}/Only.java", line=1, snippet="import a.b.C;",
           file_evidence=[_ev(f"{base}/Only.java", 1, "import a.b.C;")])
    sel = es.select(f, _ctx())
    _check(sel["primary"]["file_score"] >= 0,
           "an application file must stay selectable even with a weak snippet")
    _check("Only.java" in sel["primary"]["file_path"], "the only app proof must remain primary")


# ── Standalone runner ─────────────────────────────────────────────────────────
def _run_all() -> int:
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"FAIL  {t.__name__}: {e}")
    total = len(tests)
    print(f"\n{total - failures}/{total} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())

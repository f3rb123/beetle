"""
Secret Detection v2 (Beetle 2.0, Phase 1.91) — regression + measurement.

This phase refines the EXISTING secret architecture (it does not rebuild it):

  * Context validation — the Secret Intelligence Engine now reads the captured
    variable name + nearby usage (Authorization/Retrofit/OkHttp/Cipher/KeyStore/
    SharedPreferences/Firebase/cloud-SDK) so a GENERIC value is kept when credential
    context corroborates it and rejected when it is just a long random string.
  * Verdict wiring — secret_intel's visibility gate now consumes the engine's
    verdict (secret_status / secret_overall_confidence), so values the engine judged
    a non-secret (UUID / hash / crypto constant / library constant / unreferenced
    generic) are SUPPRESSED from the analyst's default view — kept + counted.
  * Vendor coverage — the cited Artifactory gap is closed in the APKLeaks catalog.

The file both ASSERTS the new behavior and MEASURES it: ``measure()`` runs a mixed
corpus through the real pipeline with the intelligence gate OFF (old behavior) and
ON (new behavior) and reports false-positive reduction + genuine-secret retention +
vendor coverage. Run ``python -m tests.test_secret_detection_v2`` for the report.
"""
from __future__ import annotations

import copy

from analyzers import secret_catalog, secret_intel
from analyzers.secret_intelligence import assess, annotate
from analyzers.secret_intelligence.config import Status
from analyzers.secret_intelligence.patterns import make_github_token


APP_PKG = "com.acme.bank"


# ── corpus ────────────────────────────────────────────────────────────────────
# Each entry is a detector-shaped secret dict plus a private ``_expected`` tag:
# "genuine" (must stay visible) or "fp" (must be suppressed after Phase 1.91).
def _s(name, value, path, snippet, *, line=10, severity="high",
       confidence=75, expected="genuine"):
    return {
        "name": name, "value": value, "file_path": path, "line": line,
        "snippet": snippet, "code_context": snippet, "severity": severity,
        "confidence": confidence, "_expected": expected,
    }


def _corpus() -> list[dict]:
    app = f"sources/{APP_PKG.replace('.', '/')}"
    # Provider literals are built to avoid the engine's placeholder vocabulary
    # (sequential digits / classic hex runs) so the format — not test noise —
    # drives the verdict.
    google = "AIza" + "SyBkMxQvRtWnZpLcHdGfJsAuYbXeWvQrTaP"   # 4 + 35
    stripe = "sk_live_" + "MxQvRtWnZpLcHdGfKbVnTyUq"
    app_hex = "a3f8d9c2b1e04f7a8c6d5e4b3a2f1c0d9e8b7a6c"
    return [
        # ── genuine: provider-format secrets (context-independent) ────────────
        _s("AWS Access Key ID", "AKIA" + "QWERTYUIOPLKJHGF",
           f"{app}/Cfg.java", 'String k = "AKIAQWERTYUIOPLKJHGF";', confidence=95),
        _s("Google API Key", google,
           f"{app}/Net.java", f'String g = "{google}";', confidence=90),
        _s("GitHub Token", make_github_token(),
           f"{app}/Gh.java", 'String t = token;', confidence=90),
        _s("Stripe Secret Key", stripe,
           f"{app}/Pay.java", f'String s = "{stripe}";', confidence=95),
        # ── genuine: app-specific generic secret WITH credential context ──────
        # Detected only by a generic ("weak") detector, yet a real secret: a
        # credential variable name + Authorization/Retrofit usage corroborate it.
        # Phase 1.91 must RESCUE it from legacy low-confidence suppression.
        _s("Generic API Key", app_hex, f"{app}/Api.java",
           f'String clientSecret = "{app_hex}"; '
           'retrofit.addHeader("Authorization", "Bearer " + clientSecret);'),
        # ── genuine: the cited VENDOR gap (Artifactory) ───────────────────────
        _s("Artifactory API Token", ' AKCabcdefghijklmnopqrstuv',
           f"{app}/Build.java", 'def repo = " AKCabcdefghijklmnopqrstuv"', confidence=80),

        # ── FALSE POSITIVES the phase targets ────────────────────────────────
        # Non-weak detector names + confidence 85 → the LEGACY gate keeps them
        # VISIBLE; only the Phase 1.91 intelligence verdict suppresses them. This
        # is what makes the before/after measurement attributable to this phase.
        # FIPS-197 AES test vector — a crypto constant, not a secret.
        _s("Encryption Constant", "2b7e151628aed2a6abf7158809cf4f3c",
           f"{app}/Crypto.java",
           'static final byte[] KEY = hex("2b7e151628aed2a6abf7158809cf4f3c");',
           confidence=85, expected="fp"),
        # MD5-style hash assigned to an inert constant — no credential context.
        _s("Build Checksum", "5d41402abc4b2a76b9719d911017c592",
           f"{app}/Hashes.java",
           'private static final String CHECKSUM = "5d41402abc4b2a76b9719d911017c592";',
           confidence=85, expected="fp"),
        # Request-correlation UUID (matches the bare-UUID "Heroku API key" shape).
        _s("Request Identifier", "7e9426f7-42af-4717-8689-00a9a4b65c1c",
           f"{app}/Net.java",
           'String requestId = "7e9426f7-42af-4717-8689-00a9a4b65c1c";',
           confidence=85, expected="fp"),
        # Long random base64 declared as a constant, no credential name/usage.
        _s("Data Blob", "ZxKpQmWdErTyUiOpAsDfGhJkLnMbVcXzQwErTyLkJh",
           f"{app}/Const.java",
           'public static final String DATA = "ZxKpQmWdErTyUiOpAsDfGhJkLnMbVcXzQwErTyLkJh";',
           confidence=85, expected="fp"),
    ]


# ── pipeline harness ──────────────────────────────────────────────────────────
def _run(secrets: list[dict], *, gate: bool) -> dict:
    """Run annotate + process_secrets over a fresh copy. ``gate`` toggles the
    Phase 1.91 intelligence suppression to isolate its effect (old vs new)."""
    results = {"platform": "android", "secrets": copy.deepcopy(secrets)}
    annotate(results)
    if gate:
        return _process(results)
    # "before" = pristine pre-Phase-1.91 behavior: neither the intelligence
    # suppression (FP reduction) nor the rescue (coverage) is in effect.
    rej, sup = secret_intel._intelligence_rejected, secret_intel._intelligence_supports
    secret_intel._intelligence_rejected = lambda _s: False
    secret_intel._intelligence_supports = lambda _s: False
    try:
        return _process(results)
    finally:
        secret_intel._intelligence_rejected = rej
        secret_intel._intelligence_supports = sup


def _process(results: dict) -> dict:
    secret_intel.process_secrets(results, APP_PKG)
    return results


def _classify(results: dict, corpus: list[dict]) -> dict:
    """Map each corpus value to whether it ended up visible, with its _expected tag."""
    visible_vals = {s.get("value_sha256") or "": s for s in results.get("secrets", [])}
    # process_secrets overwrites value with the mask, so match on sha256 it computes.
    import hashlib
    out = {"genuine_visible": 0, "genuine_total": 0, "fp_visible": 0, "fp_total": 0}
    visible_sha = {s.get("value_sha256") for s in results.get("secrets", [])}
    for c in corpus:
        sha = hashlib.sha256(str(c["value"]).encode("utf-8", "replace")).hexdigest()
        vis = sha in visible_sha
        if c["_expected"] == "genuine":
            out["genuine_total"] += 1
            out["genuine_visible"] += int(vis)
        else:
            out["fp_total"] += 1
            out["fp_visible"] += int(vis)
    return out


def measure() -> dict:
    corpus = _corpus()
    before = _classify(_run(corpus, gate=False), corpus)
    after = _classify(_run(corpus, gate=True), corpus)
    return {"before": before, "after": after}


# ════════════════════════════════════════════════════════════════════════════
# ASSERTIONS
# ════════════════════════════════════════════════════════════════════════════
def test_context_keeps_app_specific_generic_secret():
    """A generic value with a credential variable name + Authorization usage is a
    real secret and must NOT be rejected."""
    a = assess("a3f8d9c2b1e04f7a8c6d5e4b3a2f1c0d9e8b7a6c", {
        "name": "clientSecret", "file_path": "sources/com/acme/Api.java", "line": 3,
        "snippet": 'String clientSecret = "..."; retrofit.addHeader("Authorization", clientSecret);',
    }).to_dict()
    assert a["status"] not in (Status.FALSE_POSITIVE, Status.GENERATED_CONSTANT)
    assert a["context_score"] >= 75
    assert a["usage_referenced"] is True


def test_context_rejects_bare_random_constant():
    """The same shape with no credential name and no usage is the 'long random
    string' false positive — rejected as unreferenced."""
    a = assess("a3f8d9c2b1e04f7a8c6d5e4b3a2f1c0d9e8b7a6c", {
        "name": "DATA", "file_path": "sources/com/acme/Const.java", "line": 3,
        "snippet": 'private static final String DATA = "a3f8d9c2b1e04f7a8c6d5e4b3a2f1c0d9e8b7a6c";',
    }).to_dict()
    assert a["status"] == Status.FALSE_POSITIVE
    assert a["context_score"] <= 35
    assert a["usage_referenced"] is False


def test_uuid_without_context_rejected():
    a = assess("7e9426f7-42af-4717-8689-00a9a4b65c1c", {
        "name": "requestId", "file_path": "sources/com/acme/Net.java", "line": 3,
        "snippet": 'String requestId = "7e9426f7-42af-4717-8689-00a9a4b65c1c";',
    }).to_dict()
    assert a["status"] == Status.FALSE_POSITIVE


def test_crypto_constant_rejected():
    a = assess("2b7e151628aed2a6abf7158809cf4f3c", {
        "name": "KEY", "file_path": "sources/com/acme/Crypto.java", "line": 3,
        "snippet": 'static final byte[] KEY = hex("2b7e151628aed2a6abf7158809cf4f3c");',
    }).to_dict()
    assert a["status"] in (Status.GENERATED_CONSTANT, Status.FALSE_POSITIVE)


def test_provider_format_unaffected_by_context():
    """A recognized provider format is a secret on its own — never rejected for
    lack of surrounding context."""
    a = assess("AKIA" + "QWERTYUIOP123456", {
        "name": "", "file_path": "sources/com/acme/Cfg.java", "line": 3,
        "snippet": 'String k = "...";',
    }).to_dict()
    assert a["status"] in (Status.PROBABLE, Status.POSSIBLE, Status.VALIDATED)


def test_artifactory_in_catalog_and_matches():
    """The cited Artifactory vendor gap is closed in the unified catalog."""
    names = {p["name"] for p in secret_catalog.combined()}
    assert "Artifactory API Token" in names
    assert "Artifactory Password" in names
    rule = next(p for p in secret_catalog.combined() if p["name"] == "Artifactory API Token")
    import re
    assert re.search(rule["pattern"], 'token = " AKCabc123def456ghijك".replace')


def test_recognized_format_never_hidden_by_heuristic_fp():
    """Item 13: a value carrying a recognized provider/structured format is never
    suppressed by a HEURISTIC false-positive signal — even if it unluckily trips
    the placeholder vocabulary. Only definitive classes (public cert / known doc
    example) may suppress a recognized format."""
    # A real-shaped Google API key that happens to contain "deadbeef".
    val = "AIza" + "SyDdeadbeefMxQvRtWnZpLcHdGfJsAuYbXe"
    a = assess(val, {"name": "GOOGLE_MAPS_KEY",
                     "file_path": "sources/com/acme/Net.java", "line": 3,
                     "snippet": f'String GOOGLE_MAPS_KEY = "{val}";'}).to_dict()
    assert a["format_valid"] is True
    sec = {"secret_status": a["status"], "secret_overall_confidence": a["overall_confidence"],
           "secret_intelligence": a}
    assert secret_intel._intelligence_rejected(sec) is False, \
        "recognized provider format must not be hidden by a heuristic FP"


def test_definitive_classes_suppress_non_secrets():
    """Public certificates and known documentation examples ARE suppressed (they are
    not secrets) — the definitive half of the gate."""
    cert = "-----BEGIN CERTIFICATE-----\nMIIBfoo\n-----END CERTIFICATE-----"
    a = assess(cert, {"name": "cert", "file_path": "sources/com/acme/Tls.java",
                      "line": 1, "snippet": "cert"}).to_dict()
    sec = {"secret_status": a["status"], "secret_intelligence": a}
    assert a["status"] == Status.PUBLIC_VALUE
    assert secret_intel._intelligence_rejected(sec) is True


def test_gate_suppresses_fp_keeps_genuine():
    """The visibility gate consumes the engine verdict: every FP is suppressed,
    every genuine secret stays visible."""
    after = _classify(_run(_corpus(), gate=True), _corpus())
    assert after["fp_visible"] == 0, f"FPs still visible: {after}"
    assert after["genuine_visible"] == after["genuine_total"], f"genuine lost: {after}"


def test_measured_improvement():
    """Before/after: the gate removes FPs that the old behavior surfaced while
    retaining 100% of genuine secrets."""
    m = measure()
    # FP reduction: the gate removes every FP the legacy behavior surfaced.
    assert m["before"]["fp_visible"] > m["after"]["fp_visible"], m
    assert m["after"]["fp_visible"] == 0, m
    # Coverage: every genuine secret is visible after, including the app-specific
    # one the legacy behavior hid (so after >= before, and after == total).
    assert m["after"]["genuine_visible"] == m["after"]["genuine_total"], m
    assert m["after"]["genuine_visible"] >= m["before"]["genuine_visible"], m


def _report() -> str:
    m = measure()
    b, a = m["before"], m["after"]

    def prec(d):
        vis = d["genuine_visible"] + d["fp_visible"]
        return (d["genuine_visible"] / vis * 100) if vis else 0.0
    lines = [
        "Secret Detection v2 - measured improvement",
        "=" * 52,
        f"  genuine secrets:        {a['genuine_total']}",
        f"  false-positive seeds:   {a['fp_total']}",
        "-" * 52,
        f"  FP visible  BEFORE gate: {b['fp_visible']}",
        f"  FP visible  AFTER  gate: {a['fp_visible']}",
        f"  genuine kept BEFORE/AFTER: {b['genuine_visible']}/{a['genuine_visible']} of {a['genuine_total']}",
        f"  generic precision BEFORE: {prec(b):5.1f}%   AFTER: {prec(a):5.1f}%",
        "=" * 52,
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    print(_report())

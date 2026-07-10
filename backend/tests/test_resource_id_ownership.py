"""
Ownership / evidence guards for two false-positive sources.

A. The Chromium WebView support library (org.chromium.support_lib_boundary.*,
   androidx.webkit.*) had no ownership fingerprint, so it classified as APP code and
   could anchor an attack chain as its entry (a "Dynamic Code Loading / Reflection
   RCE" chain was anchored on WebViewBuilderBoundaryInterface.java). It must now
   classify as a non-application (library) owner, which the chain engine rejects.

B. Decompiled resource-ID constant classes (R.java, incl. obfuscated N0/a.java) are
   nothing but `public static final int NAME = 0x7f######;` — Android resource IDs.
   Those integers are never secrets and the class is never app logic, yet a value
   like 2130837504 looked like a secret candidate and the class was picked as
   secret/chain evidence. is_resource_id_class() now detects them; they are excluded
   from secret candidacy and from evidence selection (which chains consume).

Runnable standalone or under pytest:
    python -m tests.test_resource_id_ownership      # from backend/
"""
from __future__ import annotations

import os
import sys
import tempfile

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers.ownership import get_engine, context_from_results, OwnerType  # noqa: E402
from analyzers.attack_chains.engine import _NON_APP_OWNERS  # noqa: E402
from analyzers.code_analyzer import is_resource_id_class  # noqa: E402
from analyzers.evidence_scanner import scan_directory_for_secrets  # noqa: E402
from analyzers.evidence_selection import engine as ES  # noqa: E402


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


# ════════════════════════════════════════════════════════════════════════════
# A — Chromium / AndroidX WebKit classify as a non-application owner.
# ════════════════════════════════════════════════════════════════════════════
def _classify(pkg):
    ctx = context_from_results({"platform": "android", "app_info": {"package": "com.myapp"}})
    return get_engine().classify_package(pkg, platform="android", ctx=ctx).owner_type


def test_chromium_support_lib_is_not_application():
    owner = _classify("org.chromium.support_lib_boundary.WebViewBuilderBoundaryInterface")
    _check(owner != OwnerType.APPLICATION,
           f"Chromium support lib must not be app code, got {owner!r}")
    _check(owner in _NON_APP_OWNERS,
           f"owner {owner!r} must be in the chain engine's rejected set (never an entry)")


def test_chromium_base_and_androidx_webkit_are_non_application():
    for pkg in ("org.chromium.base.ThreadUtils", "androidx.webkit.WebViewCompat"):
        owner = _classify(pkg)
        _check(owner != OwnerType.APPLICATION, f"{pkg} must not be app code, got {owner!r}")
        _check(owner in _NON_APP_OWNERS, f"{pkg} ({owner!r}) must be rejected as a chain entry")


def test_app_code_still_classifies_as_application():
    _check(_classify("com.myapp.ui.MainActivity") == OwnerType.APPLICATION,
           "real app code must remain APPLICATION (guard against over-broad prefixes)")


# ════════════════════════════════════════════════════════════════════════════
# B — resource-ID constant class detection.
# ════════════════════════════════════════════════════════════════════════════
R_CLASS = """package com.app.N0;
public final class a {
    public static final int f = 2130837504;
    public static final int g = 2130837505;
    public static final int h = 0x7f020002;
    public static final int action_bar = 0x7f0a0001;
    public static final int[] View = { 0x7f010000, 0x7f010001 };
}"""

R_OBFUSCATED = """public final class a {
  public static int f = 2130837504;
  public static int g = 2130837505;
  public static int h = 2130837506;
  private a() {}
}"""

REAL_CLASS = """public class ApiClient {
  private static final int TIMEOUT = 30;
  public String fetch(String path) {
    if (path == null) return null;
    return new Http().get(BASE + path + "?token=" + TOKEN);
  }
  static final String TOKEN = "sk_live_deadbeefcafebabe0123";
}"""

SECRET_HOLDER = """public class Keys {
  public static final String AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
  public static final int VERSION = 3;
}"""


def test_resource_id_class_detected():
    _check(is_resource_id_class(R_CLASS), "a class of 0x7f int constants must be detected")
    _check(is_resource_id_class(R_OBFUSCATED), "an obfuscated R class (no 'final') must be detected")


def test_real_classes_not_detected_as_resource_id():
    _check(not is_resource_id_class(REAL_CLASS), "a class with logic must not be a resource-ID class")
    _check(not is_resource_id_class(SECRET_HOLDER),
           "a class holding a secret string must never be treated as a resource-ID class")
    _check(not is_resource_id_class(""), "empty text is not a resource-ID class")


def test_non_resource_int_constants_not_detected():
    ports = """public class Ports {
        static final int HTTP = 80;
        static final int HTTPS = 443;
        static final int CUSTOM = 8443;
    }"""
    _check(not is_resource_id_class(ports),
           "ordinary int constants (ports) are not resource IDs")


# ════════════════════════════════════════════════════════════════════════════
# B(1) — a resource-ID class cannot be a secret.
# ════════════════════════════════════════════════════════════════════════════
def test_resource_id_class_is_not_a_secret_candidate():
    with tempfile.TemporaryDirectory() as d:
        # An R-constant class whose big integers could look secret-ish …
        with open(os.path.join(d, "a.java"), "w", encoding="utf-8") as fh:
            fh.write(R_CLASS)
        # … next to a genuine secret in real code.
        with open(os.path.join(d, "ApiClient.java"), "w", encoding="utf-8") as fh:
            fh.write('class ApiClient { String k = "AKIAIOSFODNN7EXAMPLE"; }')

        sink: set = set()
        hits = scan_directory_for_secrets(d, resource_id_sink=sink)

        files = {h.get("file_path", "").replace("\\", "/").rsplit("/", 1)[-1] for h in hits}
        _check("a.java" not in files, f"no secret may be reported from the R-constant class: {files}")
        _check(any("a.java" in p for p in sink), "the skipped R class must be recorded in the sink")
        _check(any(h.get("file_path", "").endswith("ApiClient.java") for h in hits),
               "the genuine secret in real code must still be found")


# ════════════════════════════════════════════════════════════════════════════
# B(2) — a resource-ID class cannot be chain / evidence.
# ════════════════════════════════════════════════════════════════════════════
def _secret_finding(cands):
    return {
        "title": "Hardcoded Secret", "severity": "high", "category": "Secrets",
        "file_path": cands[0]["path"], "line": (cands[0]["lines"] or [0])[0],
        "snippet": cands[0]["snippet"],
        "file_evidence": cands,
    }


def test_resource_id_class_is_excluded_from_evidence_selection():
    r_path = "sources/com/app/N0/a.java"
    real_path = "sources/com/app/net/ApiClient.java"
    f = _secret_finding([
        {"path": r_path, "lines": [12], "snippet": "public static final int f = 2130837504;"},
        {"path": real_path, "lines": [40], "snippet": 'String KEY = "AKIA...";'},
    ])
    results = {"platform": "android", "app_info": {"package": "com.app"},
               "resource_id_classes": [r_path], "findings": [f]}
    ES.annotate(results, platform="android")

    prim = f["evidence_selection"]["primary"]
    prim_path = (prim.get("file_path") or prim.get("relative_path") or "")
    _check("a.java" not in prim_path, f"the R-constant class must not be the primary proof: {prim_path!r}")
    _check(prim_path.endswith("ApiClient.java"), f"the real code must be chosen instead: {prim_path!r}")


def test_finding_with_only_resource_id_evidence_has_no_proof_location():
    r_path = "sources/com/app/N0/a.java"
    f = _secret_finding([{"path": r_path, "lines": [12], "snippet": "int f = 2130837504;"}])
    results = {"platform": "android", "resource_id_classes": [r_path], "findings": [f]}
    ES.annotate(results, platform="android")
    _check(f["evidence_selection"]["candidate_count"] == 0,
           "a finding whose only evidence is an R-constant class has no valid proof location")
    _check(not f["evidence_selection"]["primary"],
           "so no primary evidence points at the R-constant class")


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    print(f"\n{failures} failure(s)")
    sys.exit(1 if failures else 0)

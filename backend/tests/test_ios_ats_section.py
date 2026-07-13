"""App Transport Security section (RUN 10).

THE THING THIS MUST GET RIGHT: iOS enforces ATS BY DEFAULT. An app that never declares
NSAppTransportSecurity is in the SECURE state — not an unconfigured or unknown one. MobSF shows
an empty table here, which reads like a gap when it is the opposite. An absent key is not the
same as a key set to false, and the report must never imply the app configured something it
never configured.
"""
import plistlib

from analyzers.ios_analyzer import _analyze_info_plist


def _ats(tmp_path, ats=None):
    plist = {"CFBundleIdentifier": "com.example.app"}
    if ats is not None:
        plist["NSAppTransportSecurity"] = ats
    p = tmp_path / "Info.plist"
    with open(p, "wb") as f:
        plistlib.dump(plist, f)
    results = {"app_info": {}, "findings": [], "permissions": {"all": [], "dangerous": []},
               "attack_surface": {"url_schemes": [], "universal_links": [], "exported_handlers": []}}
    _analyze_info_plist(str(p), results)
    return results["app_info"]["ats_state"]


def test_no_ats_key_is_the_secure_default_not_a_gap(tmp_path):
    st = _ats(tmp_path, None)
    assert st["declared"] is False
    assert st["state"] == "default"
    assert st["enforced"] is True
    assert st["posture"] == "ATS enforced"
    assert "enforced by default" in st["summary"]


def test_arbitrary_loads_disables_ats(tmp_path):
    st = _ats(tmp_path, {"NSAllowsArbitraryLoads": True})
    assert st["enforced"] is False
    assert st["posture"] == "ATS disabled"
    flag = next(f for f in st["global_flags"] if f["key"] == "NSAllowsArbitraryLoads")
    assert flag["value"] is True and flag["severity"] == "high"


def test_webcontent_relaxation_is_named_not_collapsed_into_ats_disabled(tmp_path):
    # Narrower than the blanket switch: the app's own requests are still protected, so it is
    # MEDIUM and the report must say WHICH door is open rather than "ATS disabled".
    st = _ats(tmp_path, {"NSAllowsArbitraryLoadsInWebContent": True})
    assert st["posture"] == "ATS weakened"
    flag = next(f for f in st["global_flags"] if f["key"] == "NSAllowsArbitraryLoadsInWebContent")
    assert flag["value"] is True and flag["severity"] == "medium"
    assert not st["allows_arbitrary_loads"]


def test_exception_domain_allowing_cleartext_is_high(tmp_path):
    st = _ats(tmp_path, {"NSExceptionDomains": {
        "insecure.example.com": {"NSExceptionAllowsInsecureHTTPLoads": True,
                                 "NSIncludesSubdomains": True}}})
    d = st["domains"][0]
    assert d["domain"] == "insecure.example.com"
    assert d["allows_insecure_http"] is True
    assert d["includes_subdomains"] is True
    assert d["severity"] == "high"


def test_exception_domain_that_only_lowers_tls_is_medium(tmp_path):
    st = _ats(tmp_path, {"NSExceptionDomains": {
        "legacy.example.com": {"NSExceptionMinimumTLSVersion": "TLSv1.0"}}})
    d = st["domains"][0]
    assert d["severity"] == "medium"
    assert "TLSv1.0" in d["why"]
    assert d["allows_insecure_http"] is False


def test_exception_domain_with_no_relaxation_is_info(tmp_path):
    # Declaring an exception entry that relaxes nothing is not a weakness.
    st = _ats(tmp_path, {"NSExceptionDomains": {"api.example.com": {"NSIncludesSubdomains": True}}})
    assert st["domains"][0]["severity"] == "info"


def test_worst_domain_is_listed_first(tmp_path):
    st = _ats(tmp_path, {"NSExceptionDomains": {
        "ok.example.com": {"NSIncludesSubdomains": True},
        "bad.example.com": {"NSExceptionAllowsInsecureHTTPLoads": True},
    }})
    assert st["domains"][0]["domain"] == "bad.example.com"
    assert st["domains"][0]["severity"] == "high"

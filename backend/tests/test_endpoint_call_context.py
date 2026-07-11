"""
Regression: two noise sources in URL/endpoint intelligence.

A — library/spec constants (dashif.org, aomedia.org, issuetracker.google.com, …)
    were reported as "Discovered Endpoints". Now each URL is tagged called /
    referenced / library-owned, and the default endpoints list is "called" only.
B — placeholder domains (default.url, example.com, your-api.com, *.invalid) were
    DNS-resolved. Now a placeholder/non-registrable host is never resolved.

These fail on the old behavior (spec constants surfaced, default.url resolved) and
pass on the new.
"""
from __future__ import annotations

import os
import sys
import tempfile

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import endpoint_intel as ei  # noqa: E402
from analyzers import network_intel as ni  # noqa: E402


def _write(root, rel, content):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)


# ── A: call-context classification ───────────────────────────────────────────

def test_retrofit_called_dashif_referenced():
    with tempfile.TemporaryDirectory() as root:
        _write(root, "sources/com/checkin/app/Api.java",
               'class Api {\n'
               '  static final String DASH = "https://dashif.org/identifiers/x";\n'      # spec constant
               '  static final String AOM = "https://aomedia.org/av1/spec";\n'            # spec constant
               '  Retrofit r = new Retrofit.Builder().baseUrl("https://api.checkin.io/v1/").build();\n'
               '}\n')
        results = {"platform": "android", "app_info": {"package": "com.checkin.app"}}
        eps = ei.extract_endpoints(root, results=results)

    # Default surfaces ONLY the URL the app actually calls.
    assert eps == ["https://api.checkin.io/v1/"], eps
    intel = {r["url"]: r["evidence"] for r in results["endpoints_intel"]}
    assert intel["https://api.checkin.io/v1/"] == "called"
    assert intel["https://dashif.org/identifiers/x"] == "referenced"
    assert intel["https://aomedia.org/av1/spec"] == "referenced"


def test_library_owned_url_hidden_from_default():
    with tempfile.TemporaryDirectory() as root:
        # A URL that appears ONLY in a framework/library-owned file (io.flutter.*).
        _write(root, "sources/io/flutter/plugin/X.java",
               'String u = "https://issuetracker.google.com/issues/1";')
        # A genuine app call so the default list is non-empty.
        _write(root, "sources/com/checkin/app/Net.java",
               'new java.net.URL("https://api.checkin.io/e").openConnection();')
        results = {"platform": "android", "app_info": {"package": "com.checkin.app"}}
        eps = ei.extract_endpoints(root, results=results)

    assert "https://issuetracker.google.com/issues/1" not in eps
    assert "https://api.checkin.io/e" in eps
    intel = {r["url"]: r["evidence"] for r in results["endpoints_intel"]}
    assert intel["https://issuetracker.google.com/issues/1"] == "library-owned"


def test_verbose_returns_referenced_and_library():
    with tempfile.TemporaryDirectory() as root:
        _write(root, "sources/com/checkin/app/Api.java",
               'String DASH = "https://dashif.org/x";')
        results = {"platform": "android", "app_info": {"package": "com.checkin.app"}}
        default = ei.extract_endpoints(root, results=results)
        verbose = ei.extract_endpoints(root, results=results, verbose=True)
    assert default == []                                  # referenced constant hidden
    assert "https://dashif.org/x" in verbose              # available behind verbose


def test_okhttp_and_volley_and_baseurl_are_called():
    with tempfile.TemporaryDirectory() as root:
        _write(root, "sources/com/checkin/app/C.java",
               'client.newCall(new Request.Builder().url("https://ok.checkin.io/a").build());\n'
               'queue.add(new StringRequest("https://volley.checkin.io/b", listener));\n'
               'public static final String BASE_URL = "gw.checkin.io";\n')
        results = {"platform": "android", "app_info": {"package": "com.checkin.app"}}
        eps = ei.extract_endpoints(root, results=results)
    assert "https://ok.checkin.io/a" in eps
    assert "https://volley.checkin.io/b" in eps
    assert "https://gw.checkin.io" in eps  # base-url config counts as called


# ── B: placeholder domains never resolved ────────────────────────────────────

def test_placeholder_domains_flagged():
    for host in ("default.url", "example.com", "example.org", "your-api.com",
                 "test.com", "localhost", "foo.invalid", "api.example.com"):
        assert ni.is_placeholder_domain(host), host
        assert not ni.looks_like_registrable_domain(host), host


def test_real_domains_registrable():
    for host in ("api.checkin.io", "dashif.org", "gateway.bank-corp.net"):
        assert not ni.is_placeholder_domain(host), host
        assert ni.looks_like_registrable_domain(host), host


def test_non_registrable_tokens_rejected():
    for bad in ("1.2.3.4", "notadomain", "", "http://x", "a.b"):
        assert not ni.looks_like_registrable_domain(bad), bad


def test_check_domains_never_resolves_placeholder(monkeypatch):
    from analyzers import domain_analyzer as da
    resolved = []
    monkeypatch.setattr(da.socket, "gethostbyname",
                        lambda h: (resolved.append(h), "1.1.1.1")[1])
    results = {"findings": []}
    da.check_domains(["https://default.url/x", "https://example.com/y"], results)
    assert resolved == [], f"placeholder domains must never be resolved: {resolved}"
    assert results.get("domain_intel") == []


def test_check_domains_resolves_real_domain(monkeypatch):
    from analyzers import domain_analyzer as da
    resolved = []

    def _fake(h):
        resolved.append(h)
        raise da.socket.gaierror()  # avoid the network geo call; just prove it tried

    monkeypatch.setattr(da.socket, "gethostbyname", _fake)
    results = {"findings": []}
    da.check_domains(["https://api.checkin.io/login"], results)
    assert "api.checkin.io" in resolved


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))

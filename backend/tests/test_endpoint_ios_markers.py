"""
Regression: _HTTP_CALL_MARKERS had no iOS client markers, so every iOS URL was
classified "referenced" and filtered out of results["endpoints"]. Add Swift/ObjC
HTTP-client markers (URLSession / Alamofire / NSURLConnection).

ADDITIVE: the new markers are iOS/Swift/ObjC text absent from Android source, so no
Android URL's classification can change (byte-identical Android endpoint list).
"""
from __future__ import annotations

import os
import re
import sys
import tempfile

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import endpoint_intel as ei  # noqa: E402

_URL = re.compile(r'https?://[^\s"\')]+')

# The markers added by this change (iOS/Swift/ObjC clients).
_IOS_MARKERS = {
    "urlsession", "datatask(", "urlrequest(", ".request(", "af.request", "alamofire",
    "session.data", "nsurlconnection", "nsurlsession", "downloadtask(", "uploadtask(",
}


def _classify(content, markers=None):
    """Reproduce _url_is_called for the first URL, optionally with a restricted marker set."""
    m = _URL.search(content)
    window = content.lower()[max(0, m.start() - ei._CALL_WINDOW):m.start()]
    mk = markers if markers is not None else ei._HTTP_CALL_MARKERS
    return "called" if any(x in window for x in mk) else "referenced"


# ── iOS call sites → "called" ────────────────────────────────────────────────

def test_ios_client_call_sites_are_called():
    sites = [
        'URLSession.shared.dataTask(with: URL(string: "https://api.checkin.io/v1/login")!) { d,r,e in }',
        'AF.request("https://api.checkin.io/users", method: .get)',
        'var req = URLRequest(url: URL(string: "https://api.checkin.io/x")!)',
        'let t = session.dataTask(with: URL(string: "https://telemetry.checkin.io/e")!)',
        '[NSURLConnection connectionWithRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:@"https://legacy.checkin.io/a"]]]',
        'Alamofire.request("https://api.checkin.io/z").responseJSON { r in }',
        'let dl = session.downloadTask(with: URL(string: "https://cdn.checkin.io/f")!)',
    ]
    for s in sites:
        assert _classify(s) == "called", f"iOS call site must be 'called': {s[:40]}"


def test_call_window_reaches_swift_marker():
    # The URLSession marker sits ~46 chars before the URL literal — well within 90.
    s = 'URLSession.shared.dataTask(with: URL(string: "https://api.checkin.io/v1/login")!)'
    m = _URL.search(s)
    assert m.start() < ei._CALL_WINDOW, "Swift call marker must be inside the call window"
    assert _classify(s) == "called"


# ── bare constants / comments stay "referenced" ──────────────────────────────

def test_bare_swift_constant_is_referenced():
    assert _classify('let docs = "https://dashif.org/identifiers/content_protection"') == "referenced"
    assert _classify('// see https://aomedia.org/av1/spec for details') == "referenced"
    assert _classify('static let help = "https://support.example.com/faq"') == "referenced"


# ── Android byte-identical: no Android classification depends on an iOS marker ─

_ANDROID_SNIPPETS = [
    'Retrofit r = new Retrofit.Builder().baseUrl("https://api.app.com/v1/").build();',
    'String DASH = "https://dashif.org/x";',
    'new java.net.URL("https://telemetry.app.com/e").openConnection();',
    'client.newCall(new Request.Builder().url("https://ok.app.com/a").build());',
    'val base = "https://cdn.app.com/assets"',
    'queue.add(new StringRequest("https://volley.app.com/b", listener));',
]


def test_android_classification_unchanged_by_ios_markers():
    android_only = tuple(m for m in ei._HTTP_CALL_MARKERS if m not in _IOS_MARKERS)
    for s in _ANDROID_SNIPPETS:
        with_ios = _classify(s)                       # full (new) tuple
        without_ios = _classify(s, markers=android_only)  # Android-only (old) tuple
        assert with_ios == without_ios, (
            f"iOS markers changed an Android URL's classification: {s[:50]} "
            f"({without_ios} -> {with_ios})")


def test_ios_markers_absent_from_android_source():
    joined = "\n".join(_ANDROID_SNIPPETS).lower()
    assert not any(m in joined for m in _IOS_MARKERS), "iOS markers must not appear in Android source"


# ── end-to-end: iOS URL surfaces in results["endpoints"] ─────────────────────

def test_ios_url_surfaces_as_called_endpoint():
    root = tempfile.mkdtemp()
    d = os.path.join(root, "Payload", "App.app")
    os.makedirs(d)
    with open(os.path.join(d, "Net.swift"), "w", encoding="utf-8") as f:
        f.write('func load() {\n'
                '  let doc = "https://dashif.org/spec"\n'          # bare constant -> referenced
                '  URLSession.shared.dataTask(with: URL(string: "https://api.checkin.io/v1")!).resume()\n'
                '}\n')
    results = {"platform": "ios", "app_info": {"bundle_id": "io.checkin"}}
    eps = ei.extract_endpoints(root, results=results)
    assert "https://api.checkin.io/v1" in eps, "iOS URLSession URL must be a called endpoint"
    assert "https://dashif.org/spec" not in eps, "bare constant stays referenced (filtered)"
    intel = {r["url"]: r["evidence"] for r in results["endpoints_intel"]}
    assert intel["https://api.checkin.io/v1"] == "called"
    assert intel["https://dashif.org/spec"] == "referenced"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")

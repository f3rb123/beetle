"""
Endpoint Intelligence — broad URL / endpoint extraction (Beetle 2.5.6).

Replaces the narrow, per-platform ``_extract_endpoints`` that scanned only
``.xml/.json/.properties/.js/.bundle/.txt`` and matched ``http(s)://`` ONLY — so
URLs hardcoded in Java / Kotlin / Smali / Dart / TypeScript and ``ws://`` /
custom-scheme deep links were invisible (the bug where a release app surfaced only
``http://127.0.0.1``).

A single extractor used by BOTH the Android and iOS pipelines:

  * Scans the decompiled tree across source / resource / config / smali / dart,
    reusing the evidence scanner's file caps + directory-skip filters.
  * Extracts ``http/https/ws/wss/ftp/ftps`` URLs PLUS app-specific custom-scheme
    deep links (``myapp://…``), excluding platform/spec noise schemes.
  * Filters framework/spec noise (xmlns, w3.org, schemas.android.com, …) and
    validates that each endpoint has a real host, to keep false positives low.
  * Returns a sorted, de-duplicated list destined for ``results["endpoints"]`` —
    where Finding Fusion's ``merge_endpoint_streams`` then unions APKLeaks hits.

Endpoints are informational intelligence (not findings), so broadening coverage
never inflates the findings false-positive rate; richer scheme/host grouping is
done by the Network panel and domain intelligence downstream.
"""
from __future__ import annotations

import os
import re

from .evidence_scanner import (
    is_binary_dump_path, _ev_should_skip_dir, _EV_MAX_FILES, _EV_MAX_FILE_BYTES,
)
from .source_corpus import SourceCorpus

# Source / resource / config / disassembly extensions — Android, iOS, Flutter, RN.
_EP_EXTENSIONS = (
    ".java", ".kt", ".kts", ".smali", ".dart", ".js", ".jsx", ".ts", ".tsx",
    ".mjs", ".cjs", ".xml", ".json", ".properties", ".txt", ".gradle", ".yaml",
    ".yml", ".conf", ".cfg", ".config", ".ini", ".env", ".swift", ".m", ".mm",
    ".h", ".plist", ".html", ".bundle", ".vue",
)

# Standard network URLs (group(0) is the whole URL).
_URL_RE = re.compile(r"(?:https?|wss?|ftps?)://[^\s\"'<>\\)\]}]+", re.I)
# Any scheme:// URI — used to harvest app custom-scheme deep links (myapp://…).
_SCHEME_RE = re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.\-]{1,28})://([^\s\"'<>\\)\]}]+)")
# Bare API base-URL hosts assigned to a base-url-like constant WITHOUT a scheme —
# the Retrofit/OkHttp/Volley/BuildConfig case the URL regex misses (e.g.
# BASE_URL = "api.example.com"). Gated on the key + a real alpha TLD to keep FP low.
_BASEURL_RE = re.compile(
    r"""(?ix)
    \b(?:base[_-]?url|api[_-]?url|api[_-]?host|api[_-]?base|endpoint|server[_-]?url|host)\b
    \s*[:=]\s*["']
    ([a-z0-9][a-z0-9.\-]+\.[a-z]{2,})        # bare host with an alpha TLD
    (?:[:/][^\s"']*)?["']
    """)
# Build-time literal hint substrings — keep a file in the scan even with no "://".
_BAREURL_HINTS = ("baseurl", "base_url", "api_url", "apiurl", "api_host",
                  "apihost", "endpoint", "server_url")

# Substrings that mark a spec / framework / store URL, not an app endpoint.
_NOISE_SUBSTR = (
    "schemas.android.com", "schema.org", "www.w3.org", "/w3.org/", "xmlns",
    "play.google.com/store", "developer.android.com", "apache.org/",
    "ns.adobe.com", "java.sun.com", "purl.org/", "specification",
    "schemas.microsoft.com", "example.com", "example.org", "localhost",
    "127.0.0.1",  # loopback is reported via IP intelligence, not as an endpoint
)

# Schemes that are platform/runtime noise — NOT app deep links.
_NOISE_SCHEMES = frozenset((
    "http", "https", "ws", "wss", "ftp", "ftps",          # handled by _URL_RE
    "file", "content", "android.resource", "jar", "data", "mailto", "tel",
    "sms", "smsto", "geo", "javascript", "blob", "about", "res", "asset",
    "assets", "classpath", "urn", "view-source", "chrome", "chrome-extension",
    "intent", "market",
))

# A scheme that is a plausible app deep link must look like a real custom scheme.
_DEEPLINK_HOST_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.\-_]*")

_MAX_ENDPOINTS = 500

# ── Call-context weighting ────────────────────────────────────────────────────
# A URL is "called" only when it is passed to a real HTTP client — not sitting in a
# constant pool, a comment, or a spec/library path. These markers are informed by the
# taint analyzer's Network sink list (Retrofit / OkHttp / java.net.URL / Volley) plus
# the Dart/Flutter (Dio / http) clients the taint DEX pass can't see. A marker must
# appear immediately BEFORE the URL literal for the URL to count as called.
try:
    from .taint_analyzer import SINKS as _TAINT_SINKS
    _TAINT_NET_TOKENS = tuple(sorted({
        lbl.lower().split(".")[0]  # class token, e.g. "okhttp", "url", "retrofit"
        for (_cls, _mth, lbl, cat, _sev) in _TAINT_SINKS if cat == "Network" and lbl
    }))
except Exception:  # pragma: no cover — taint import must never break endpoint extraction
    _TAINT_NET_TOKENS = ()

_HTTP_CALL_MARKERS = (
    "baseurl", "base_url",                                   # Retrofit.baseUrl / Dio baseUrl:
    ".url(", "newcall(", "request.builder", "requestbuilder",  # OkHttp Request.url / newCall
    "openconnection", "openstream", "new url(", "url(",      # java.net.URL(...).openConnection
    "stringrequest", "jsonobjectrequest", "jsonarrayrequest", "volley",  # Volley
    "dio(", "baseoptions", "uri.parse", "http.get", "http.post", "http.read",  # Dart / Flutter
    "httpurlconnection", "loadurl(", "retrofit", "webservice",
    # iOS / Swift / ObjC HTTP clients (URLSession, Alamofire, NSURLConnection). ADDITIVE:
    # Android source has none of this text, so it can only make MORE iOS URLs "called".
    "urlsession", "datatask(", "urlrequest(", ".request(", "af.request", "alamofire",
    "session.data", "nsurlconnection", "nsurlsession", "downloadtask(", "uploadtask(",
)
_CALL_WINDOW = 90  # chars of preceding context inspected for a client marker


def _url_is_called(content_low: str, start: int) -> bool:
    """True when a URL literal at ``start`` is preceded by an HTTP-client call marker
    (i.e. it is an ARGUMENT to a real client), not merely a referenced constant."""
    window = content_low[max(0, start - _CALL_WINDOW):start]
    return any(m in window for m in _HTTP_CALL_MARKERS)


def _clean(url: str) -> str:
    """Strip trailing punctuation/quoting that the greedy match may have pulled in."""
    return (url or "").rstrip("\"',;)]}>").strip()


def _has_host(url: str) -> bool:
    """True when a standard URL has a dotted host (filters ``http://`` fragments)."""
    m = re.match(r"(?:https?|wss?|ftps?)://([^/\s:]+)", url, re.I)
    if not m:
        return False
    host = m.group(1)
    return "." in host and len(host) > 3


def _accept(url: str) -> bool:
    low = url.lower()
    if len(url) < 12:
        return False
    if any(n in low for n in _NOISE_SUBSTR):
        return False
    return _has_host(url)


def _accept_deeplink(scheme: str, rest: str) -> bool:
    if scheme.lower() in _NOISE_SCHEMES:
        return False
    # Require something host/path-like after :// so we skip bare "scheme://".
    return bool(rest) and len(rest) >= 2 and bool(_DEEPLINK_HOST_RE.match(rest))


# A binary's string table has no delimiters, so adjacent literals abut and the URL regex
# swallows them as one token ("…/batch" + "https://crashlytics…" -> one 200-char blob).
# Split before every embedded scheme to recover the individual URLs.
_ABUTTED_SPLIT_RE = re.compile(r"(?=(?:https?|wss?|ftps?)://)", re.I)

# printf/NSString format placeholders (%@, %s, %1$s) and templating braces. In a HOST
# these mark a runtime-assembled template, not a reachable endpoint
# ("https://%@.app-analytics-services.com"). In a PATH they are fine — the host is still
# a real, reportable domain — so this is checked against the host only.
_FMT_PLACEHOLDER_RE = re.compile(r"%[@sdiuf]|%\d+\$[@sdiuf]|\{[^}]*\}|\$\{")


def _host_of(url: str) -> str:
    m = re.match(r"(?:https?|wss?|ftps?)://([^/\s:]+)", url, re.I)
    return m.group(1) if m else ""


def extract_urls_from_text(text: str) -> list[str]:
    """Accept-filtered URLs from a raw strings blob that has NO source context.

    For the compiled-binary path (iOS Mach-O strings), where there is no call site to
    prove against — a URL in a stripped AOT blob is a bare literal by construction, so
    the ``called`` weighting in :func:`extract_endpoints` can never fire and would drop
    every one of them. Same accept/clean filters as the text path, plus two defects that
    only a delimiter-less string table produces: abutted literals (split) and
    format-string hosts (dropped). Android's text-only path never calls this.
    """
    out: set[str] = set()
    for m in _URL_RE.finditer(text):
        for part in _ABUTTED_SPLIT_RE.split(m.group(0)):
            url = _clean(part)
            if not _accept(url):
                continue
            if _FMT_PLACEHOLDER_RE.search(_host_of(url)):
                continue    # runtime-assembled host template, not a real endpoint
            out.add(url)
    return sorted(out)


def _owner_lookup(results: dict | None):
    """(classify_fn, is_library_fn) using the shared ownership engine — consumed, not
    re-derived. Returns no-op classifiers when ownership is unavailable."""
    if not isinstance(results, dict):
        return (lambda _p: "Unknown"), (lambda _ot: False)
    try:
        from . import ownership as _own
        from .canonical_finding import CanonicalFinding as _CF
        ctx = _own.context_from_results(results)
        engine = _own.get_engine()
        platform = ctx.platform or "android"
        cache: dict[str, str] = {}

        def _classify(rel_path: str) -> str:
            if rel_path in cache:
                return cache[rel_path]
            try:
                ot = engine.classify(_CF(title="_ep", file_path=rel_path, platform=platform), ctx).owner_type
            except Exception:
                ot = "Unknown"
            cache[rel_path] = ot
            return ot

        return _classify, _own.is_library_owner
    except Exception:
        return (lambda _p: "Unknown"), (lambda _ot: False)


def _tag(rec: dict, *, called: bool, library: bool):
    """Fold one occurrence into a URL's aggregate evidence record."""
    if library:
        rec["lib"] = True
    else:
        rec["app"] = True
        if called:
            rec["called"] = True


def _evidence_of(rec: dict) -> str:
    if rec.get("called"):
        return "called"
    if rec.get("app"):
        return "referenced"
    return "library-owned"


def extract_endpoints(base_dir: str, extra_dirs: list | None = None, *,
                      corpus: SourceCorpus | None = None, results: dict | None = None,
                      verbose: bool = False) -> list[str]:
    """Broadly extract URLs + custom-scheme deep links from the decompiled tree.

    Each URL is tagged with call-context evidence — ``called`` (passed to an HTTP
    client), ``referenced`` (a bare constant/comment), or ``library-owned`` (only
    seen in framework/library files). By DEFAULT this returns only URLs the app
    actually calls (plus its own custom-scheme deep links and base-url configs); the
    full tagged inventory is stashed on ``results["endpoints_intel"]`` for verbose
    consumers. ``verbose=True`` returns every accepted URL.
    Return type is unchanged (sorted ``list[str]``) so existing readers are unaffected.
    """
    corpus = corpus or SourceCorpus()
    dirs: list[str] = []
    if extra_dirs:
        dirs.extend(d for d in extra_dirs if d and os.path.exists(d))
    if base_dir and os.path.exists(base_dir):
        dirs.append(base_dir)

    classify_owner, is_library = _owner_lookup(results)
    # url -> {called, app, lib, file} aggregate evidence.
    records: dict[str, dict] = {}

    def _record(url: str, *, called: bool, owner: str, rel: str):
        rec = records.setdefault(url, {"file": rel})
        _tag(rec, called=called, library=is_library(owner))
        rec.setdefault("file", rel)

    files_scanned = 0
    for scan_dir in dirs:
        if files_scanned >= _EV_MAX_FILES:
            break
        for root, subdirs, files in corpus.walk(scan_dir):
            rel_root = os.path.relpath(root, scan_dir)
            if rel_root != "." and _ev_should_skip_dir(rel_root):
                subdirs[:] = []
                continue
            for fname in files:
                if files_scanned >= _EV_MAX_FILES:
                    break
                if not fname.lower().endswith(_EP_EXTENSIONS) or is_binary_dump_path(fname):
                    continue
                fpath = os.path.join(root, fname)
                content = corpus.read_text(fpath, max_bytes=_EV_MAX_FILE_BYTES)
                if content is None:
                    continue
                files_scanned += 1
                low = content.lower()
                if "://" not in content and not any(h in low for h in _BAREURL_HINTS):
                    continue  # fast reject — no URI and no base-url constant here
                rel = os.path.relpath(fpath, scan_dir)
                owner = classify_owner(rel)
                for m in _URL_RE.finditer(content):
                    url = _clean(m.group(0))
                    if _accept(url):
                        _record(url, called=_url_is_called(low, m.start()), owner=owner, rel=rel)
                for m in _SCHEME_RE.finditer(content):
                    scheme, rest = m.group(1), m.group(2)
                    if scheme.lower() in _NOISE_SCHEMES:
                        continue
                    uri = _clean(m.group(0))
                    if _accept_deeplink(scheme, rest) and not any(n in uri.lower() for n in _NOISE_SUBSTR):
                        # An app custom-scheme deep link is app surface by construction —
                        # always "called" (it is the app's own entry point).
                        _record(uri, called=True, owner=owner, rel=rel)
                # Bare base-URL hosts (no scheme) → normalize to https for the inventory.
                for m in _BASEURL_RE.finditer(content):
                    host = m.group(1).strip().rstrip("/").lower()
                    if "." in host and not any(n in host for n in _NOISE_SUBSTR):
                        # Assigned to a base-url/api-url constant → a real client config.
                        _record(f"https://{host}", called=True, owner=owner, rel=rel)

    # Publish the full tagged inventory (additive) for verbose/Network-panel consumers.
    if isinstance(results, dict):
        results["endpoints_intel"] = [
            {"url": u, "evidence": _evidence_of(r), "owner_type": None, "file": r.get("file", "")}
            for u, r in sorted(records.items())
        ]

    if verbose:
        keep = list(records)
    else:
        # Default: only URLs the app actually CALLS (referenced constants and
        # library-owned URLs stay behind the verbose flag / endpoints_intel).
        keep = [u for u, r in records.items() if _evidence_of(r) == "called"]
    return sorted(keep)[:_MAX_ENDPOINTS]

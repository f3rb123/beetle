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


def extract_endpoints(base_dir: str, extra_dirs: list | None = None, *, corpus: SourceCorpus | None = None) -> list[str]:
    """Broadly extract URLs + custom-scheme deep links from the decompiled tree.
    Returns a sorted, de-duplicated list (capped) for ``results["endpoints"]``."""
    corpus = corpus or SourceCorpus()
    dirs: list[str] = []
    if extra_dirs:
        dirs.extend(d for d in extra_dirs if d and os.path.exists(d))
    if base_dir and os.path.exists(base_dir):
        dirs.append(base_dir)

    found: set[str] = set()
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
                for m in _URL_RE.finditer(content):
                    url = _clean(m.group(0))
                    if _accept(url):
                        found.add(url)
                for m in _SCHEME_RE.finditer(content):
                    scheme, rest = m.group(1), m.group(2)
                    if scheme.lower() in _NOISE_SCHEMES:
                        continue
                    uri = _clean(m.group(0))
                    if _accept_deeplink(scheme, rest) and not any(n in uri.lower() for n in _NOISE_SUBSTR):
                        found.add(uri)
                # Bare base-URL hosts (no scheme) → normalize to https for the inventory.
                for m in _BASEURL_RE.finditer(content):
                    host = m.group(1).strip().rstrip("/").lower()
                    if "." in host and not any(n in host for n in _NOISE_SUBSTR):
                        found.add(f"https://{host}")

    return sorted(found)[:_MAX_ENDPOINTS]

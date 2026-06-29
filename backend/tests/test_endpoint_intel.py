"""
Endpoint Intelligence — broad extraction (Phase 2.5.6) regression.

The previous extractor scanned only .xml/.json/.properties/.js/.bundle/.txt and
matched http(s):// only, so URLs in Java/Kotlin/Smali/Dart and ws:// / custom
deep links were missed (a release app surfaced only http://127.0.0.1). These
tests lock the broadened source + scheme coverage and the noise filtering.

Run: ``python -m pytest tests/test_endpoint_intel.py`` from the backend directory.
"""
from __future__ import annotations

import os
import tempfile

from analyzers import endpoint_intel


def _write(root: str, rel: str, content: str) -> None:
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _tree() -> tempfile.TemporaryDirectory:
    tmp = tempfile.TemporaryDirectory()
    r = tmp.name
    # URLs hidden in source the old extractor never scanned.
    _write(r, "sources/com/app/Api.kt", 'val base = "https://api.bank.example-corp.io/v2/login"\n')
    _write(r, "smali/com/app/Net.smali", 'const-string v0, "http://legacy.bank-corp.net/transfer"\n')
    _write(r, "lib/main.dart", "const url = 'https://flutter.bank-corp.net/session';\n")
    _write(r, "assets/app.js", 'const ws = "wss://realtime.bank-corp.net/socket";\n')
    # Custom-scheme deep link.
    _write(r, "res/values/links.xml", '<string name="cb">dvbankapp://oauth/callback?code=1</string>\n')
    # Noise that must be filtered out.
    _write(r, "res/layout/a.xml",
           '<x xmlns:android="http://schemas.android.com/apk/res/android" '
           'href="http://www.w3.org/2000/svg" local="http://127.0.0.1:8080/x"/>\n')
    return tmp


def test_extracts_across_sources_and_schemes():
    with _tree() as root:
        eps = endpoint_intel.extract_endpoints(root)
    joined = "\n".join(eps)
    assert "https://api.bank.example-corp.io/v2/login" in eps          # .kt
    assert "http://legacy.bank-corp.net/transfer" in eps               # .smali
    assert "https://flutter.bank-corp.net/session" in eps              # .dart
    assert "wss://realtime.bank-corp.net/socket" in eps                # ws scheme + .js
    assert any(e.startswith("dvbankapp://") for e in eps), joined      # custom deep link


def test_filters_framework_and_loopback_noise():
    with _tree() as root:
        eps = endpoint_intel.extract_endpoints(root)
    low = "\n".join(eps).lower()
    assert "schemas.android.com" not in low
    assert "w3.org" not in low
    assert "127.0.0.1" not in low   # loopback is IP intelligence, not an endpoint


def test_bare_base_url_hosts_extracted():
    # Retrofit/OkHttp/BuildConfig base URLs declared WITHOUT a scheme were missed.
    with tempfile.TemporaryDirectory() as root:
        _write(root, "sources/com/app/BuildConfig.java",
               'public static final String BASE_URL = "api.bank-corp.net";\n')
        _write(root, "sources/com/app/Api.kt",
               'const val API_HOST = "gateway.bank-corp.net/v1"\n')
        eps = endpoint_intel.extract_endpoints(root)
    assert "https://api.bank-corp.net" in eps
    assert "https://gateway.bank-corp.net" in eps


def test_empty_tree_is_clean():
    with tempfile.TemporaryDirectory() as root:
        _write(root, "a/b.kt", "val x = 1\n")
        assert endpoint_intel.extract_endpoints(root) == []

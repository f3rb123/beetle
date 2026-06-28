"""
Network Intelligence — IP Discovery tests (Beetle 2.0, Phase 1.99).

Covers the contract:

* IPv4 and IPv6 extraction from decompiled source / resources / config.
* Full classification taxonomy (public / private / loopback / link-local /
  multicast / reserved / broadcast / documentation / unspecified / unknown).
* Owner attribution via the Ownership Engine (Application vs third-party SDK).
* Duplicate suppression + occurrence MERGE (one canonical entry, many files).
* Placeholder / noise suppression (kept + counted, never dropped).
* Confidence calculation and intelligence tagging.
* Android and iOS use the SAME canonical model (parity).
* Backward compatibility: legacy fields (ip/type/file_path/line/confidence) survive.

Runnable standalone or under pytest:
    python -m tests.test_network_intel       # from backend/
"""
from __future__ import annotations

import os
import sys
import tempfile

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import network_intel as ni  # noqa: E402
from analyzers.network_intel import IPClass  # noqa: E402


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


APP = "com.company.app"


def _tree(files: dict) -> str:
    """Create a temp jadx-style tree {relpath: content} and return its root."""
    root = tempfile.mkdtemp()
    for rel, content in files.items():
        p = os.path.join(root, "jadx", "sources", *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(content)
    return root


def _annotate(root: str, platform: str = "android", pkg: str = APP) -> dict:
    results = {"platform": platform, "app_info": {"package": pkg, "bundle_id": pkg},
               "ips": ni.extract_ips(root)}
    ni.annotate(results, platform=platform)
    return results


def _by_ip(results: dict, ip: str) -> dict | None:
    return next((x for x in results["ips"] if x["ip"] == ip), None)


# ── Classification taxonomy ───────────────────────────────────────────────────
def test_classification_taxonomy():
    cases = {
        "34.117.59.81": IPClass.PUBLIC,
        "10.0.0.5": IPClass.PRIVATE,
        "192.168.1.50": IPClass.PRIVATE,
        "172.16.5.5": IPClass.PRIVATE,
        "127.0.0.1": IPClass.LOOPBACK,
        "169.254.1.1": IPClass.LINK_LOCAL,
        "224.0.0.1": IPClass.MULTICAST,
        "255.255.255.255": IPClass.BROADCAST,
        "0.0.0.0": IPClass.UNSPECIFIED,
        "192.0.2.10": IPClass.DOCUMENTATION,
        "2606:4700:4700::1111": IPClass.PUBLIC,
        "2001:db8::1": IPClass.DOCUMENTATION,
        "::1": IPClass.LOOPBACK,
        "fe80::1": IPClass.LINK_LOCAL,
        "ff02::1": IPClass.MULTICAST,
        "not.an.ip": IPClass.UNKNOWN,
    }
    for ip, expected in cases.items():
        _check(ni.classify(ip) == expected, f"{ip}: expected {expected}, got {ni.classify(ip)}")


# ── Extraction ────────────────────────────────────────────────────────────────
def test_ipv4_extraction():
    root = _tree({f"{APP.replace('.', '/')}/Net.java": 'String s = "34.117.59.81";'})
    res = _annotate(root)
    _check(_by_ip(res, "34.117.59.81") is not None, "IPv4 public address must be extracted")


def test_ipv6_extraction_including_compressed():
    root = _tree({f"{APP.replace('.', '/')}/Net.kt":
                  'val a = "2606:4700:4700::1111"\nval b = "2001:4860:4860:0:0:0:0:8888"'})
    res = _annotate(root)
    a, b = _by_ip(res, "2606:4700:4700::1111"), _by_ip(res, "2001:4860:4860:0:0:0:0:8888")
    _check(a is not None and a["version"] == 6, "compressed IPv6 must be extracted")
    _check(b is not None and b["version"] == 6, "full IPv6 must be extracted")
    _check(res["ip_intelligence"]["ipv6"] == 2, "summary must count both IPv6 addresses")


def test_times_and_versions_not_matched():
    root = _tree({f"{APP.replace('.', '/')}/build.gradle":
                  'String t = "12:30:45"\nversionName "9.8.7.6"'})
    res = _annotate(root)
    _check(_by_ip(res, "12:30:45") is None, "a time literal must not be matched as IPv6")
    _check(_by_ip(res, "9.8.7.6") is None, "a version declaration line must be filtered")


# ── Public / private + intelligence + confidence ──────────────────────────────
def test_public_and_private_visible_with_owner_and_confidence():
    root = _tree({f"{APP.replace('.', '/')}/ApiClient.kt":
                  'val base = "http://10.0.0.5:8080/api" // internal staging\nval prod = "34.117.59.81"'})
    res = _annotate(root)
    pub, priv = _by_ip(res, "34.117.59.81"), _by_ip(res, "10.0.0.5")
    _check(pub and pub["classification"] == IPClass.PUBLIC and not pub["suppressed"], "public IP must be visible")
    _check(priv and priv["classification"] == IPClass.PRIVATE, "private IP classified RFC1918")
    _check(priv["owner_type"] == "Application", "owner attributed via Ownership Engine")
    _check(0 < priv["confidence"] <= 99, "confidence must be a computed 1-99 score")
    _check("Hardcoded Internal IP" in priv["intelligence"], "private app IP must be flagged")


def test_loopback_surfaced_as_reference():
    root = _tree({f"{APP.replace('.', '/')}/Dbg.java": 'String h = "127.0.0.1";'})
    res = _annotate(root)
    lo = _by_ip(res, "127.0.0.1")
    _check(lo and lo["classification"] == IPClass.LOOPBACK, "loopback classified")
    _check("Loopback Reference" in lo["intelligence"], "loopback highlighted as a reference")


def test_reserved_and_noise_suppressed_by_default():
    root = _tree({f"{APP.replace('.', '/')}/A.xml":
                  "<a>169.254.0.1</a><b>224.0.0.1</b><c>192.0.2.5</c>"})
    res = _annotate(root)
    for ip in ("169.254.0.1", "224.0.0.1", "192.0.2.5"):
        e = _by_ip(res, ip)
        _check(e is not None, f"{ip} must be KEPT (not dropped) for auditability")
        _check(e["suppressed"] is True, f"{ip} (noise class) must be suppressed by default")
    _check(res["ip_intelligence"]["suppressed"] >= 3, "summary must count suppressed noise")


# ── Owner attribution ─────────────────────────────────────────────────────────
def test_owner_attribution_application_vs_sdk():
    root = _tree({
        f"{APP.replace('.', '/')}/Net.java": 'String s = "34.117.59.81";',
        "com/google/android/gms/X.java": 'String s = "52.10.20.30";',
    })
    res = _annotate(root)
    app_ip, sdk_ip = _by_ip(res, "34.117.59.81"), _by_ip(res, "52.10.20.30")
    _check(app_ip["owner_type"] == "Application", "app file IP owned by Application")
    _check(sdk_ip["owner_type"] != "Application", "GMS file IP must not be Application-owned")
    _check(app_ip["confidence"] > sdk_ip["confidence"],
           "application-owned IP must score higher confidence than an SDK one")


# ── Duplicate suppression + merge ─────────────────────────────────────────────
def test_duplicate_occurrences_merged():
    root = _tree({
        f"{APP.replace('.', '/')}/A.java": 'String s = "34.117.59.81";',
        f"{APP.replace('.', '/')}/B.java": 'String s = "34.117.59.81";',
        f"{APP.replace('.', '/')}/C.java": 'String s = "34.117.59.81";',
    })
    res = _annotate(root)
    hits = [x for x in res["ips"] if x["ip"] == "34.117.59.81"]
    _check(len(hits) == 1, "repeated IP must collapse to ONE canonical entry")
    _check(hits[0]["occurrences"] == 3, "occurrence count must be tracked")
    _check(len(hits[0]["merged_files"]) == 3, "all source files must be merged")
    _check("Multiple IP References" in hits[0]["intelligence"], "multi-reference must be tagged")


def test_placeholder_ips_suppressed():
    root = _tree({f"{APP.replace('.', '/')}/A.java": 'String s = "8.8.8.8"; String d="1.1.1.1";'})
    res = _annotate(root)
    for ip in ("8.8.8.8", "1.1.1.1"):
        e = _by_ip(res, ip)
        _check(e is not None and e["suppressed"] is True, f"placeholder {ip} must be suppressed")


# ── Android / iOS parity ──────────────────────────────────────────────────────
def test_android_ios_parity():
    files = {f"{APP.replace('.', '/')}/Net.swift": 'let s = "34.117.59.81"\nlet p = "10.0.0.5"'}
    a = _annotate(_tree(files), platform="android")
    i = _annotate(_tree(files), platform="ios")

    def shape(res):
        return sorted((x["ip"], x["classification"], x["suppressed"]) for x in res["ips"])
    _check(shape(a) == shape(i), "Android and iOS must classify/suppress identically")
    # Swift source must be scanned on BOTH platforms (parity for iOS source IPs).
    _check(_by_ip(i, "34.117.59.81") is not None, "iOS must extract IPs from Swift source")


# ── Backward compatibility ────────────────────────────────────────────────────
def test_backward_compatible_fields_present():
    root = _tree({f"{APP.replace('.', '/')}/Net.java": 'String s = "34.117.59.81";'})
    res = _annotate(root)
    e = _by_ip(res, "34.117.59.81")
    for k in ("ip", "type", "file_path", "line", "snippet", "confidence", "file_evidence"):
        _check(k in e, f"legacy field {k} must survive for existing consumers")
    _check(e["type"] == "public", "legacy 'type' must stay public/private for the Android finding + UI")


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
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())

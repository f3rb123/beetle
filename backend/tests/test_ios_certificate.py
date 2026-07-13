"""
Regression: the iOS report showed "No certificate data" because results["certificate"]
was never populated, even though signing certs + provisioning fields were parsed into
results["app_info"]. ios_analyzer now builds results["certificate"] from them, and the
PDF Certificate section is platform-aware (iOS: signing/provisioning; Android: unchanged).

Covers:
  * _build_ios_certificate populates a certificate dict with team/expiry/signing identity
  * the PDF row selection renders iOS signing/provisioning rows for platform=="ios"
  * the Android cert rows are byte-identical (no iOS rows leak in)
"""
from __future__ import annotations

import os
import sys

import pytest

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import ios_analyzer as ios  # noqa: E402


# ── _build_ios_certificate (pure, no reportlab) ──────────────────────────────

def _ios_results_signed():
    return {
        "platform": "ios",
        "app_info": {
            "bundle_id": "io.checkin",
            "provisioning_team": "Acme Inc",
            "provisioning_type": "distribution",
            "provisioning_profile": "Acme AppStore",
            "provisioning_expiry": "2027-01-01 00:00:00+00:00",
            "signing_certificates": [{
                "subject": "CN=Apple Distribution: Acme Inc (AB12CD34),OU=AB12CD34,O=Acme Inc,C=US",
                "issuer":  "CN=Apple Worldwide Developer Relations Certification Authority,OU=G3,O=Apple Inc.,C=US",
                "serial":  "0a1b2c",
                "not_before": "2024-01-01T00:00:00Z",
                "not_after":  "2099-01-01T00:00:00Z",
                "sha1":   "deadbeef",
                "sha256": "cafebabe",
            }],
        },
        "findings": [],
    }


def test_build_ios_certificate_populates_signing_and_provisioning():
    r = _ios_results_signed()
    ios._build_ios_certificate(r)
    cert = r["certificate"]
    assert cert["available"] is True
    assert cert["platform"] == "ios"
    assert cert["signing_identity"] == "Apple Distribution: Acme Inc (AB12CD34)"
    assert cert["team"] == "Acme Inc"
    assert cert["provisioning_type"] == "distribution"
    assert cert["provisioning_profile"] == "Acme AppStore"
    assert cert["provisioning_expiry"].startswith("2027-01-01")
    assert cert["subject"]["O"] == "Acme Inc"
    assert cert["issuer"]["CN"].startswith("Apple Worldwide Developer Relations")
    assert cert["valid_from"] == "2024-01-01"
    assert cert["valid_to"] == "2099-01-01"
    assert cert["expired"] is False          # not_after is in the future → derived, not assumed
    assert cert["sha256_fingerprint"] == "cafebabe"


def test_build_ios_certificate_expired_is_derived_from_date():
    r = _ios_results_signed()
    r["app_info"]["signing_certificates"][0]["not_after"] = "2001-01-01T00:00:00Z"
    ios._build_ios_certificate(r)
    assert r["certificate"]["expired"] is True


def test_build_ios_certificate_provisioning_only_no_certs():
    r = {"platform": "ios", "app_info": {"provisioning_team": "Acme Inc",
                                         "provisioning_type": "development"}, "findings": []}
    ios._build_ios_certificate(r)
    cert = r["certificate"]
    assert cert["available"] is True
    assert cert["team"] == "Acme Inc"
    assert cert["signing_identity"] == ""     # no leaf cert
    assert "expired" not in cert              # unknown, not assumed


def test_build_ios_certificate_unsigned_leaves_section_absent():
    r = {"platform": "ios", "app_info": {"bundle_id": "io.x"}, "findings": []}
    ios._build_ios_certificate(r)
    assert "certificate" not in r             # → report shows "No certificate data", as before


def test_build_ios_certificate_never_overwrites_existing():
    r = _ios_results_signed()
    r["certificate"] = {"available": True, "sentinel": 1}
    ios._build_ios_certificate(r)
    assert r["certificate"] == {"available": True, "sentinel": 1}


def test_rfc4514_attrs_handles_escaped_comma():
    a = ios._rfc4514_attrs("CN=Doe\\, Inc,O=Doe Holdings,C=US")
    assert a["CN"] == "Doe, Inc"
    assert a["O"] == "Doe Holdings"


# ── PDF row selection: platform-aware, Android byte-identical ────────────────
# reportlab-gated: import lazily so the _build_ios_certificate tests above still run
# in environments without reportlab (only the two PDF-row tests below are skipped).
try:
    from report import pdf_generator as pg  # noqa: E402
    _HAS_PG = True
except Exception:
    pg = None
    _HAS_PG = False

_pdf_only = pytest.mark.skipif(not _HAS_PG, reason="reportlab not installed")


_ANDROID_CERT = {
    "available": True,
    "subject": {"CN": "Acme", "O": "Acme Inc"},
    "issuer":  {"CN": "Acme", "O": "Acme Inc"},
    "self_signed": True,
    "debug_cert": False,
    "valid_from": "2020-01-01",
    "valid_to": "2045-01-01",
    "key_type": "RSA",
    "key_size": 2048,
    "signature_algo": "SHA256withRSA",
    "scheme": ["v2", "v3"],
    "sha256_fingerprint": "AA:BB",
}

# The exact rows the pre-change Android branch produced (frozen snapshot).
_ANDROID_ROWS_EXPECTED = [
    ["Subject CN",    "Acme"],
    ["Subject O",     "Acme Inc"],
    ["Issuer CN",     "Acme"],
    ["Self-Signed",   "Yes ⚠"],
    ["Debug Cert",    "No"],
    ["Valid From",    "2020-01-01"],
    ["Valid To",      "2045-01-01"],
    ["Key Type",      "RSA"],
    ["Key Size",      "2048 bits"],
    ["Sig Algorithm", "SHA256withRSA"],
    ["Scheme",        "v2, v3"],
    ["SHA-256",       "AA:BB"],
]


@_pdf_only
def test_android_cert_rows_byte_identical():
    for platform in ("android", None, "", "flutter"):  # anything non-iOS → Android rows
        assert pg._certificate_rows(_ANDROID_CERT, platform) == _ANDROID_ROWS_EXPECTED


@_pdf_only
def test_ios_cert_rows_render_signing_and_provisioning():
    r = _ios_results_signed()
    ios._build_ios_certificate(r)
    rows = pg._certificate_rows(r["certificate"], "ios")
    labels = [lbl for lbl, _ in rows]
    values = {lbl: val for lbl, val in rows}
    # iOS-specific rows present …
    assert "Signing Identity" in labels
    assert "Team" in labels and values["Team"] == "Acme Inc"
    assert "Provisioning" in labels and values["Provisioning"] == "Distribution"
    assert "Profile Expiry" in labels and values["Profile Expiry"].startswith("2027")
    # … and the Android-only rows are absent.
    for android_only in ("Self-Signed", "Debug Cert", "Key Type", "Key Size",
                         "Sig Algorithm", "Scheme"):
        assert android_only not in labels, f"iOS section must not render {android_only}"


@_pdf_only
def test_ios_expired_marker_in_valid_to():
    cert = {"available": True, "platform": "ios", "subject": {}, "issuer": {},
            "valid_to": "2001-01-01", "expired": True}
    rows = dict(pg._certificate_rows(cert, "ios"))
    assert "EXPIRED" in rows["Valid To"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))

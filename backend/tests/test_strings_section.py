"""Strings section (RUN 13) — both platforms.

TWO THINGS THIS MUST NEVER DO:

1. LEAK A SECRET. This is the highest-risk surface in the product: it shows the raw strings
   themselves. The secret pipeline masks only the fields it knows about — exactly how RUN 12
   leaked the Firebase API key in plaintext through a new section. Every value here goes through
   redact() -> secret_intel.mask_value first.

2. SHIP MobSF'S EMAIL GARBAGE. On this app the raw email regex yields 48 hits and 44 (91%) are
   Dart runtime symbols (_AnonymousRestorationInformation@133124995.fromSerializableData). Only
   real addresses survive.
"""
from analyzers import strings_section as ss

REAL_KEY = "AIzaSyCw2rXeRTyaNxZ3cBm3gUip5sfZ1fW88rI"


# ── 1. secret leak ───────────────────────────────────────────────────────────
def test_a_secret_in_the_string_table_is_masked_never_shown_raw():
    results = {"string_analysis": {
        "Hidden URL / API Endpoint": {
            "severity": "info", "count": 2,
            "matches": [{"value": REAL_KEY, "files": ["Runner"]},
                        {"value": "https://httpbin.org/post", "files": ["Runner"]}],
        }}}
    section = ss.build(results)
    values = [m["value"] for c in section["categories"] for m in c["matches"]]
    assert REAL_KEY not in values, "the raw API key must never reach the Strings section"
    import json
    assert REAL_KEY not in json.dumps(section), "not anywhere in the section"
    masked = next(m for c in section["categories"] for m in c["matches"] if m["masked"])
    assert masked["value"].startswith("AIza")          # recognisable shape survives
    assert section["masked_count"] == 1
    # A harmless string is untouched.
    assert "https://httpbin.org/post" in values


def test_redact_uses_the_same_masking_as_the_secrets_table():
    from analyzers.secret_intel import mask_value
    shown, masked = ss.redact(REAL_KEY)
    assert masked is True
    assert shown == mask_value(REAL_KEY), "one masking implementation, not a second"


def test_ordinary_strings_are_not_masked():
    shown, masked = ss.redact("FLAG_SECURE")
    assert masked is False and shown == "FLAG_SECURE"


# ── 2. email FP filter ───────────────────────────────────────────────────────
DART_GARBAGE = [
    "_AnonymousRestorationInformation@133124995.fromSerializableData",
    "_BigIntImpl@0150898.from",
    "_growablelist@0150898._literal8",
    "_httpparser@17463476.responsepa",
    "_bytebuffer@8027147._new",
]


def test_dart_runtime_symbols_are_not_emails():
    for garbage in DART_GARBAGE:
        assert not ss.is_reportable_email(garbage), garbage


def test_format_string_hosts_are_not_emails():
    # "%@.app-analytics-services.com" is a runtime-assembled host, not an address
    # (same class as RUN 1.1's format-string URLs).
    assert not ss.is_reportable_email("%@.app-analytics-services.com")
    assert not ss.is_reportable_email("%@.app-analytics-services-att.com")


def test_library_internal_addresses_are_dropped():
    # A real address, but it is OpenSSL's, not the app's.
    assert not ss.is_reportable_email("appro@openssl.org")


def test_the_real_address_survives():
    # The one genuine address in this app (MobSF found it too, buried in 95% garbage).
    assert ss.is_reportable_email("service.coord@cvx.com")


def test_email_section_keeps_only_real_addresses():
    section = ss.build({}, extra_emails=DART_GARBAGE + [
        "service.coord@cvx.com", "appro@openssl.org", "%@.app-analytics-services.com"])
    assert section["emails"] == ["service.coord@cvx.com"]
    assert section["emails_rejected"] == 7


# ── the section is a surface, not a detector ─────────────────────────────────
def test_section_emits_no_findings():
    results = {"findings": [], "string_analysis": {}}
    ss.build(results)
    assert results["findings"] == []


def test_urls_and_ips_come_from_the_shared_run1_sets():
    results = {"endpoints": ["https://b.example.com", "https://a.example.com"],
               "ips": [{"ip": "192.168.161.138"}, {"ip": "192.168.161.138"}]}
    section = ss.build(results)
    assert section["urls"] == ["https://a.example.com", "https://b.example.com"]
    assert section["ips"] == ["192.168.161.138"]      # de-duplicated


def test_a_potential_secret_category_is_masked_even_if_the_catalog_misses_it():
    # string_analyzer labels these "(Potential Secret)". Printing the raw value of a string the
    # report has just called a potential secret is the RUN 12 leak wearing a different hat --
    # and the secret CATALOG does not match a bare base64 blob, so the category is the trigger.
    blob = "I1pbrAfvNd+dE01BN/vpphGvZfT3YiFNhVowUJhGC9bpmz44b"
    results = {"string_analysis": {"Base64 Encoded String (Potential Secret)": {
        "severity": "info", "count": 1, "matches": [{"value": blob, "files": ["Runner"]}]}}}
    section = ss.build(results)
    m = section["categories"][0]["matches"][0]
    assert m["masked"] is True
    assert m["value"] != blob
    import json
    assert blob not in json.dumps(section)


def test_a_benign_category_is_still_shown_in_full():
    results = {"string_analysis": {"Hardcoded IP Address": {
        "severity": "info", "count": 1, "matches": [{"value": "192.168.161.138", "files": ["x"]}]}}}
    section = ss.build(results)
    m = section["categories"][0]["matches"][0]
    assert m["masked"] is False and m["value"] == "192.168.161.138"

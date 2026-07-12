"""OSV dependency-scan COVERAGE (RUN 14).

RUN 8.1 deferred the "Up-to-date Dependencies" MASVS control to this run, because it cannot be
credited until OSV coverage is PROVEN real. "0 CVEs" is meaningless unless the scanner could
actually have found one.

It could not. Every dependency in this app is a CocoaPod, and OSV has NO CocoaPods ecosystem, so
all 39 queries return empty BY CONSTRUCTION. On top of that, 17 of the 39 carry a placeholder
version ("0.0.1" from a Flutter plugin's framework Info.plist) that could never match an advisory
even in a supported ecosystem.

So the honest verdict is NOT "no known vulnerabilities" — it is "not assessable". These tests lock
that distinction, and lock that the scanner DOES flag a real advisory when the ecosystem answers
(so a future zero is a real zero, not a dead scanner).
"""
from analyzers import cve_mapper


def test_the_scanner_is_not_dead_it_flags_a_known_vulnerable_package(monkeypatch):
    """POSITIVE CONTROL. Inject a package@version with a known advisory and confirm it is
    flagged — proving a zero elsewhere is a real answer, not a broken pipeline."""
    fake_vuln = {
        "id": "GHSA-test-1234", "summary": "Prototype pollution in lodash",
        "severity": [{"type": "CVSS_V3", "score": "7.4"}],
        "aliases": ["CVE-2020-8203"],
    }
    monkeypatch.setattr(cve_mapper, "_query_osv",
                        lambda product, version, ecosystem: [fake_vuln]
                        if (product, ecosystem) == ("lodash", "npm") else [])
    monkeypatch.setattr(cve_mapper, "load_kev_set", lambda: set())
    monkeypatch.setattr(cve_mapper, "_init_cache", lambda: None)

    out = cve_mapper.analyze_packages(
        [{"product": "lodash", "version": "4.17.15", "ecosystem": "npm", "file": "x"}])
    assert out["stats"]["cves_matched"] == 1, "a known-vulnerable dependency MUST be flagged"
    assert out["findings"], "the advisory must reach the findings"


def test_an_ecosystem_that_does_not_answer_makes_components_unassessable(monkeypatch):
    # CocoaPods: OSV has no such ecosystem, so the canary returns nothing.
    monkeypatch.setattr(cve_mapper, "_query_osv", lambda p, v, e: [])
    cov = cve_mapper.assess_coverage([
        {"product": "FirebaseCore", "version": "11.15.0", "ecosystem": "CocoaPods"},
        {"product": "nanopb", "version": "2.30910.0", "ecosystem": "CocoaPods"},
    ])
    assert cov["verdict"] == "no_coverage"
    assert cov["assessable"] == 0
    assert cov["unassessable"] == 2
    assert cov["ecosystems"]["CocoaPods"]["osv_answers"] is False
    assert "NOT a clean bill of health" in cov["ecosystems"]["CocoaPods"]["reason"]


def test_an_ecosystem_that_answers_makes_real_versions_assessable(monkeypatch):
    # npm answers (the canary comes back with advisories), so a real version IS assessable.
    monkeypatch.setattr(cve_mapper, "_query_osv",
                        lambda p, v, e: [{"id": "GHSA-x"}] if e == "npm" else [])
    cov = cve_mapper.assess_coverage([
        {"product": "lodash", "version": "4.17.15", "ecosystem": "npm"},
    ])
    assert cov["verdict"] == "full"
    assert cov["assessable"] == 1
    assert cov["ecosystems"]["npm"]["osv_answers"] is True


def test_placeholder_versions_are_never_assessable(monkeypatch):
    # Even in an ecosystem that answers, "0.0.1" from a Flutter plugin's Info.plist is not a
    # real released version — it could never match an advisory.
    monkeypatch.setattr(cve_mapper, "_query_osv",
                        lambda p, v, e: [{"id": "GHSA-x"}] if e == "Pub" else [])
    cov = cve_mapper.assess_coverage([
        {"product": "image_picker_ios", "version": "0.0.1", "ecosystem": "Pub"},
        {"product": "http", "version": "0.13.0", "ecosystem": "Pub"},
    ])
    assert cov["placeholder_versions"] == 1
    assert cov["assessable"] == 1          # only the real version
    assert cov["verdict"] == "partial"


def test_no_components_is_not_reported_as_coverage(monkeypatch):
    monkeypatch.setattr(cve_mapper, "_query_osv", lambda p, v, e: [])
    cov = cve_mapper.assess_coverage([])
    assert cov["verdict"] == "no_components"
    assert cov["assessable"] == 0

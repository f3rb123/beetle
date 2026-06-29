"""
Secret Intelligence counting accuracy (Phase 2.5.1) — regression.

Locks two guarantees the analyst-facing counters depend on:

  1. Canonical partition — every VISIBLE secret has exactly one primary category,
     so the per-category counts always sum to the reported total. Previously the
     UI mixed overlapping facets (Application Secrets ⊇ Credential Pairs, plus the
     orthogonal Validation Candidates), so the displayed categories never equalled
     the total.
  2. Merge dedup — a secret detected by BOTH Beetle Native and APKLeaks collapses
     to a single entry (unioned detected_by) so Finding Fusion never double-counts.

Run: ``python -m pytest tests/test_secret_counting.py`` from the backend directory.
"""
from __future__ import annotations

from analyzers import secret_intel
from analyzers.secret_intel import PRIMARY_CATEGORIES, primary_category, process_secrets
from analyzers.detection_sources.fusion import merge_secret_streams


APP_PKG = "com.acme.bank"
_APP = f"sources/{APP_PKG.replace('.', '/')}"


def _raw(name, value, path, *, line=10, severity="high", confidence=90):
    """A detector-shaped raw secret that passes the evidence gate."""
    snippet = f'String s = "{value}";'
    return {
        "name": name, "value": value, "file_path": path, "line": line,
        "snippet": snippet, "code_context": snippet,
        "severity": severity, "confidence": confidence,
    }


# ── 1. primary_category is total + mutually exclusive ────────────────────────
def test_primary_category_is_canonical_and_exhaustive():
    cases = [
        ({"is_pair": True, "provider": "AWS", "type": "AWS_CREDENTIAL_PAIR"}, "Credential Pairs"),
        ({"provider": "GOOGLE", "type": "GOOGLE_API_KEY"}, "Cloud Credentials"),
        ({"provider": "AWS", "type": "AWS_ACCESS_KEY"}, "Cloud Credentials"),
        ({"provider": "PRIVATE_KEY", "type": "PEM_PRIVATE_KEY"}, "Private Keys"),
        ({"provider": "GCP", "type": "GCP_SERVICE_ACCOUNT_KEY"}, "Private Keys"),
        ({"provider": "GITHUB", "type": "GITHUB_PAT"}, "API Keys & Tokens"),
        ({"provider": "GENERIC", "type": "GENERIC_API_KEY"}, "API Keys & Tokens"),
        ({"provider": "GENERIC", "type": "HARDCODED_PASSWORD"}, "Passwords & Logins"),
        ({"provider": "GENERIC", "type": "SOMETHING_ELSE"}, "Other Secrets"),
    ]
    for secret, expected in cases:
        got = primary_category(secret)
        assert got == expected, f"{secret} -> {got}, expected {expected}"
        assert got in PRIMARY_CATEGORIES


# ── 2. process_secrets: per-category counts sum to the total ─────────────────
def test_category_counts_sum_to_total():
    results = {"secrets": [
        # AWS access + secret in the same file → fuse into ONE Credential Pair.
        _raw("AWS Access Key ID", "AKIA" + "QWERTYUIOPLKJHGF", f"{_APP}/Cfg.java", line=11),
        _raw("AWS Secret Access Key", "wJalr" + "XUtnFEMIKxQwErTyUiOpAsDfGhJkLzXcVbNm", f"{_APP}/Cfg.java", line=12),
        # Cloud credential.
        _raw("Google API Key", "AIza" + "SyBkMxQvRtWnZpLcHdGfJsAuYbXeWvQrTaP", f"{_APP}/Net.java"),
        # API key/token.
        _raw("GitHub Personal Access Token", "ghp_" + "MxQvRtWnZpLcHdGfKbVnTyUq0123456789", f"{_APP}/Api.java"),
        # Private key.
        _raw("PEM Private Key", "-----BEGIN PRIVATE KEY-----\nMIIBVwIBADAN\n-----END PRIVATE KEY-----", f"{_APP}/Keys.java"),
    ]}

    summary = process_secrets(results, app_package=APP_PKG)
    visible = results["secrets"]
    by_cat = summary["secrets_by_category"]

    # The partition invariant — the whole point of Phase 2.5.1.
    assert sum(c["count"] for c in by_cat) == len(visible) == summary["total_application_secrets"]

    # Every visible secret carries exactly one canonical primary category.
    for s in visible:
        assert s["primary_category"] in PRIMARY_CATEGORIES

    # The breakdown only lists known categories, no duplicates, no zero rows.
    seen = [c["category"] for c in by_cat]
    assert len(seen) == len(set(seen))
    assert all(c["category"] in PRIMARY_CATEGORIES and c["count"] > 0 for c in by_cat)

    # The AWS pair collapsed the two halves → exactly one Credential Pair row.
    pair_rows = [c for c in by_cat if c["category"] == "Credential Pairs"]
    assert pair_rows and pair_rows[0]["count"] == 1


def test_identical_secrets_deduped_before_counting():
    # The SAME secret arrives from two producers (same provider/type/value/path:line).
    dup = lambda src: {  # noqa: E731
        "name": "Google API Key", "value": "AIza" + "SyBkMxQvRtWnZpLcHdGfJsAuYbXeWvQrTaP",
        "file_path": f"{_APP}/Net.java", "line": 7, "snippet": 'k = "AIza...";',
        "severity": "high", "confidence": 90, "detected_by": [src], "source": src,
    }
    results = {"secrets": [dup("Beetle Native"), dup("APKLeaks")]}
    summary = process_secrets(results, app_package=APP_PKG)

    assert len(results["secrets"]) == 1, "identical secret must be counted once"
    assert summary["total_application_secrets"] == 1
    assert summary["deduplicated_secrets"] == 1
    # Attribution from both producers is preserved on the single kept secret.
    assert set(results["secrets"][0].get("detected_by", [])) >= {"Beetle Native", "APKLeaks"}
    # Partition still sums to the (deduped) total.
    assert sum(c["count"] for c in summary["secrets_by_category"]) == 1


def test_empty_secrets_partition_is_consistent():
    results = {"secrets": []}
    summary = process_secrets(results, app_package=APP_PKG)
    assert summary["secrets_by_category"] == []
    assert summary["total_application_secrets"] == 0 == len(results["secrets"])


# ── 3. merged Native + APKLeaks secret counts once ──────────────────────────
def test_native_and_apkleaks_merge_counts_once():
    value = "AKIA" + "ZZZZ1111QWER2222AS"
    results = {"secrets": [
        {"name": "AWS Access Key ID", "value": value,
         "file_path": f"{_APP}/Cfg.java", "line": 5, "snippet": "x", "source": "Beetle Native"},
    ]}
    apkleaks_hit = {"name": "AWS Access Key ID", "value": value,
                    "file_path": f"{_APP}/Cfg.java", "line": 5, "snippet": "x", "source": "APKLeaks"}

    stats = merge_secret_streams(results, [apkleaks_hit])

    assert len(results["secrets"]) == 1, "same (type, value) must collapse to one secret"
    assert stats["merged"] == 1 and stats["added"] == 0
    detected_by = results["secrets"][0].get("detected_by") or []
    assert "APKLeaks" in detected_by and "Beetle Native" in detected_by

"""RUN 32 — StrandHogg 2.0 (CVE-2020-0096) platform-gated detector.

StrandHogg 2.0 hits ANY exported activity on targetSdk < 29 — no risky launchMode or
taskAffinity required (that is StrandHogg 1.0). These tests lock BOTH directions of the
gate and the calibrated per-activity severity:
  - fires only when targetSdk < 29,
  - stays silent at targetSdk >= 29 AND when targetSdk is unknown (no false alarm),
  - one GROUPED finding (not N cards),
  - sensitive-flow OR launcher => HIGH; any other exported activity => MEDIUM,
  - remediation names targetSdk >= 29 and the finding cites CVE-2020-0096.
"""
import pytest

from analyzers.android_analyzer import _detect_strandhogg2, _sdk_int


def _results(target_sdk, activities):
    return {
        "app_info": {"target_sdk": target_sdk},
        "attack_surface": {"activities": activities},
        "findings": [],
    }


def _act(short, exported=True, launcher=False):
    return {"name": f"com.x.{short}", "short_name": short,
            "exported": exported, "is_launcher": launcher}


def _sh2(results):
    return [f for f in results["findings"] if f["rule_id"] == "manifest_strandhogg2"]


# ── the gate — both directions ───────────────────────────────────────────────
def test_fires_below_29():
    r = _results(22, [_act("PostLogin")])
    _detect_strandhogg2(r)
    assert len(_sh2(r)) == 1


def test_silent_at_29():
    r = _results(29, [_act("PostLogin")])
    _detect_strandhogg2(r)
    assert _sh2(r) == []


def test_silent_above_29():
    r = _results(33, [_act("PostLogin")])
    _detect_strandhogg2(r)
    assert _sh2(r) == []


def test_silent_when_target_sdk_unknown():
    """'?' / missing targetSdk must NOT fire — absence of evidence is not vulnerability."""
    for unknown in ("?", "", None, "n/a"):
        r = _results(unknown, [_act("PostLogin")])
        _detect_strandhogg2(r)
        assert _sh2(r) == [], f"unknown target_sdk {unknown!r} must not fire"


def test_silent_with_no_exported_activities():
    r = _results(22, [_act("Internal", exported=False)])
    _detect_strandhogg2(r)
    assert _sh2(r) == []


# ── grouping + severity calibration ──────────────────────────────────────────
def test_groups_into_one_finding_with_all_rows():
    r = _results(22, [
        _act("LoginActivity", launcher=True),
        _act("PostLogin"),
        _act("DoTransfer"),
        _act("ViewStatement"),
        _act("ChangePassword"),
        _act("Internal", exported=False),  # excluded — not exported
    ])
    _detect_strandhogg2(r)
    f = _sh2(r)[0]
    rows = {row["short_name"]: row["severity"] for row in f["strandhogg2_activities"]}
    assert set(rows) == {"LoginActivity", "PostLogin", "DoTransfer",
                         "ViewStatement", "ChangePassword"}
    # The exact InsecureBankv2 calibration (owner-ratified, rule-derived):
    assert rows["LoginActivity"] == "high"    # launcher
    assert rows["PostLogin"] == "high"        # 'login'
    assert rows["DoTransfer"] == "high"       # 'transfer'
    assert rows["ViewStatement"] == "medium"  # no keyword, not launcher
    assert rows["ChangePassword"] == "medium" # 'password'/'change' NOT in the set
    assert f["severity"] == "high"            # overall = max


def test_non_sensitive_non_launcher_is_medium():
    r = _results(22, [_act("SettingsActivity")])
    _detect_strandhogg2(r)
    assert _sh2(r)[0]["strandhogg2_activities"][0]["severity"] == "medium"
    assert _sh2(r)[0]["severity"] == "medium"


def test_launcher_alone_is_high():
    r = _results(22, [_act("SplashActivity", launcher=True)])
    _detect_strandhogg2(r)
    assert _sh2(r)[0]["strandhogg2_activities"][0]["severity"] == "high"


# ── metadata contract ────────────────────────────────────────────────────────
def test_finding_metadata_and_remediation():
    r = _results(22, [_act("PostLogin")])
    _detect_strandhogg2(r)
    f = _sh2(r)[0]
    assert f["cwe"] == "CWE-926"
    assert f["masvs"] == "MASVS-PLATFORM-1"
    assert f["owasp"] == "M1"
    assert f["cve"] == "CVE-2020-0096"
    assert "29" in f["recommendation"] and "targetSdk" in f["recommendation"]
    assert f["target_sdk"] == 22
    # evidence anchors on the targetSdkVersion line so the finding survives enforcement
    assert f["manifest_evidence_spec"] == {"attr": "targetSdkVersion", "value": "22"}


def test_sdk_int_parsing():
    assert _sdk_int("22") == 22
    assert _sdk_int(29) == 29
    assert _sdk_int("?") is None
    assert _sdk_int(None) is None
    assert _sdk_int("") is None


def test_strandhogg_finding_is_not_tagged_code_loading():
    """Regression (caught in RUN 32 artifact verification): the chain engine's capability
    tagger matches a bare 'reflection' substring in a finding's prose. StrandHogg 2.0 is
    task hijacking, NOT dynamic code loading — its description must not carry a token that
    mis-tags it CODE_LOADING and assembles a bogus 'Dynamic Code Loading / Reflection RCE'
    chain. Locks the wording so the FP cannot silently return."""
    from analyzers.attack_chains.engine import tag_capabilities
    r = _results(22, [_act("PostLogin"), _act("DoTransfer"), _act("Login", launcher=True)])
    _detect_strandhogg2(r)
    f = _sh2(r)[0]
    caps = tag_capabilities(f)
    assert "CODE_LOADING" not in caps, (
        f"StrandHogg 2.0 must not be tagged CODE_LOADING (got {sorted(caps)}); "
        "check the description for a 'reflection'/'dynamic code' trigger token")

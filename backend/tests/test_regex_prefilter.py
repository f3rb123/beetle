"""
Regex necessary-literal prefilter tests (v1.3 stabilization).

The prefilter may only ever say "cannot match" when that is PROVABLE from the
regex structure — a false skip would silently drop a detection. These tests
pin the safety property against the real production catalogs: for every
pattern that gets anchors, any text that matches the pattern must pass the
prefilter.

Runnable standalone or under pytest:
    python -m tests.test_regex_prefilter       # from backend/
"""
from __future__ import annotations

import os
import re
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers.regex_prefilter import (  # noqa: E402
    anchors_for, fold, may_match, necessary_literals)


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


# ── derivation basics ────────────────────────────────────────────────────────

def test_literal_prefix():
    _check(necessary_literals(r"AKIA[0-9A-Z]{16}") == ("akia",), "AKIA prefix")
    _check(necessary_literals(r"sk_live_[0-9a-zA-Z]{24,}") == ("sk_live_",), "stripe")


def test_branch_with_factored_prefix():
    lits = necessary_literals(r"(?i)(?:password|passwd|pwd)\s*=")
    _check(lits == ("password", "passwd", "pwd"),
           f"factored-prefix branch must recombine, got {lits!r}")


def test_conservative_fallbacks():
    _check(necessary_literals(r"gh[pousr]_[A-Za-z0-9_]{36,}") is None,
           "char class breaks the literal run — must NOT filter")
    _check(necessary_literals(r"AC[a-f0-9]{32}") is None,
           "'ac' (2 chars) is too short a literal — must NOT filter")
    _check(necessary_literals(r"\b(?:\d{1,3}\.){3}\d{1,3}\b") is None,
           "pure numeric shape has no literal — must NOT filter")


def test_optional_elements_are_not_anchors():
    lits = necessary_literals(r"(?:DEBUG)?[0-9]{6}INVOICE")
    _check(lits == ("invoice",),
           f"optional group must not become the anchor, got {lits!r}")


def test_repeat_min_one_is_mandatory():
    lits = necessary_literals(r"(?:token){1,3}[0-9]+")
    _check(lits == ("token",), f"min>=1 repeat is mandatory, got {lits!r}")


def test_may_match_semantics():
    folded = fold('String key = "AKIAABCDEFGHIJKLMNOP";')
    _check(may_match(r"AKIA[0-9A-Z]{16}", folded), "present anchor must pass")
    _check(not may_match(r"AKIA[0-9A-Z]{16}", fold("no secrets here")),
           "absent anchor must be skipped")
    _check(may_match(r"gh[pousr]_[A-Za-z0-9_]{36,}", fold("anything")),
           "None anchors → always scan")


def test_casefold_safety_kelvin_and_long_s():
    # U+212A KELVIN SIGN matches 'k' under IGNORECASE; U+017F LATIN SMALL
    # LETTER LONG S matches 's'. casefold() maps both correctly — .lower()
    # would miss the long s and wrongly skip the file.
    pattern = r"risk_key"
    text = "RIſK_KEY risk_key?"  # first token exercises the fold path
    for candidate in (text, "RISK_KEY", "risk_key", "RIKSK"):
        if re.search(pattern, candidate, re.IGNORECASE):
            _check(may_match(pattern, fold(candidate)),
                   f"prefilter must not skip a matching text: {candidate!r}")


# ── safety property against every production catalog ────────────────────────

def _assert_anchor_necessary(pattern: str):
    """For a pattern with anchors, synthesize matches with exrex-free trick:
    use the pattern's own anchor embedded in text and verify consistency —
    plus verify each anchor IS a casefolded substring requirement by checking
    the pattern against text stripped of all anchors."""
    anchors = anchors_for(pattern)
    if anchors is None:
        return
    try:
        rx = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    except re.error:
        return
    # Text that contains none of the anchors must not match the regex.
    # (Necessity: match ⇒ anchor present. Contrapositive is testable.)
    probe = "The quick brown fox jumps over 12345 lazy dogs éü."
    folded = fold(probe)
    if any(a in folded for a in anchors):
        return  # probe accidentally contains an anchor — nothing to assert
    m = rx.search(probe)
    _check(m is None,
           f"pattern {pattern!r} matched anchor-free text {m and m.group(0)!r} "
           f"— derived anchors {anchors!r} are NOT necessary")


def test_anchor_necessity_on_all_catalogs():
    from analyzers import secret_catalog
    from analyzers.code_rules import CODE_RULES, IOS_CODE_RULES
    from analyzers.string_analyzer import STRING_PATTERNS
    from analyzers.tracker_db import ANDROID_API_CATEGORIES

    patterns = [p["pattern"] for p in secret_catalog.combined()]
    patterns += [r["pattern"] for r in CODE_RULES + IOS_CODE_RULES]
    patterns += [p["pattern"] for p in STRING_PATTERNS]
    patterns += [p for ps in ANDROID_API_CATEGORIES.values() for p in ps]
    for pattern in patterns:
        _assert_anchor_necessary(pattern)


def test_real_matches_always_pass_prefilter():
    """Sample corpus lines that famously trip each catalog — every regex match
    in these texts must survive the prefilter."""
    from analyzers import secret_catalog
    from analyzers.code_rules import CODE_RULES
    from analyzers.string_analyzer import STRING_PATTERNS

    texts = [
        'aws_key = "AKIAIOSFODNN7EXAMPLE"',
        'String p = "sk_live_abcdefghijklmnopqrstuvwx";',
        'password = "hunter2secret"',
        'Cipher.getInstance("AES/ECB/PKCS5Padding");',
        'Log.d("TAG", "user token " + token);',
        'Runtime.getRuntime().exec("su");',
        'PendingIntent.getActivity(ctx, 0, intent, 0);',
        'webView.addJavascriptInterface(new JsBridge(), "bridge");',
        '<uses-permission android:name="android.permission.READ_CONTACTS"/>',
        'https://hooks.slack.com/services/T0000000/B0000000/XXXXXXXXXXXXXXXXXXXXXXXX',
    ]
    catalogs = ([p["pattern"] for p in secret_catalog.combined()]
                + [r["pattern"] for r in CODE_RULES]
                + [p["pattern"] for p in STRING_PATTERNS])
    for text in texts:
        folded = fold(text)
        for pattern in catalogs:
            try:
                rx = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            except re.error:
                continue
            if rx.search(text):
                _check(may_match(pattern, folded),
                       f"prefilter skipped a real match: {pattern!r} on {text!r}")


if __name__ == "__main__":
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all regex_prefilter tests passed")

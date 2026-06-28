"""
Regression corpus (Beetle 2.0, Phase 1.98).

The benchmark apps Beetle must keep detecting well. We cannot ship the binaries, so
each entry declares the detection SIGNATURES the app is known to exercise (its
"ground truth" coverage). The regression test asserts that the Detection Coverage
Registry still covers every expected signature — so a future change can never
silently drop a capability the corpus depends on.

Add an app by appending a ``CorpusApp``; add an expected detection by adding its
signature (see ``benchmark.signature``). Pure data + a checker — no I/O.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import benchmark
from . import registry


@dataclass
class CorpusApp:
    name: str
    platform: str                       # "android" | "ios"
    framework: str = "native"           # native | flutter | react-native | cordova
    source: str = ""
    expected: set = field(default_factory=set)   # canonical signatures it should exercise
    notes: str = ""


REGRESSION_CORPUS: list[CorpusApp] = [
    CorpusApp(
        name="InsecureShop", platform="android", source="https://github.com/hax0rgb/InsecureShop",
        expected={"weak_cipher_ecb", "weak_hash_md5", "exported", "deeplinks",
                  "cleartext", "allow_backup", "private_key"},
        notes="OWASP-style intentionally vulnerable Android app; the MobSF comparison source."),
    CorpusApp(
        name="DVIA-v2", platform="ios", source="https://github.com/prateek147/DVIA-v2",
        expected={"weak_hash_md5", "private_key", "jwt"},
        notes="Damn Vulnerable iOS App."),
    CorpusApp(
        name="OWASP MSTG Hacking Playground", platform="android",
        source="https://github.com/OWASP/MSTG-Hacking-Playground",
        expected={"weak_cipher_ecb", "weak_hash_sha1", "exported", "cleartext"},
        notes="OWASP MSTG reference app."),
    CorpusApp(
        name="GoatDroid", platform="android", source="https://github.com/jackMannino/OWASP-GoatDroid-Project",
        expected={"allow_backup", "exported", "weak_hash_md5"},
        notes="Legacy OWASP intentionally-vulnerable Android app."),
    CorpusApp(
        name="Flutter sample", platform="android", framework="flutter",
        expected={"aws_access_key", "firebase"},
        notes="Flutter apps embed secrets in libapp.so / assets; coverage must reach them."),
    CorpusApp(
        name="React Native sample", platform="android", framework="react-native",
        expected={"google_api_key", "firebase", "aws_cognito"},
        notes="RN apps ship secrets in the JS bundle; AWS Cognito Identity Pool is common."),
    CorpusApp(
        name="Sample iOS app", platform="ios",
        expected={"ats", "private_key", "google_api_key"},
        notes="Generic iOS coverage sanity (ATS / plist / secrets)."),
]


def _registered_signatures() -> set[str]:
    """Every detection signature Beetle's full surface currently provides:
    the coverage registry + the unified secret catalog (all provenances) + the
    SAST crypto/code rules. This is the coverage source of truth for regression."""
    sigs: set[str] = set()
    for e in registry.all_entries():
        sigs.add(benchmark.signature(e.name))
    try:
        from .. import secret_catalog
        for p in secret_catalog.patterns():
            sigs.add(benchmark.signature(p.get("name", "")))
    except Exception:
        pass
    try:
        from ..code_rules import CODE_RULES, IOS_CODE_RULES
        for r in list(CODE_RULES) + list(IOS_CODE_RULES):
            sigs.add(benchmark.signature(r.get("title") or r.get("id") or ""))
    except Exception:
        pass
    return sigs


def missing_for(app: CorpusApp) -> set[str]:
    """Expected signatures NOT currently covered by the registry (a regression)."""
    return {s for s in app.expected if s not in _registered_signatures()}


def coverage_report() -> dict:
    """Per-app coverage status across the corpus."""
    covered = _registered_signatures()
    out = {}
    for app in REGRESSION_CORPUS:
        miss = {s for s in app.expected if s not in covered}
        out[app.name] = {
            "platform": app.platform, "framework": app.framework,
            "expected": sorted(app.expected), "missing": sorted(miss),
            "ok": not miss,
        }
    return out

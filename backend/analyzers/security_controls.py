"""
Security Control Resolution — the single authority on "is this control present?".

Before this module, three subsystems each answered that question independently by
substring-matching a blob of finding titles and descriptions:

  * ``scoring.py``            — awarded a +5 "Certificate pinning detected" bonus
                                whenever the string "certificate pinning" appeared
                                anywhere, so the finding *"No Certificate Pinning
                                Configured"* paid the bonus for its own absence.
                                So did the ``debuggable`` finding's description,
                                which merely mentions *bypassing* pinning.
  * ``masvs_intel.py``        — got it right (negation-window guard) but re-derived
                                the answer from its own corpus.
  * ``attack_chains/engine``  — a third guess, which additionally read
                                ``results["score"]["bonuses"]`` even though chains
                                are built before scoring runs, so that half of its
                                input was always empty.

They could and did contradict each other inside one report. This module resolves
each control ONCE, from evidence, and every consumer reads the answer.

Design
------
**Positive evidence only.** A control is ``present`` because something asserted it
*is* — a structured config signal, a rule that only fires on the control's own
implementation, or a title that asserts presence. A finding asserting the control
is MISSING contributes ``negative`` evidence and can never produce ``present``.

**Evidence sources, in descending order of trust:**

1. *Structured config* — ``network_config.summary`` booleans, manifest attributes.
   Parsed values, not prose. Cannot be wrong about what the app declares.
2. *Rule identity* — an exact ``rule_id`` that only fires on the control's own
   implementation (``obfuscation_detected``) or on its absence (``nsc_no_pinning``).
   Stable across title rewording.
3. *Assertive titles* — a title phrase that asserts presence ("Root Detection
   Present"), guarded by the same negation check masvs_intel already used.
4. *Code corpus* — implementation tokens (``certificatepinner``, ``rootbeer``)
   found in manifest XML, network config, SDK names, behaviour entries, and the
   *code* (snippet / code_context) of INFO-severity or security-control findings.

**Finding descriptions are never evidence.** They are Beetle's own prose and they
name controls constantly — to recommend them ("Use certificate pinning via OkHttp
CertificatePinner"), to warn they can be bypassed ("Any user with ADB access can
… bypass certificate pinning"), or to explain a control that is *absent*. Every
false positive this module exists to kill entered through a description.

States
------
``present`` / ``partial`` / ``absent`` / ``unknown`` for controls whose presence is
the good outcome; ``blocked`` / ``allowed`` / ``unknown`` for ``cleartext``, where
the good outcome is the control *denying* something.

``partial`` means present-but-degraded: positive evidence coexists with negative
evidence (pinned for one domain, unpinned for the rest) or with weakening evidence
(``debug-overrides`` sets ``overridePins="true"``, so pinning is bypassable).

``unknown`` means no evidence either way — distinct from ``absent``, which requires
something to have asserted the control is missing. Neither awards a bonus.

Deterministic: evidence lists are sorted, no randomness, no network, no I/O.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

__all__ = [
    "CONTROLS",
    "resolve",
    "positive_corpus",
    "corpus_asserts",
    "state_of",
    "is_present",
]

# ── States ───────────────────────────────────────────────────────────────────
PRESENT, PARTIAL, ABSENT, UNKNOWN = "present", "partial", "absent", "unknown"
BLOCKED, ALLOWED = "blocked", "allowed"

# ── Evidence polarity ────────────────────────────────────────────────────────
POSITIVE, NEGATIVE, WEAKENING = "positive", "negative", "weakening"

# Negation tokens searched in the window preceding a corpus hit. Lifted verbatim
# from masvs_intel._NEGATION — the one implementation that already got
# "no certificate pinning" right — so its correctness is preserved, not re-guessed.
_NEGATION = ("no ", "not ", "without", "missing", "disabled", "absent", "lack",
             "insecure", "weak", "vulnerab")

# Characters of preceding context scanned for a negation token.
_NEGATION_WINDOW = 24


@dataclass(frozen=True)
class _ControlSpec:
    """How one control is decided. All matching inputs live here, nowhere else."""
    key: str
    # Rule ids that fire ONLY when the control is implemented / missing / weakened.
    positive_rule_ids: frozenset = frozenset()
    negative_rule_ids: frozenset = frozenset()
    weakening_rule_ids: frozenset = frozenset()
    # Title phrases (lowercase) that ASSERT presence / absence. Negative phrases are
    # tested first, so "code obfuscation not detected" can never read as positive.
    positive_titles: tuple = ()
    negative_titles: tuple = ()
    # Implementation tokens matched against the positive corpus (code, not prose).
    code_patterns: tuple = ()
    # State names. `cleartext` inverts: the control's job is to deny, so "present"
    # reads as "blocked" and "absent" as "allowed".
    present_state: str = PRESENT
    absent_state: str = ABSENT
    # When true, ANY negative evidence wins outright instead of yielding `partial`.
    # One domain permitting cleartext means cleartext is allowed, full stop; there
    # is no partially-blocked wire.
    absent_wins: bool = False


_SPECS: tuple = (
    _ControlSpec(
        key="cert_pinning",
        # nsc_no_backup_pin / nsc_expired_pin only exist inside the `has_pinning`
        # branch of the NSC parser — they are proof pinning IS configured, and say
        # nothing about whether it exists.
        positive_rule_ids=frozenset({
            "nsc_pinning_configured", "nsc_no_backup_pin", "nsc_expired_pin",
        }),
        negative_rule_ids=frozenset({"nsc_no_pinning"}),
        # overridePins="true" makes configured pinning bypassable, not absent.
        weakening_rule_ids=frozenset({"nsc_pin_override_debug"}),
        positive_titles=("certificate pinning configured", "certificate pinning detected",
                         "certificate pinning present"),
        # Checked before the positive phrases, so "No Certificate Pinning Detected"
        # resolves to absence rather than matching "certificate pinning detected".
        negative_titles=("no certificate pinning", "certificate pinning not",
                         "missing certificate pinning"),
        # Deliberately excludes the bare phrase "certificate pinning": it appears in
        # remediation prose for half the network rules. Implementation tokens only.
        code_patterns=("certificatepinner", "pin-set", "pinset", "public-key-pins",
                       "trustkit"),
    ),
    _ControlSpec(
        key="cleartext",
        positive_rule_ids=frozenset(),
        negative_rule_ids=frozenset({
            "manifest_cleartext_traffic", "nsc_global_cleartext", "nsc_domain_cleartext",
            "android_clear_text_traffic_permitted", "ios_ats_disabled",
        }),
        positive_titles=("cleartext disabled", "cleartext traffic blocked"),
        negative_titles=("cleartext http traffic permitted", "cleartext http permitted",
                         "permits cleartext", "cleartext permitted",
                         "app transport security disabled"),
        code_patterns=('cleartexttrafficpermitted="false"', 'usescleartexttraffic="false"'),
        present_state=BLOCKED,
        absent_state=ALLOWED,
        absent_wins=True,
    ),
    _ControlSpec(
        key="root_detection",
        positive_rule_ids=frozenset({"android_no_root_detection", "ios_jailbreak_detection"}),
        positive_titles=("root detection present", "jailbreak detection logic",
                         "jailbreak detection present"),
        negative_titles=("no root detection", "root detection not",
                         "missing root detection", "no jailbreak detection"),
        # "tamper" alone matches "tampering risk"; require the control's own name.
        # `android_root_detection_bypass_strings` (Magisk package names) is excluded:
        # its own description concedes it "may indicate root-detection logic or a
        # reference list for bypass" — ambiguous evidence decides nothing.
        code_patterns=("rootbeer", "isdevicerooted", "isrooted", "checkrootmethod",
                       "jailbreak detection", "tamper detection", "anti-tamper"),
    ),
    _ControlSpec(
        key="obfuscation",
        positive_rule_ids=frozenset({"obfuscation_detected"}),
        negative_rule_ids=frozenset({"obfuscation_not_detected", "android_obfuscation_missing"}),
        positive_titles=("code obfuscation detected",),
        negative_titles=("obfuscation not detected", "no code obfuscation",
                         "code obfuscation not"),
        # No corpus patterns: obfuscation is a property of the whole dex, decided by
        # the class-name-ratio detector. Every textual mention of "obfuscation" in
        # this codebase belongs to a finding that says it is MISSING.
        code_patterns=(),
    ),
    _ControlSpec(
        key="frida_detection",
        # `android_frida_gadget` is deliberately NOT positive: a bundled frida-gadget
        # is an instrumented build — the opposite of a defence against instrumentation.
        positive_rule_ids=frozenset({"android_frida_detection"}),
        positive_titles=("frida / dynamic analysis detection", "frida detection present"),
        negative_titles=("no frida detection", "frida detection not"),
        code_patterns=(),
    ),
    _ControlSpec(
        key="safetynet_play_integrity",
        positive_titles=("play integrity present", "safetynet attestation present"),
        negative_titles=("no play integrity", "no safetynet", "missing attestation"),
        code_patterns=("playintegrity", "play integrity", "integritymanager", "safetynet",
                       "dcdevice"),
    ),
    _ControlSpec(
        key="flag_secure",
        positive_rule_ids=frozenset({"android_no_screenshot_prevention"}),
        positive_titles=("screenshot protection present",),
        negative_titles=("no screenshot protection", "screenshot protection not",
                         "missing flag_secure"),
        code_patterns=("flag_secure",),
    ),
    _ControlSpec(
        key="sqlcipher",
        positive_titles=("sqlcipher encryption present",),
        negative_titles=("no sqlcipher",),
        code_patterns=("sqlcipher", "net.sqlcipher"),
    ),
)

CONTROLS: tuple = tuple(spec.key for spec in _SPECS)
_BY_KEY: dict = {spec.key: spec for spec in _SPECS}


# ════════════════════════════════════════════════════════════════════════════
# Corpus
# ════════════════════════════════════════════════════════════════════════════
def positive_corpus(results: dict) -> str:
    """Lowercase corpus of things that testify a control IS implemented.

    Manifest XML, parsed network config, declared permissions, detected SDKs,
    behaviour entries, and — for INFO-severity or explicitly security-control
    findings — the title and the *code* they matched.

    Finding descriptions are excluded. They are Beetle's own remediation prose and
    they name controls whether the control is present, absent, or merely bypassable,
    which is what made every naive matcher wrong.
    """
    parts: list = []

    mx = results.get("manifest_xml")
    if isinstance(mx, str):
        parts.append(mx)

    nc = results.get("network_config")
    if nc:
        parts.append(json.dumps(nc, default=str, sort_keys=True))

    for b in results.get("behavior_analysis") or []:
        if isinstance(b, dict):
            parts.append(str(b.get("title", "")) + " " + str(b.get("description", "")))

    for s in results.get("sdks") or []:
        if isinstance(s, dict):
            parts.append(str(s.get("name", "")) + " " + str(s.get("package", "")))
        elif isinstance(s, str):
            parts.append(s)

    for p in results.get("manifest_permissions") or results.get("permissions") or []:
        if isinstance(p, str):
            parts.append(p)
        elif isinstance(p, dict):
            parts.append(str(p.get("name", "")))

    for f in results.get("findings") or []:
        if not isinstance(f, dict) or f.get("is_attack_chain"):
            continue
        if f.get("security_control") or str(f.get("severity")) == "info":
            parts.append(" ".join(str(f.get(k, "")) for k in ("title", "snippet", "code_context")))

    return " ".join(parts).lower()


def corpus_asserts(corpus: str, pattern: str) -> bool:
    """True when `pattern` occurs in `corpus` without a negation immediately before it.

    This is masvs_intel's original guard, extracted so there is one implementation.
    Every occurrence is checked, not just the first: "no certificate pinning" earlier
    in the corpus must not veto a genuine `certificatepinner` later in it.
    """
    if not pattern:
        return False
    start = 0
    while True:
        idx = corpus.find(pattern, start)
        if idx == -1:
            return False
        window = corpus[max(0, idx - _NEGATION_WINDOW):idx]
        if not any(neg in window for neg in _NEGATION):
            return True
        start = idx + 1


# ════════════════════════════════════════════════════════════════════════════
# Evidence collection
# ════════════════════════════════════════════════════════════════════════════
def _ev(source: str, polarity: str, signal: str, detail: str) -> dict:
    return {"source": source, "polarity": polarity, "signal": signal, "detail": detail}


def _sort_key(e: dict) -> tuple:
    return (e["polarity"], e["source"], e["signal"], e["detail"])


def _finding_evidence(spec: _ControlSpec, findings: list) -> list:
    """Evidence from findings: rule identity first, then assertive titles."""
    out: list = []
    for f in findings:
        rule_id = str(f.get("rule_id") or f.get("id") or "")
        title = str(f.get("title") or "").lower()

        if rule_id in spec.negative_rule_ids:
            out.append(_ev("finding", NEGATIVE, rule_id, f"finding asserts the control is missing: {f.get('title')}"))
            continue
        if rule_id in spec.weakening_rule_ids:
            out.append(_ev("finding", WEAKENING, rule_id, f"finding weakens the control: {f.get('title')}"))
            continue
        if rule_id in spec.positive_rule_ids:
            out.append(_ev("finding", POSITIVE, rule_id, f"rule fires only when the control is implemented: {f.get('title')}"))
            continue

        # Negative phrasing is tested before positive, and wins: a title that says
        # the control is missing can never contribute presence.
        neg = next((p for p in spec.negative_titles if p in title), None)
        if neg:
            out.append(_ev("finding", NEGATIVE, f"title:{neg}", f"title asserts absence: {f.get('title')}"))
            continue
        pos = next((p for p in spec.positive_titles if p in title and corpus_asserts(title, p)), None)
        if pos:
            out.append(_ev("finding", POSITIVE, f"title:{pos}", f"title asserts presence: {f.get('title')}"))
    return out


_CLEARTEXT_TRUE_RE = re.compile(r'usescleartexttraffic\s*=\s*"(true|1)"')
_CLEARTEXT_FALSE_RE = re.compile(r'usescleartexttraffic\s*=\s*"(false|0)"')


def _structured_evidence(spec: _ControlSpec, results: dict) -> list:
    """Evidence from parsed configuration — the highest-trust source."""
    out: list = []
    nc = results.get("network_config") or {}
    summary = nc.get("summary") or {} if isinstance(nc, dict) else {}
    manifest = str(results.get("manifest_xml") or "").lower()

    if spec.key == "cert_pinning" and nc.get("present"):
        if summary.get("has_pinning"):
            n = summary.get("pinned_domain_count", 0)
            out.append(_ev("network_security_config", POSITIVE, "summary.has_pinning",
                           f"network_security_config.xml declares a pin-set for {n} domain(s)"))
        else:
            out.append(_ev("network_security_config", NEGATIVE, "summary.has_pinning",
                           "network_security_config.xml declares no pin-set"))
        if summary.get("pin_override"):
            out.append(_ev("network_security_config", WEAKENING, "summary.pin_override",
                           'debug-overrides sets overridePins="true" — configured pinning is bypassable'))

    if spec.key == "cleartext":
        if nc.get("present"):
            if summary.get("cleartext_global"):
                out.append(_ev("network_security_config", NEGATIVE, "summary.cleartext_global",
                               'base-config sets cleartextTrafficPermitted="true"'))
            elif nc.get("base_config"):
                out.append(_ev("network_security_config", POSITIVE, "summary.cleartext_global",
                               'base-config sets cleartextTrafficPermitted="false"'))
            for domains in summary.get("cleartext_domains") or []:
                out.append(_ev("network_security_config", NEGATIVE, "summary.cleartext_domains",
                               f"domain-config permits cleartext for: {', '.join(domains)}"))
        if _CLEARTEXT_TRUE_RE.search(manifest):
            out.append(_ev("manifest", NEGATIVE, "android:usesCleartextTraffic",
                           'manifest sets android:usesCleartextTraffic="true"'))
        elif _CLEARTEXT_FALSE_RE.search(manifest):
            out.append(_ev("manifest", POSITIVE, "android:usesCleartextTraffic",
                           'manifest sets android:usesCleartextTraffic="false"'))
    return out


def _corpus_evidence(spec: _ControlSpec, corpus: str) -> list:
    out: list = []
    for pat in spec.code_patterns:
        if corpus_asserts(corpus, pat):
            out.append(_ev("code", POSITIVE, pat, f"implementation token '{pat}' found in app code/config"))
    return out


# ════════════════════════════════════════════════════════════════════════════
# Resolution
# ════════════════════════════════════════════════════════════════════════════
def _decide(spec: _ControlSpec, evidence: list) -> str:
    pos = any(e["polarity"] == POSITIVE for e in evidence)
    neg = any(e["polarity"] == NEGATIVE for e in evidence)
    weak = any(e["polarity"] == WEAKENING for e in evidence)

    if spec.absent_wins:
        if neg:
            return spec.absent_state
        return spec.present_state if pos else UNKNOWN

    if pos and not neg and not weak:
        return spec.present_state
    if pos:
        return PARTIAL
    if neg:
        return spec.absent_state
    return UNKNOWN


def resolve(results: dict) -> dict:
    """Resolve every security control once, from evidence. Deterministic and pure.

    Returns ``{control_key: {"state": str, "evidence": [...]}}``. Does not mutate
    `results`; the caller stores it under ``results["security_controls"]``.
    """
    findings = [f for f in (results.get("findings") or [])
                if isinstance(f, dict) and not f.get("is_attack_chain")]
    corpus = positive_corpus(results)

    out: dict = {}
    for spec in _SPECS:
        evidence = (_structured_evidence(spec, results)
                    + _finding_evidence(spec, findings)
                    + _corpus_evidence(spec, corpus))
        # Deduplicate identical evidence (a rule firing on several files) and order
        # stably so the report and any diff of it are reproducible.
        seen: set = set()
        unique: list = []
        for e in sorted(evidence, key=_sort_key):
            k = _sort_key(e)
            if k in seen:
                continue
            seen.add(k)
            unique.append(e)
        out[spec.key] = {"state": _decide(spec, unique), "evidence": unique}
    return out


# ════════════════════════════════════════════════════════════════════════════
# Consumer accessors — the only sanctioned way to ask "is this control present?"
# ════════════════════════════════════════════════════════════════════════════
def state_of(results: dict, control: str) -> str:
    """State of `control`, resolving on demand if the pipeline has not stored it."""
    if control not in _BY_KEY:
        raise KeyError(f"unknown security control: {control!r}")
    controls = results.get("security_controls")
    if not isinstance(controls, dict) or control not in controls:
        controls = resolve(results)
    return controls[control].get("state", UNKNOWN)


def is_present(results: dict, control: str) -> bool:
    """True only for a fully-present control.

    `partial` is excluded on purpose. A partial control is present but degraded —
    pinning that `debug-overrides` can turn off, or pinning that covers one domain
    while the rest go unpinned. It has not earned a "good practice" bonus, and it
    cannot be relied on to block an attack chain.
    """
    return state_of(results, control) in (PRESENT, BLOCKED)

"""
Confidence Engine — configuration (Beetle 2.0, Phase 1.3).

THE single tuning file. Every weight, base score and threshold the Confidence
Engine uses lives here with a documented rationale. Future tuning = edit this
file only; `engine.py` contains logic, never constants.

Design principles
-----------------
* Deterministic: pure data, no randomness, no environment lookups.
* Explainable: every number has a comment saying *why* it is what it is.
* Independent dimensions: detection / ownership / evidence / context /
  exploitability are scored separately and only combined at the very end, so the
  breakdown always survives.
"""
from __future__ import annotations

# Bump when the model changes so stored scores are traceable to a config.
CONFIDENCE_VERSION = "1.0.0"


# ════════════════════════════════════════════════════════════════════════════
# DETECTION CONFIDENCE — "did the detector identify a real issue?"
# ════════════════════════════════════════════════════════════════════════════
# Confidence is a property of the *detector class*, not the individual finding:
# a structural parser (manifest/cert) is near-deterministic, a regex over
# decompiled code is inherently more false-positive-prone. Values are precision
# priors, not guesses — they reflect how often each technique is right.
DETECTOR_BASE_CONFIDENCE = {
    "structural_parser": 95,   # manifest / plist / certificate parser — structured input, ~no ambiguity
    "binary_analyzer":   90,   # ELF/Mach-O hardening facts — read straight from the binary
    "dependency_scanner": 90,  # version string → known CVE (OSV/KEV) — deterministic mapping
    "semgrep":           88,   # AST / semantic rule — far fewer FPs than raw regex
    "dataflow":          85,   # taint source→sink — real data flow, some path imprecision
    "secret_detector":   80,   # key pattern + entropy — specific but context-sensitive
    "regex_sast":        72,   # regex over decompiled code — useful but FP-prone
    "jni_native":        70,   # heuristic native/JNI inspection
    "heuristic":         60,   # string / keyword heuristics
    "default":           65,   # unknown detector — neutral-ish prior
}

# Raw `evidence_type` / `source_module` / category tokens → detector class.
# Checked in this priority: evidence_type, then source_module, then category.
DETECTOR_CLASS_BY_TOKEN = {
    # evidence_type
    "semgrep": "semgrep",
    "manifest": "structural_parser",
    "taint_flow": "dataflow",
    "regex_match": "regex_sast",
    # source_module
    "sast": "regex_sast",
    "custom_rule": "regex_sast",
    "taint": "dataflow",
    "secret": "secret_detector",
    "evidence": "secret_detector",
    "jwt_scanner": "secret_detector",
    "cert": "structural_parser",
    "certificate": "structural_parser",
    "elf": "binary_analyzer",
    "lief": "binary_analyzer",
    "macho": "binary_analyzer",
    "binary": "binary_analyzer",
    "native": "binary_analyzer",
    "cve-map": "dependency_scanner",
    "cve": "dependency_scanner",
    "osv": "dependency_scanner",
    "packages": "dependency_scanner",
    "jni": "jni_native",
    "string": "heuristic",
    "keyword": "heuristic",
    "apkid": "heuristic",
}

# Category → detector class fallback when source/evidence_type are uninformative.
DETECTOR_CLASS_BY_CATEGORY = {
    "certificate": "structural_parser",
    "binary hardening": "binary_analyzer",
    "vulnerable component": "dependency_scanner",
    "supply chain / dependencies": "dependency_scanner",
    "taint analysis": "dataflow",
    "secrets": "secret_detector",
    "network security": "structural_parser",
    "permissions": "structural_parser",
    "configuration": "structural_parser",
}

# A live-validated secret is as certain as detection gets.
DETECTION_VALIDATED = 100


# ════════════════════════════════════════════════════════════════════════════
# OWNERSHIP CONFIDENCE — read directly from the Ownership Engine
# ════════════════════════════════════════════════════════════════════════════
# We do NOT recompute ownership. We read `owner_confidence`. If the Ownership
# Engine never ran (0), use a neutral prior so overall is not unfairly dragged.
OWNERSHIP_NEUTRAL_DEFAULT = 50


# ════════════════════════════════════════════════════════════════════════════
# EVIDENCE CONFIDENCE — "how verifiable is this?"  (additive, capped at 100)
# ════════════════════════════════════════════════════════════════════════════
# A finding always has *some* basis (it was emitted), hence a base. Each concrete,
# analyst-verifiable artifact adds points. Strong multi-step evidence (a taint
# chain) and corroboration across files (cross-references) are weighted highest
# because they are the hardest to fake.
EVIDENCE_BASE = 20
EVIDENCE_POINTS = {
    "line":              15,   # exact line number → reviewer can jump to it
    "snippet":           20,   # the actual code/evidence text
    "method":            10,   # owning method identified
    "class":              8,   # owning class identified
    "file_path":          7,   # a resolvable file
    "source_resolved":   10,   # decompiler succeeded & the path resolves to source
    "manifest":          12,   # backed by a verified manifest entry
    "call_chain":        18,   # taint/call chain — multi-step proof
    "multiple_evidence": 15,   # >1 evidence locations (cross-references corroborate)
    "binary_metadata":   10,   # symbol/section evidence for native findings
}
# A finding that claimed a location which could not be resolved is unreliable.
EVIDENCE_UNRESOLVED_CAP = 30


# ════════════════════════════════════════════════════════════════════════════
# CONTEXT CONFIDENCE — "is this in meaningful application context?"
# ════════════════════════════════════════════════════════════════════════════
# Driven by ownership: a bug in first-party app code matters operationally far
# more than the identical pattern inside a framework or generated file. These are
# *context* scores, not severity — a framework finding can still be real.
CONTEXT_BY_OWNER = {
    "Application":        95,
    "Unknown":           55,   # could be obfuscated app code — neither rewarded nor punished
    "OpenSourceLibrary": 45,
    "VendorSDK":         45,
    "ThirdPartySDK":     45,
    "GoogleSDK":         40,
    "GeneratedCode":     30,   # machine-generated — rarely an actionable app bug
    "AndroidFramework":  25,   # platform code shipped by the OS/runtime
    "AppleFramework":    25,
}
CONTEXT_DEFAULT = 50
# App configuration (manifest / NSC / permissions) is genuinely the app's own
# surface even when no owning package is derivable — floor its context high.
CONTEXT_APP_CONFIG_FLOOR = 80
# Resource files are app-owned but rarely executable logic — medium.
CONTEXT_RESOURCE = 50
# Native libraries are "it depends" — stay neutral rather than guess.
CONTEXT_NATIVE_NEUTRAL = 50


# ════════════════════════════════════════════════════════════════════════════
# EXPLOITABILITY CONFIDENCE — conservative likelihood-of-exploitation (NOT severity)
# ════════════════════════════════════════════════════════════════════════════
# Deliberately conservative; future reachability/exploit engines will refine it.
# Starts low and only rises with concrete reachability/attack-surface signals.
EXPLOIT_BASE = 25
EXPLOIT_SIGNALS = {
    "reachable_yes":        25,   # reachability engine proved a path
    "reachable_maybe":      10,
    "exported_component":   20,   # attacker-reachable entry point
    "external_source":      18,   # taint source is externally controllable (intent/user input)
    "dangerous_sink":       15,   # taint sink is an injection/exec/webview primitive
    "dangerous_api":        12,   # category is an inherently dangerous API (WebView/Crypto/Command)
    "validated_secret":     30,   # a live-valid secret is directly abusable
    "secret_in_app":        12,   # an app-owned secret ships in the artifact
    "in_attack_chain":      20,   # already correlated into an attack chain
    "permission_sensitive":  8,
}
# Code that cannot run in practice caps exploitability low regardless of signals.
EXPLOIT_UNREACHABLE_CAP = 25     # reachability == NO
EXPLOIT_GENERATED_CAP = 25       # generated code (e.g. BuildConfig) — see spec example
EXPLOIT_FRAMEWORK_CAP = 30       # platform framework internals


# ════════════════════════════════════════════════════════════════════════════
# OVERALL CONFIDENCE — explainable weighted roll-up
# ════════════════════════════════════════════════════════════════════════════
# Weights sum to 1.0. Rationale: detection (is it real?) and evidence (can we
# prove it?) dominate confidence-in-a-finding; ownership and context modulate
# operational relevance; exploitability is the smallest factor here (it is a
# likelihood, refined by later engines) so it never overpowers a well-evidenced,
# app-owned finding.
OVERALL_WEIGHTS = {
    "detection":      0.30,
    "ownership":      0.20,
    "evidence":       0.25,
    "context":        0.15,
    "exploitability": 0.10,
}

# ── Multi-engine agreement (Phase 1.95 — Finding Fusion Engine) ───────────────
# Confidence is no longer pure per-finding heuristics: independent corroboration
# raises detection trust, engine disagreement damps it. Applied as a BOUNDED,
# explainable bonus to the detection dimension (so it flows through the existing
# weights into overall and into the reason). detection_count comes from the Fusion
# Engine; conflicts come from finding["fusion"]["conflicts"].
AGREEMENT_PER_ENGINE = 12        # + detection-confidence per ADDITIONAL engine
AGREEMENT_MAX = 24               # cap on the agreement bonus
AGREEMENT_CONFLICT_DAMP = 0.5    # multiply the bonus when engines conflict on metadata

# Decision-path short-circuits (applied after the weighted score; breakdown is
# always retained). Each sets a floor/cap and a `confidence_stage` label.
OVERALL_VALIDATED_FLOOR = 95     # validation_status == valid
OVERALL_ATTACK_CHAIN_FLOOR = 85  # correlated into an attack chain
OVERALL_UNRESOLVED_CAP = 35      # claimed evidence could not be resolved

# Bands for the human label / dashboard summary (not used in math).
BANDS = (
    (75, "High"),
    (50, "Medium"),
    (25, "Low"),
    (0,  "Informational"),
)


def band_for(score: int) -> str:
    for threshold, label in BANDS:
        if score >= threshold:
            return label
    return "Informational"

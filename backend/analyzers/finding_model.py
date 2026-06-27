"""
Canonical Finding Model — Phase 0 + Phase 1 foundation.

This module is a NON-DESTRUCTIVE normalization layer that runs once after all
analyzers have populated `results["findings"]`. It does two things today:

  Phase 0 — attach a canonical field set to every finding (additive only).
  Phase 1 — classify each finding's ownership (APP / LIBRARY / SYSTEM / UNKNOWN)
            from its source path/package, and emit diagnostic metrics.

It deliberately does NOT implement clustering, semantic dedup, suppression, a
confidence engine, a fixability engine, new scoring, or bucket filtering. Those
fields are seeded with safe defaults so later phases can fill them without
another schema migration.

Backward compatibility contract:
  * Only ADDS keys to each finding dict; never removes or rewrites existing keys.
  * If a canonical key already exists on a finding, it is left untouched.
  * Returns the same list object it was given (mutated in place).
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
from collections import Counter

log = logging.getLogger("cortex.findings")

# ── Ownership vocabulary ─────────────────────────────────────────────────────
APP = "APP"
LIBRARY = "LIBRARY"
SYSTEM = "SYSTEM"
UNKNOWN = "UNKNOWN"

# Canonical field set (Phase 0). Values here are the safe defaults applied when a
# finding does not already carry the key. Future phases overwrite the empty ones.
CANONICAL_DEFAULTS = {
    "canonical_id": "",
    "cluster_id": "",
    "ownership": "",
    "bucket": "",
    "confidence_score": 0,
    "fixability": "",
    "evidence_type": "",
    "owner_package": "",
    "suppressed_reason": "",
}

# Directory segments that prefix a decompiled package path but are not part of
# the package itself. Stripped before deriving the dotted package.
# NOTE: deliberately excludes "java"/"kotlin" — those are real top-level
# package names (java.lang, kotlin.coroutines) and must not be stripped.
_ROOT_DIR_SEGMENTS = {
    "sources", "resources", "smali", "apktool", "jadx",
    "apk_extract", "ipa_extract", "src", "root", "original", "unknown",
}
_SMALI_CLASSES_RE = re.compile(r"^smali_classes\d+$")

# SYSTEM: platform / language runtime packages.
_SYSTEM_PREFIXES = (
    "android.", "java.", "javax.", "kotlin.", "kotlinx.", "dalvik.",
    "sun.", "org.w3c.", "org.xml.", "org.xmlpull.", "junit.",
)

# LIBRARY: well-known third-party SDK / framework packages. Checked BEFORE
# SYSTEM so that e.g. `android.support.*` and `com.google.android.gms.*` are not
# mis-bucketed as SYSTEM. Seeded list — extend freely; this is data, not logic.
_LIBRARY_PREFIXES = (
    "androidx.", "android.support.", "android.arch.",
    "com.google.firebase.", "com.google.android.gms.",
    "com.google.android.play.", "com.google.android.material.",
    "com.google.android.datatransport.", "com.google.mlkit.",
    "com.google.gson.", "com.google.common.", "com.google.protobuf.",
    "com.google.errorprone.", "com.google.auto.",
    "okhttp3.", "okhttp.", "okio.", "retrofit2.", "retrofit.",
    "com.squareup.", "com.bumptech.glide.", "dagger.",
    "io.reactivex.", "rx.", "com.facebook.", "com.android.installreferrer.",
    "org.apache.", "io.grpc.", "com.airbnb.", "com.jakewharton.",
    "io.fabric.", "com.crashlytics.", "io.sentry.", "com.appsflyer.",
    "com.adjust.", "com.amplitude.", "com.mixpanel.", "com.onesignal.",
    "com.applovin.", "com.unity3d.", "com.mopub.", "com.flurry.",
    "org.greenrobot.", "butterknife.", "com.airbnb.lottie.", "coil.",
)

# App-owned non-package artifacts (config / resources / dex root).
_APP_ARTIFACT_HINTS = ("androidmanifest.xml", "/res/", "res/", "classes.dex",
                       "assets/", "/assets/", ".plist", "info.plist")


def _pkg_from_dotted(fqn: str) -> str:
    """Drop the trailing ClassName / inner-class from a dotted FQN -> package."""
    fqn = fqn.split("$", 1)[0]
    segs = [s for s in fqn.split(".") if s]
    if not segs:
        return ""
    # A leading capital on the last segment means it's the class, not a package.
    if segs[-1][:1].isupper():
        segs = segs[:-1]
    return ".".join(segs)


def _package_from_class_ref(s: str) -> str | None:
    """Package from a class *reference* (not a filesystem path), else None.

    Handles the formats analyzers actually emit for non-file evidence:
      "com.app.example.SomeClass"     -> "com.app.example"   (FQN)
      "com.app.example.SomeClass;"    -> "com.app.example"   (taint, trailing ;)
      "Lcom/app/example/SomeClass;"   -> "com.app.example"   (JVM signature)
      "Lcom/app/Foo$Bar;"             -> "com.app"           (inner class)
    Returns None for real paths ("sources/com/app/Foo.java") and for plain
    filenames so the normal path logic still applies.
    """
    if not s:
        return None
    t = s.strip()
    # JVM type signature: Lcom/app/Foo;  (slashes + leading L + trailing ;)
    if t.startswith("L") and "/" in t and t.rstrip().endswith(";"):
        return _pkg_from_dotted(t[1:].rstrip(";").replace("/", "."))
    # Anything with a path separator is a filesystem path — not a class ref.
    if "/" in t or "\\" in t:
        return None
    had_semicolon = t.endswith(";")
    t = t.rstrip(";")
    if "." not in t:
        return None
    segs = [x for x in t.split("$", 1)[0].split(".") if x]
    if len(segs) < 2:
        return None
    # Only treat as a class ref when it really looks like one: an explicit
    # trailing ';' (taint/JVM origin) or a Capitalised final segment (ClassName).
    looks_like_class = had_semicolon or segs[-1][:1].isupper()
    if not looks_like_class:
        return None
    return _pkg_from_dotted(t)


def _path_to_package(path: str) -> str:
    """Best-effort dotted package from a decompiled source path or class ref.

    "sources/com/example/app/Foo.java" -> "com.example.app"
    "smali_classes2/androidx/work/Worker.smali" -> "androidx.work"
    "com.app.example.SomeClass;" -> "com.app.example"   (taint class ref)
    "Lcom/app/example/Foo;" -> "com.app.example"          (JVM signature)
    Returns "" when no package can be derived (resources, manifest, dex root).
    """
    if not path:
        return ""
    # Class references (dotted FQN / JVM signature) come before path parsing —
    # they have no directory layout to walk.
    cref = _package_from_class_ref(path)
    if cref is not None:
        return cref
    norm = path.replace("\\", "/").strip().lstrip("./")
    parts = [p for p in norm.split("/") if p]
    if not parts:
        return ""

    # Drop leading root/container dirs (sources/, smali/, smali_classesN/, ...).
    i = 0
    while i < len(parts) and (parts[i] in _ROOT_DIR_SEGMENTS or _SMALI_CLASSES_RE.match(parts[i])):
        i += 1
    parts = parts[i:]
    if not parts:
        return ""

    # Drop the trailing filename (anything with an extension).
    if "." in parts[-1]:
        parts = parts[:-1]
    if not parts:
        return ""

    # Guard against non-package trees (res/, assets/, lib/, META-INF/).
    if parts[0].lower() in ("res", "assets", "lib", "meta-inf", "build", "fabric"):
        return ""

    return ".".join(parts)


def _looks_obfuscated(package: str) -> bool:
    """Heuristic: ProGuard/R8-style packages collapse to 1-2 char segments."""
    segs = [s for s in package.split(".") if s]
    if len(segs) < 2:
        return len(segs) == 1 and len(segs[0]) <= 2
    short = sum(1 for s in segs if len(s) <= 2)
    return short >= max(1, (len(segs) + 1) // 2)


def classify_ownership(path: str, app_package: str = "") -> tuple[str, str]:
    """Return (ownership, owner_package) for a finding's source path.

    Order: APP -> LIBRARY -> SYSTEM -> UNKNOWN(obfuscated) -> UNKNOWN.
    """
    norm = (path or "").replace("\\", "/").lower()
    package = _path_to_package(path)

    if not package:
        # No derivable package: app-owned config/resource/dex artifacts are APP.
        if any(hint in norm for hint in _APP_ARTIFACT_HINTS):
            return APP, ""
        return UNKNOWN, ""

    p = package.lower()
    ap = (app_package or "").lower().strip()

    if ap and (p == ap or p.startswith(ap + ".")):
        return APP, package
    for prefix in _LIBRARY_PREFIXES:
        if p == prefix.rstrip(".") or p.startswith(prefix):
            return LIBRARY, package
    for prefix in _SYSTEM_PREFIXES:
        if p == prefix.rstrip(".") or p.startswith(prefix):
            return SYSTEM, package
    if _looks_obfuscated(package):
        return UNKNOWN, package
    return UNKNOWN, package


def _finding_path(finding: dict) -> str:
    """Best path for a finding, tolerant of every analyzer's field naming."""
    for key in ("file_path", "file", "path"):
        v = finding.get(key)
        if v:
            return str(v)
    fe = finding.get("file_evidence")
    if isinstance(fe, list) and fe and isinstance(fe[0], dict) and fe[0].get("path"):
        return str(fe[0]["path"])
    files = finding.get("files")
    if isinstance(files, list) and files:
        return str(files[0])
    return ""


def _evidence_type(finding: dict, path: str) -> str:
    """Light, non-engine label of where the evidence came from."""
    if finding.get("call_chain") or (finding.get("source_label") and finding.get("sink")):
        return "taint_flow"
    src = str(finding.get("source") or "").lower()
    if src == "semgrep":
        return "semgrep"
    if "androidmanifest.xml" in path.lower() or "info.plist" in path.lower():
        return "manifest"
    if finding.get("rule_id") or src in ("sast", "custom_rule"):
        return "regex_match"
    return ""


def _canonical_id(finding: dict, owner_package: str) -> str:
    """Deterministic, stable id from rule identity + canonical package.

    Intentionally coarse (no line numbers) so the same logical issue keeps a
    stable id across re-scans; finer identity is a later (clustering) phase.
    """
    rule = finding.get("rule_id") or finding.get("id") or finding.get("title") or "finding"
    basis = f"{rule}|{owner_package}".lower()
    digest = hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:10]
    return f"BEETLE-{digest}"


def canonicalize_findings(findings: list[dict], app_package: str = "") -> list[dict]:
    """Phase 0 + Phase 1. Mutates findings in place; returns the same list."""
    if not findings:
        return findings or []

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        # Phase 0 — seed canonical fields without clobbering existing values.
        for key, default in CANONICAL_DEFAULTS.items():
            finding.setdefault(key, default)

        path = _finding_path(finding)

        # Phase 1 — ownership (only set when not already classified).
        if not finding.get("ownership"):
            ownership, owner_package = classify_ownership(path, app_package)
            finding["ownership"] = ownership
            if owner_package and not finding.get("owner_package"):
                finding["owner_package"] = owner_package

        if not finding.get("evidence_type"):
            finding["evidence_type"] = _evidence_type(finding, path)

        if not finding.get("canonical_id"):
            finding["canonical_id"] = _canonical_id(finding, finding.get("owner_package", ""))

    return findings


def ownership_metrics(findings: list[dict]) -> dict:
    """Counts by ownership bucket. Small dict, safe to persist on results."""
    counts = {"total": 0, APP: 0, LIBRARY: 0, SYSTEM: 0, UNKNOWN: 0}
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        counts["total"] += 1
        own = f.get("ownership") or UNKNOWN
        counts[own] = counts.get(own, 0) + 1
    return counts


def emit_diagnostics(findings: list[dict], *, platform: str = "android", app_package: str = "") -> dict:
    """Log ownership metrics (INFO) and per-finding diagnostics (DEBUG).

    Returns the metrics dict so callers can stash it on results for verification.
    """
    metrics = ownership_metrics(findings)
    log.info(
        "[ownership] %s pkg=%s | Total Findings: %d | APP: %d | LIBRARY: %d | SYSTEM: %d | UNKNOWN: %d",
        platform, app_package or "?", metrics["total"],
        metrics.get(APP, 0), metrics.get(LIBRARY, 0),
        metrics.get(SYSTEM, 0), metrics.get(UNKNOWN, 0),
    )
    if log.isEnabledFor(logging.DEBUG):
        for f in findings or []:
            if not isinstance(f, dict):
                continue
            log.debug(
                "[finding] rule_id=%s ownership=%s package=%s file=%s | %s",
                f.get("rule_id") or f.get("id") or "-",
                f.get("ownership") or UNKNOWN,
                f.get("owner_package") or "-",
                _finding_path(f) or "-",
                f.get("title") or "-",
            )
    return metrics


# ── Phase 2: Finding Inventory & Noise Analysis ──────────────────────────────
def _rule_key(finding: dict) -> str:
    return finding.get("rule_id") or finding.get("id") or finding.get("title") or "unknown"


def build_finding_diagnostics(findings: list[dict]) -> dict:
    """Aggregate findings into a small, internal diagnostics object.

    Pure (no logging, no mutation). Returns:
      {
        "top_rules": [{rule_id,title,severity,ownership,count}, ...],   # noisiest first
        "ownership_breakdown": {total, APP, LIBRARY, SYSTEM, UNKNOWN},
        "severity_breakdown":  {critical, high, medium, low, info},
        "rule_frequency":      {rule_id: count, ...},                   # desc
        "top_by_ownership":    {APP:[...], LIBRARY:[...], SYSTEM:[...], UNKNOWN:[...]},
      }
    Designed to answer: which rules/libraries create the most noise, and which
    findings are candidates for suppression or confidence downgrades.
    """
    groups: dict[str, dict] = {}
    sev_break: Counter = Counter()
    own_break: Counter = Counter()

    for f in findings or []:
        if not isinstance(f, dict):
            continue
        key = _rule_key(f)
        sev = (f.get("severity") or "info")
        own = f.get("ownership") or UNKNOWN
        sev_break[sev] += 1
        own_break[own] += 1
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "rule_id": f.get("rule_id") or f.get("id") or key,
                "title": "",
                "sev": Counter(),
                "own": Counter(),
                "count": 0,
            }
        g["count"] += 1
        g["sev"][sev] += 1
        g["own"][own] += 1
        if not g["title"]:
            g["title"] = f.get("title") or key

    rule_list = [
        {
            "rule_id": g["rule_id"],
            "title": g["title"],
            "severity": g["sev"].most_common(1)[0][0] if g["sev"] else "info",
            "ownership": g["own"].most_common(1)[0][0] if g["own"] else UNKNOWN,
            "count": g["count"],
        }
        for g in groups.values()
    ]
    # Noisiest first; stable tie-break by rule_id.
    rule_list.sort(key=lambda r: (-r["count"], r["rule_id"]))

    top_by_ownership: dict[str, list] = {}
    for own in (APP, LIBRARY, SYSTEM, UNKNOWN):
        top_by_ownership[own] = [
            {"rule_id": r["rule_id"], "title": r["title"], "severity": r["severity"], "count": r["count"]}
            for r in rule_list if r["ownership"] == own
        ][:10]

    return {
        "top_rules": rule_list[:15],
        "ownership_breakdown": {
            "total": sum(own_break.values()),
            APP: own_break.get(APP, 0),
            LIBRARY: own_break.get(LIBRARY, 0),
            SYSTEM: own_break.get(SYSTEM, 0),
            UNKNOWN: own_break.get(UNKNOWN, 0),
        },
        "severity_breakdown": {s: sev_break.get(s, 0) for s in ("critical", "high", "medium", "low", "info")},
        "rule_frequency": {r["rule_id"]: r["count"] for r in rule_list},
        "top_by_ownership": top_by_ownership,
    }


def log_finding_analysis(diagnostics: dict, *, platform: str = "android") -> None:
    """Emit the human-readable FINDING ANALYSIS block (INFO) and, at DEBUG,
    the full per-rule inventory (rule_id / title / severity / ownership / count).
    """
    if not diagnostics:
        return
    ob = diagnostics.get("ownership_breakdown", {})
    top = diagnostics.get("top_rules", [])

    lines = [
        "",
        "===== FINDING ANALYSIS =====",
        "",
        f"Total Findings: {ob.get('total', 0)}",
        "",
        f"APP: {ob.get(APP, 0)}",
        f"LIBRARY: {ob.get(LIBRARY, 0)}",
        f"SYSTEM: {ob.get(SYSTEM, 0)}",
        f"UNKNOWN: {ob.get(UNKNOWN, 0)}",
        "",
        "Top Rules:",
    ]
    for i, r in enumerate(top[:10], 1):
        lines.append(f"{i}. {r['rule_id']} ({r['count']})")
    lines += ["", "============================"]
    log.info("\n".join(lines))

    if log.isEnabledFor(logging.DEBUG):
        log.debug("Per-rule inventory (%s):", platform)
        log.debug("%-36s %-9s %-8s %s", "RULE", "SEVERITY", "OWNER", "COUNT")
        for r in top:
            log.debug("%-36s %-9s %-8s %d", str(r["rule_id"])[:36], r["severity"], r["ownership"], r["count"])


# ═════════════════════════════════════════════════════════════════════════════
# Phase 3 — Signal Quality, Library Filtering, Confidence, Deduplication
# ═════════════════════════════════════════════════════════════════════════════
#
# This phase REDUCES report noise. Unlike Phase 0/1/2 (purely additive), Phase 3
# is allowed to:
#   * downgrade severity of security-control findings (root detection)
#   * mark known false positives as suppressed (moved out of the primary list)
#   * collapse N duplicate taint flows into one grouped finding (evidence kept)
#   * compute a real 0-100 confidence score and a LOW/MEDIUM/HIGH signal quality
#
# It NEVER invents new findings. The default presentation (UI + PDF) shows only
# application-owned, high-confidence, non-suppressed findings; "All Findings"
# restores everything (the data is never destroyed, only partitioned).

# ── Fine-grained ownership labels (Phase 3) ──────────────────────────────────
APPLICATION = "APPLICATION"
THIRD_PARTY_LIBRARY = "THIRD_PARTY_LIBRARY"
ANDROID_FRAMEWORK = "ANDROID_FRAMEWORK"
GOOGLE_SDK = "GOOGLE_SDK"
FIREBASE = "FIREBASE"
JETPACK = "JETPACK"
# UNKNOWN reused from the Phase 1 vocabulary.

# Short badge text per label (for UI/PDF chips).
OWNERSHIP_BADGES = {
    APPLICATION: "APPLICATION",
    THIRD_PARTY_LIBRARY: "THIRD-PARTY",
    ANDROID_FRAMEWORK: "FRAMEWORK",
    GOOGLE_SDK: "GOOGLE SDK",
    FIREBASE: "FIREBASE",
    JETPACK: "JETPACK",
    UNKNOWN: "UNKNOWN",
}

# Ordered prefix → label table. First match wins, so the most specific Google
# sub-SDKs (firebase) come before the generic com.google.* catch-all.
_LABEL_PREFIXES = (
    ("com.google.firebase.", FIREBASE),
    ("com.google.android.gms.tasks.", GOOGLE_SDK),
    ("com.google.android.gms.", GOOGLE_SDK),
    ("com.google.android.play.", GOOGLE_SDK),
    ("com.google.android.material.", GOOGLE_SDK),
    ("com.google.android.datatransport.", GOOGLE_SDK),
    ("com.google.mlkit.", GOOGLE_SDK),
    ("com.google.ads.", GOOGLE_SDK),
    ("com.google.", GOOGLE_SDK),
    ("androidx.", JETPACK),
    ("android.arch.", JETPACK),
    ("android.support.", ANDROID_FRAMEWORK),
    ("android.", ANDROID_FRAMEWORK),
    ("dalvik.", ANDROID_FRAMEWORK),
    ("java.", ANDROID_FRAMEWORK),
    ("javax.", ANDROID_FRAMEWORK),
    ("kotlin.", ANDROID_FRAMEWORK),
    ("kotlinx.", ANDROID_FRAMEWORK),
    ("sun.", ANDROID_FRAMEWORK),
    ("org.w3c.", ANDROID_FRAMEWORK),
    ("org.xml.", ANDROID_FRAMEWORK),
    ("org.xmlpull.", ANDROID_FRAMEWORK),
    ("junit.", THIRD_PARTY_LIBRARY),
    # iOS / Apple platform frameworks.
    ("platform.uikit.", ANDROID_FRAMEWORK),
    ("platform.foundation.", ANDROID_FRAMEWORK),
)


def classify_ownership_label(path: str, app_package: str = "") -> str:
    """Fine-grained ownership label for Phase 3 filtering/badges.

    Returns one of APPLICATION / FIREBASE / GOOGLE_SDK / JETPACK /
    ANDROID_FRAMEWORK / THIRD_PARTY_LIBRARY / UNKNOWN. Built on top of the
    Phase 1 coarse classifier so the two never disagree about app ownership.
    """
    coarse, owner_package = classify_ownership(path, app_package)
    if coarse == APP:
        return APPLICATION
    package = (owner_package or _path_to_package(path)).lower()
    if not package:
        # No package: only app-owned artifacts reach here as APP; everything
        # else is genuinely unknown.
        return APPLICATION if coarse == APP else UNKNOWN

    ap = (app_package or "").lower().strip()
    if ap and (package == ap or package.startswith(ap + ".")):
        return APPLICATION

    for prefix, label in _LABEL_PREFIXES:
        if package == prefix.rstrip(".") or package.startswith(prefix):
            return label

    if coarse == LIBRARY:
        return THIRD_PARTY_LIBRARY
    if coarse == SYSTEM:
        return ANDROID_FRAMEWORK
    return UNKNOWN


# Findings that are inherently app-owned even with no file path: they come from
# the app's OWN manifest / components / config, not from a dependency.
_APP_SCOPED_CATEGORIES = {
    "network security", "components", "component", "deeplinks", "deeplink",
    "backup", "manifest", "configuration", "permissions", "attack surface",
    "exported component", "security controls", "data storage", "platform",
    "behavior analysis", "binary hardening", "certificate", "attack chain",
}
# Dependency / supply-chain findings describe libraries, never app code.
_DEP_SOURCES = {"CVE-MAP", "OSV", "CVE", "OSV-SCANNER"}
_DEP_CATEGORIES = {
    "supply chain", "vulnerable dependency", "vulnerable dependencies",
    "dependencies", "dependency", "components (dependency)", "cve",
}


def _is_dependency_finding(finding: dict) -> bool:
    if str(finding.get("source") or "").upper() in _DEP_SOURCES:
        return True
    return str(finding.get("category") or "").lower() in _DEP_CATEGORIES


def resolve_finding_ownership(finding: dict, app_package: str = "") -> tuple[str, str, str]:
    """Authoritative ownership for a finding: (coarse, label, owner_package).

    Combines path/class-ref parsing with finding-level signals so that:
      * dotted / JVM class refs resolve to their real package (P1)
      * manifest/component/app-config findings with NO path become APPLICATION
        (P1) — unless they are dependency/CVE findings (those stay UNKNOWN).
    """
    # Phase 6 Task 2: synthesized attack-chain findings are application-level by
    # construction — never inherit a member's library/framework ownership.
    if finding.get("is_attack_chain"):
        return APP, APPLICATION, finding.get("owner_package", "")

    # Phase B/E: a manifest-declared exported component is the app's exposure
    # even when its implementing class lives in a library package. View Code may
    # open that library class, but ownership stays APPLICATION (not hidden).
    if finding.get("app_owned_exposure"):
        return APP, APPLICATION, finding.get("owner_package", "")

    path = _finding_path(finding)
    label = classify_ownership_label(path, app_package)
    coarse, owner_pkg = classify_ownership(path, app_package)

    if label != UNKNOWN:
        return coarse, label, owner_pkg

    # Path gave us nothing useful. Decide from the finding's own nature.
    if _is_dependency_finding(finding):
        return UNKNOWN, UNKNOWN, owner_pkg

    has_path = bool(path)
    app_scoped = (
        finding.get("evidence_type") == "manifest"
        or str(finding.get("category") or "").lower() in _APP_SCOPED_CATEGORIES
    )
    # No resolvable path AND app-scoped (manifest/component/config) -> APPLICATION.
    if not has_path and app_scoped:
        return APP, APPLICATION, owner_pkg
    # A manifest/config finding whose only path is an app artifact (res/manifest).
    if app_scoped and coarse == APP:
        return APP, APPLICATION, owner_pkg
    return coarse, label, owner_pkg


def is_application_code(finding) -> bool:
    """True when a finding belongs to first-party application code.

    Accepts a finding dict (preferred) or a raw label string. Library, Google
    SDK, Firebase, Jetpack and platform-framework code are NEVER application
    code — these are the packages the brief says must never be treated as such.
    """
    if isinstance(finding, str):
        return finding == APPLICATION
    label = finding.get("ownership_label")
    if not label:
        return finding.get("ownership") == APP
    return label == APPLICATION


# ── Evidence text extraction ─────────────────────────────────────────────────
_SNIPPET_MARKER_RE = re.compile(r"^[>\s]*\d+\s*\|\s?(.*)$")


def _finding_text(finding: dict) -> str:
    """Concatenate every code-ish field on a finding into one searchable blob."""
    parts = [
        finding.get("snippet"), finding.get("code_context"),
        finding.get("evidence") if isinstance(finding.get("evidence"), str) else None,
        finding.get("value"), finding.get("match"), finding.get("matched_string"),
    ]
    for e in finding.get("file_evidence") or []:
        if isinstance(e, dict):
            parts.append(e.get("snippet"))
    return "\n".join(str(p) for p in parts if p)


def _code_lines(text: str) -> list[str]:
    """Strip snippet gutter markers ('> 12 | code') → bare code lines."""
    out = []
    for ln in text.splitlines():
        if not ln.strip():
            continue
        m = _SNIPPET_MARKER_RE.match(ln)
        out.append((m.group(1) if m else ln).strip())
    return [ln for ln in out if ln]


_IMPORT_RE = re.compile(r"^\s*(?:import|#import|@import|using)\b")


def _is_import_only(text: str) -> bool:
    """True when every non-blank code line is an import/using directive.

    This is the core "informational evidence only" signal: an
    `import dalvik.system.PathClassLoader` with no instantiation nearby.
    """
    lines = _code_lines(text)
    if not lines:
        return False
    return all(_IMPORT_RE.match(ln) for ln in lines)


# Rule families where confidence hinges on real usage vs. a bare reference.
# Each entry: rule_id -> tuple of regexes that prove ACTUAL usage/instantiation.
_USAGE_PROOF = {
    "android_dex_class_loader": (
        re.compile(r"new\s+\w*(?:DexClassLoader|PathClassLoader|InMemoryDexClassLoader|BaseDexClassLoader)", re.I),
        re.compile(r"\.loadClass\s*\(", re.I),
        re.compile(r"\.loadDex\s*\(", re.I),
    ),
    "android_reflection": (
        re.compile(r"\.invoke\s*\(", re.I),
        re.compile(r"\.getDeclaredMethod\s*\(", re.I),
        re.compile(r"\.getMethod\s*\(", re.I),
        re.compile(r"\.getDeclaredField\s*\(", re.I),
        re.compile(r"\.newInstance\s*\(", re.I),
    ),
    "android_runtime_exec": (
        re.compile(r"\.exec\s*\(", re.I),
    ),
}


def _coerce_int(value, default: int) -> int:
    try:
        return int(round(float(value)))
    except (TypeError, ValueError):
        return default


_SEVERITY_CONFIDENCE_FLOOR = {
    "critical": 80, "high": 75, "medium": 55, "low": 40, "info": 30,
}


def compute_confidence(finding: dict, text: str | None = None) -> int:
    """Return a 0-100 confidence that the finding is a real, actionable issue.

    Heuristics (cheap, deterministic, no I/O):
      * import / reference only          -> 10   (informational evidence)
      * proven usage for usage-gated rule-> 95
      * validated secrets / manifest     -> high
      * otherwise fall back to the analyzer-supplied confidence, floored by
        severity so nothing real collapses below its severity band.
    """
    if text is None:
        text = _finding_text(finding)
    # Phase 6: correlated attack chains are high-confidence by construction.
    if finding.get("is_attack_chain"):
        return 90
    # Phase 5.3: a finding that claimed a source location which could not be
    # resolved is unreliable — cap it in the informational band.
    if finding.get("unresolved_evidence"):
        return 30
    rule_id = finding.get("rule_id") or finding.get("id") or ""
    sev = normalize_severity_label(finding.get("severity"))

    # Validated live secrets are as confident as it gets.
    if finding.get("validated") is True or finding.get("validation_status") == "valid":
        return 95

    proofs = _USAGE_PROOF.get(rule_id)
    if proofs:
        if any(p.search(text) for p in proofs):
            return 95
        # Usage-gated rule with no proof of use → import/reference only.
        return 10

    # Generic import-only suppression of confidence for any rule.
    if text and _is_import_only(text):
        return 10

    # Taint flows: the analyzer's own confidence is already meaningful.
    if finding.get("taint_flow") or finding.get("call_chain"):
        return max(_coerce_int(finding.get("confidence"), 70), 60)

    floor = _SEVERITY_CONFIDENCE_FLOOR.get(sev, 40)
    base = _coerce_int(finding.get("confidence"), floor)
    return max(min(base, 100), floor if base else floor)


def normalize_severity_label(sev) -> str:
    """Severity normalizer — delegates to the single authority (Phase 1.15).

    `analyzers.common.normalize_severity` is the one authoritative severity
    normalizer for the whole backend (it is also alias-tolerant: ``warn`` →
    ``medium`` etc.). For the canonical severities every producer actually emits
    (critical/high/medium/low/info) this returns exactly what the previous local
    implementation did, so behavior is unchanged; the local table below is only a
    resilience fallback for the (theoretical) case where ``common`` cannot be
    imported, keeping this module importable in isolation.
    """
    try:
        from .common import normalize_severity as _common_norm
        return _common_norm(sev)
    except Exception:
        if sev is None:
            return "info"
        s = str(sev).strip().lower()
        return s if s in ("critical", "high", "medium", "low", "info") else "info"


def confidence_band(score: int) -> str:
    """0-39 informational · 40-69 suspicious · 70-100 high."""
    if score >= 70:
        return "high"
    if score >= 40:
        return "suspicious"
    return "informational"


# ── Known false-positive suppression ─────────────────────────────────────────
_NAMESPACE_NOISE = (
    "schemas.android.com", "://schemas.android.com",
    "www.w3.org", "://www.w3.org", "xmlns",
    "schemas.microsoft.com", "ns.adobe.com",
)
_CRYPTO_CONTEXT_HINTS = (
    "password", "passwd", "secret", "token", "signature", "hmac",
    "digest", "checksum", "messagedigest", "encrypt", "decrypt", "cipher",
)


def _suppression_reason(finding: dict, text: str, confidence: int) -> str:
    """Return a non-empty reason string when a finding is a known FP, else ''."""
    rule_id = finding.get("rule_id") or finding.get("id") or ""
    title = str(finding.get("title") or "").lower()
    blob = f"{text}\n{finding.get('value', '')}\n{finding.get('url', '')}".lower()

    # 0. Phase 6 Task 1: taint flows inside framework / library / SDK code are
    # almost never application vulnerabilities. Keep only application-owned flows
    # unless they participate in a correlated application attack chain.
    if _is_taint(finding) and not is_application_code(finding) and not finding.get("in_attack_chain"):
        return "framework_library_taint"

    # 1. android-namespace / xmlns / w3.org URLs are never real findings.
    if any(tok in blob for tok in _NAMESPACE_NOISE) and (
        "url" in title or "domain" in title or "endpoint" in title
        or finding.get("category") in ("Network", "Domains", "URLs")
        or blob.strip().startswith("http")
    ):
        return "android_namespace_url"

    # 2. obj.hashCode()/super.hashCode() reported as a crypto weakness.
    if rule_id == "android_java_hashcode":
        if not any(h in blob for h in _CRYPTO_CONTEXT_HINTS):
            return "hashcode_not_crypto"

    # 3. Dynamic code-loading flagged on an import / reference with no usage.
    if rule_id == "android_dex_class_loader" and confidence <= 10:
        return "import_only_no_instantiation"

    return ""


# ── Root-detection reclassification ──────────────────────────────────────────
_ROOT_TOKENS = (
    "which su", "/system/bin/su", "/system/xbin/su", "/sbin/su", "su -c",
    "/system/xbin/which", "/system/bin/which",
    "busybox", "magisk", "supersu", "superuser.apk", "superuser",
    "test-keys", "rootbeer", "eu.chainfire", "com.noshufou.android.su",
    "com.thirdparty.superuser", "com.koushikdutta.superuser",
    "com.topjohnwu.magisk", "/system/app/superuser", "isrooted", "is_rooted",
    "checkroot", "detectroot", "/su/bin", "magiskhide", "daemonsu",
)

# A quoted/bare `su` argument, used alongside a probe verb/path, is a root check
# even when the tokens are split across exec() array args, e.g.
#   exec(new String[]{"/system/xbin/which", "su"})
_SU_ARG_RE = re.compile(r"""(["'\[\s,{(])su(["'\]\s,})])""", re.I)
_ROOT_PROBE_HINTS = (
    "which", "/system/xbin", "/system/bin", "/sbin", "/su/bin",
    "busybox", "superuser", "stat ", "ls ", "exec",
)


def _looks_like_root_detection(finding: dict, text: str) -> bool:
    blob = f"{text}\n{finding.get('title', '')}".lower()
    if any(tok in blob for tok in _ROOT_TOKENS):
        return True
    # Split-argument form: a standalone "su" token next to a probe verb/path.
    if _SU_ARG_RE.search(blob) and any(h in blob for h in _ROOT_PROBE_HINTS):
        return True
    return False


def _reclassify_root_detection(finding: dict, text: str) -> bool:
    """Downgrade a root-detection check from a vuln to an INFO security control.

    Returns True when the finding was reclassified.
    """
    rule_id = finding.get("rule_id") or finding.get("id") or ""
    # Only reclassify findings that are actually probing for root — never a real
    # OS-command-injection sink with tainted input (those keep their severity).
    if finding.get("taint_flow") or finding.get("call_chain"):
        return False
    if not _looks_like_root_detection(finding, text):
        return False

    finding["severity"] = "info"
    finding["category"] = "Security Controls"
    finding["title"] = "Root Detection Present"
    finding["security_control"] = True
    finding["reclassified_from"] = rule_id or "command_execution"
    finding["description"] = (
        "The application probes for signs of a rooted device (su binary, "
        "BusyBox, Magisk/SuperSU, test-keys builds, or known root-management "
        "packages). This is a defensive security control, not a vulnerability."
    )
    finding["recommendation"] = (
        "Root detection raises the bar for casual tampering. For higher "
        "assurance, combine it with Play Integrity / SafetyNet attestation, "
        "since on-device checks can be bypassed on a determined attacker's device."
    )
    return True


# ── Taint-flow grouping ──────────────────────────────────────────────────────
# Friendly group titles keyed by sink category (lower-cased substring match).
_SINK_GROUP_TITLES = (
    ("log", "User-Controlled Data Logged"),
    ("logging", "User-Controlled Data Logged"),
    ("sql", "User-Controlled Data in SQL Query"),
    ("file", "User-Controlled Data in File Operation"),
    ("webview", "User-Controlled Data Loaded in WebView"),
    ("intent", "User-Controlled Data in Intent"),
    ("command", "User-Controlled Data in OS Command"),
    ("exec", "User-Controlled Data in OS Command"),
    ("network", "User-Controlled Data in Network Request"),
    ("crypto", "User-Controlled Data in Crypto Operation"),
    ("reflection", "User-Controlled Data in Reflection Call"),
)


def _taint_group_title(sink_cat: str) -> str:
    s = (sink_cat or "").lower()
    for token, title in _SINK_GROUP_TITLES:
        if token in s:
            return title
    return f"User-Controlled Data Flows to {sink_cat or 'Sensitive Sink'}"


def _taint_location(finding: dict) -> str:
    """Short 'Class.method' style location for a taint flow finding."""
    chain = finding.get("call_chain") or (finding.get("taint_flow") or {}).get("chain")
    if isinstance(chain, list) and chain:
        head = str(chain[0])
        # com.app.SendMoney.onCreate -> SendMoney.onCreate
        segs = head.split(".")
        return ".".join(segs[-2:]) if len(segs) >= 2 else head
    path = _finding_path(finding)
    if path:
        base = path.replace("\\", "/").split("/")[-1]
        return base.rsplit(".", 1)[0] if "." in base else base
    return "unknown"


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _is_taint(finding: dict) -> bool:
    return bool(finding.get("taint_flow")) or finding.get("source") == "TAINT" \
        or finding.get("category") == "Taint Analysis"


# ── Phase G: taint-flow value gate ───────────────────────────────────────────
# Sinks that are a real injection / exfiltration primitive regardless of the
# data's sensitivity — a tainted value reaching them is always worth surfacing.
_HIGH_VALUE_TAINT_SINKS = {
    "webview", "filesystem", "crypto", "execution", "sqlite", "network",
    "reflection", "dynamicloading", "dynamic_loading",
}
# Sinks whose risk depends on the data: logging to logcat, intent redirects, and
# prefs writes are low value unless the source is genuinely sensitive PII.
_LOW_VALUE_TAINT_SINKS = {"logging", "intent", "storage"}
# PII / privileged sources that justify keeping even a low-value sink flow.
_PII_TAINT_SOURCES = {
    "location", "sms", "accounts", "camera", "microphone", "clipboard",
    "contentprovider",
}


def _is_low_value_taint(f: dict) -> bool:
    """Phase G: a taint flow into a low-value sink (Log / Intent / SharedPrefs)
    whose source is not sensitive PII — noise, not an actionable vulnerability.

    High-value sinks (WebView, SQL, file write, exec, reflection, dynamic
    loading, network) are NEVER low value; those are always prioritized.
    """
    if not _is_taint(f):
        return False
    tf = f.get("taint_flow") or {}
    sink = str(tf.get("sink_cat") or f.get("sink_cat") or "").replace(" ", "").lower()
    source = str(tf.get("source_cat") or f.get("source_cat") or "").replace(" ", "").lower()
    if sink in _HIGH_VALUE_TAINT_SINKS:
        return False
    if sink in _LOW_VALUE_TAINT_SINKS:
        return source not in _PII_TAINT_SOURCES
    return False


def _group_taint_findings(findings: list[dict]) -> tuple[list[dict], int]:
    """Collapse taint flows that share a sink-derived group title.

    Phase 4 (P5): group by the friendly, sink-derived title rather than by the
    raw (source_cat, sink_cat) pair, so the multiple "User-Controlled Data
    Logged" groups produced by different source categories merge into ONE. The
    distinct source categories are aggregated into the group description.

    Returns (new_list, collapsed_count): how many findings were absorbed.
    """
    groups: dict[str, list[dict]] = {}
    order: list[object] = []  # preserve first-seen ordering of groups + others

    for f in findings:
        if not isinstance(f, dict) or not _is_taint(f):
            order.append(f)
            continue
        tf = f.get("taint_flow") or {}
        sink_cat = str(tf.get("sink_cat") or f.get("sink_cat") or "Sensitive Sink")
        key = _taint_group_title(sink_cat)
        if key not in groups:
            groups[key] = []
            order.append(("group", key))
        groups[key].append(f)

    collapsed = 0
    result: list[dict] = []
    for item in order:
        if isinstance(item, dict):
            result.append(item)
            continue
        _, key = item
        members = groups[key]
        if len(members) == 1:
            result.append(members[0])
            continue
        collapsed += len(members) - 1
        result.append(_build_taint_group(key, members))
    return result, collapsed


def _build_taint_group(title: str, members: list[dict]) -> dict:
    """Synthesize one grouped finding from N taint flows (evidence preserved)."""
    rep = min(members, key=lambda m: _SEV_RANK.get(normalize_severity_label(m.get("severity")), 4))
    tf = rep.get("taint_flow") or {}
    sink_cat = tf.get("sink_cat") or rep.get("sink_cat") or "Sensitive Sink"

    # Distinct source categories across the merged flows (P5 aggregation).
    source_cats = []
    for m in members:
        sc = (m.get("taint_flow") or {}).get("source_cat") or m.get("source_cat")
        if sc and sc not in source_cats:
            source_cats.append(str(sc))
    sources_str = ", ".join(source_cats) if source_cats else "User Input"

    # De-duplicate evidence locations, keep insertion order.
    seen_loc = set()
    locations = []
    file_evidence = []
    any_app = False
    for m in members:
        if m.get("is_app_code") or m.get("ownership_label") == APPLICATION:
            any_app = True
        loc = _taint_location(m)
        if loc in seen_loc:
            continue
        seen_loc.add(loc)
        locations.append(loc)
        chain = m.get("call_chain") or (m.get("taint_flow") or {}).get("chain") or []
        file_evidence.append({
            "path": _finding_path(m) or loc,
            "lines": [m.get("line")] if m.get("line") else [],
            "snippet": " → ".join(str(c) for c in chain) if chain else loc,
        })

    # Highest-severity (lowest rank) member drives the group severity.
    best_sev = sorted(
        (normalize_severity_label(m.get("severity")) for m in members),
        key=lambda s: _SEV_RANK.get(s, 4),
    )[0] if members else "medium"

    grouped = dict(rep)  # inherit canonical fields/standards from representative
    grouped.update({
        "title": title,
        "severity": best_sev,
        "category": "Taint Analysis",
        "description": (
            f"User-controlled data from {sources_str} flows into "
            f"**{sink_cat}** in {len(locations)} location(s) without apparent "
            f"sanitization. All affected entry points are listed under Evidence."
        ),
        "grouped": True,
        "evidence_count": len(locations),
        "grouped_evidence": locations,
        "group_member_count": len(members),
        "file_evidence": file_evidence,
        "files": [e["path"] for e in file_evidence],
        "file_count": len(file_evidence),
    })
    # If any flow lands in app code, the group is application-owned (P1).
    if any_app:
        grouped["ownership"] = APP
        grouped["ownership_label"] = APPLICATION
        grouped["ownership_badge"] = OWNERSHIP_BADGES[APPLICATION]
        grouped["is_app_code"] = True
    # Drop single-flow fields that no longer describe the group as a whole.
    grouped.pop("call_chain", None)
    grouped.pop("snippet", None)
    return grouped


# ── Signal quality ───────────────────────────────────────────────────────────
def compute_signal_quality(finding: dict) -> str:
    """LOW / MEDIUM / HIGH. HIGH requires app code + high confidence + evidence."""
    app = is_application_code(finding)
    conf = _coerce_int(finding.get("confidence_score"), 0)
    ev = _coerce_int(finding.get("evidence_count"), 0)

    if app and conf >= 70 and ev >= 1:
        return "HIGH"
    if (app and conf >= 40) or (conf >= 70 and ev >= 1):
        return "MEDIUM"
    return "LOW"


def _has_extractable_evidence(finding: dict) -> bool:
    """Phase A — True when a finding carries at least one concrete piece of
    evidence an analyst can verify: a decompiled/manifest/xml/resource snippet,
    a resolvable source path, a taint chain, or a certificate evidence block.
    """
    if finding.get("is_attack_chain"):
        return True  # synthesized from its members' evidence
    if finding.get("file_evidence") or finding.get("call_chain") or finding.get("taint_flow"):
        return True
    for key in ("snippet", "code_context", "evidence", "file_path", "component"):
        if finding.get(key):
            return True
    # A manifest finding still awaiting enforcement carries its resolve spec.
    if finding.get("manifest_evidence_spec"):
        return True
    return False


def _evidence_count(finding: dict) -> int:
    if finding.get("grouped"):
        return _coerce_int(finding.get("evidence_count"), 1)
    fe = finding.get("file_evidence")
    if isinstance(fe, list) and fe:
        return len(fe)
    files = finding.get("files")
    if isinstance(files, list) and files:
        return len(files)
    if finding.get("file_path") or finding.get("snippet") or finding.get("call_chain"):
        return 1
    return 0


# ── Cross-section noise scrub (endpoints / IPs / evidence paths) ─────────────
# These run alongside Phase 3 to clean the non-finding result arrays the UI also
# renders (Domains/Endpoints, IPs). Detectors are fixed at source too; this is a
# defensive catch-all so a namespace URL or reserved IP can never reach a report.
_BINARY_DUMP_SUFFIXES = (
    ".dex", ".so", ".dylib", ".arsc", ".odex", ".vdex", ".oat",
    ".dex.txt", ".so.txt", ".dylib.txt", ".arsc.txt",
)
_NAMESPACE_URL_HOSTS = (
    "schemas.android.com", "schemas.microsoft.com", "schemas.xmlsoap.org",
    "schemas.openxmlformats.org", "www.w3.org", "/w3.org", "xmlns",
    "ns.adobe.com", "java.sun.com", "xml.org", "purl.org",
    "apache.org/licenses", "apache.org/xml", "openid.net/specs",
    "specs.openid.net", "oasis-open.org", "relaxng.org", "docbook.org",
)


def _is_binary_dump_path(path) -> bool:
    return str(path or "").replace("\\", "/").lower().endswith(_BINARY_DUMP_SUFFIXES)


def _is_namespace_url(url) -> bool:
    u = str(url or "").lower()
    return any(host in u for host in _NAMESPACE_URL_HOSTS)


def _is_real_public_or_private_ip(ip_str) -> bool:
    import ipaddress
    try:
        ip = ipaddress.ip_address(str(ip_str))
    except ValueError:
        return False
    if (ip.is_loopback or ip.is_unspecified or ip.is_multicast
            or ip.is_link_local or ip.is_reserved):
        return False
    for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "100.64.0.0/10"):
        if ip in ipaddress.ip_network(net):
            return False
    return True


def scrub_noise(results: dict) -> dict:
    """Strip namespace URLs, reserved/invalid IPs and binary-dump evidence from
    the result arrays the UI renders. Returns a small stats dict (what removed).
    """
    removed = {"endpoints": 0, "ips": 0, "evidence_repathed": 0}

    eps = results.get("endpoints")
    if isinstance(eps, list):
        kept = [u for u in eps if not _is_namespace_url(u)]
        removed["endpoints"] = len(eps) - len(kept)
        results["endpoints"] = kept

    ips = results.get("ips")
    if isinstance(ips, list):
        kept_ips = []
        for entry in ips:
            ip_val = entry.get("ip") if isinstance(entry, dict) else entry
            path = entry.get("file_path") if isinstance(entry, dict) else ""
            if not _is_real_public_or_private_ip(ip_val) or _is_binary_dump_path(path):
                continue
            kept_ips.append(entry)
        removed["ips"] = len(ips) - len(kept_ips)
        results["ips"] = kept_ips

    # Re-point findings/secrets that landed on a binary dump to the best
    # non-binary evidence path available; otherwise leave them (dex-only scans).
    for coll_key in ("findings", "secrets"):
        for item in results.get(coll_key, []) or []:
            if not isinstance(item, dict):
                continue
            if _is_binary_dump_path(item.get("file_path") or item.get("full_path")):
                alt = _first_non_binary_path(item)
                if alt:
                    item["file_path"] = alt
                    removed["evidence_repathed"] += 1
    return removed


def _first_non_binary_path(item: dict) -> str:
    for e in item.get("file_evidence") or []:
        if isinstance(e, dict) and e.get("path") and not _is_binary_dump_path(e["path"]):
            return str(e["path"])
    for f in item.get("files") or []:
        if f and not _is_binary_dump_path(f):
            return str(f)
    return ""


# ═════════════════════════════════════════════════════════════════════════════
# Phase 6 Task 6 — Manifest Evidence Enforcement
# ═════════════════════════════════════════════════════════════════════════════
# Every manifest-derived finding must carry a real manifest path, line number,
# and the exact manifest snippet. Findings are tagged at creation with a
# `manifest_evidence_spec` ({attr, value, anchor}); this pass resolves that spec
# against the decoded AndroidManifest.xml and either attaches the evidence or
# DROPS the finding entirely when no evidence line can be located.

def _load_manifest_text(scan_id: str, manifest_xml: str = "") -> tuple[str, str]:
    """Return (text, rel_path) for the decoded AndroidManifest.xml.

    Prefer the apktool-decoded file on disk (real, viewable line numbers); fall
    back to the reconstructed manifest string captured during parsing.
    """
    try:
        from . import scan_storage  # lazy: avoid import cycle
        p = scan_storage.resolve_source_file(scan_id, "AndroidManifest.xml")
        if p and p.is_file():
            txt = p.read_text(errors="replace")
            if "<manifest" in txt or "<application" in txt:
                return txt, "AndroidManifest.xml"
    except Exception:
        pass
    if isinstance(manifest_xml, str) and manifest_xml.strip():
        return manifest_xml, "AndroidManifest.xml"
    return "", "AndroidManifest.xml"


def _find_manifest_line(text: str, spec: dict) -> tuple[int, str]:
    """Locate the manifest line for a spec. Returns (line_no, snippet) or (0, "")."""
    if not text:
        return 0, ""
    lines = text.splitlines()
    attr = spec.get("attr")
    value = spec.get("value")
    if attr:
        if value:
            pat = re.compile(
                r'(?:android:)?' + re.escape(attr) + r'\s*=\s*"' + re.escape(str(value)) + r'"', re.I)
        else:
            pat = re.compile(r'(?:android:)?' + re.escape(attr) + r'\s*=\s*"[^"]*"', re.I)
        for i, ln in enumerate(lines, 1):
            if pat.search(ln):
                return i, _snippet_around(lines, i)
    anchor = spec.get("anchor")
    if anchor:
        apat = re.compile(r'<' + re.escape(anchor) + r'(\s|>|/)', re.I)
        for i, ln in enumerate(lines, 1):
            if apat.search(ln):
                return i, _snippet_around(lines, i)
    return 0, ""


def enforce_manifest_evidence(findings: list[dict], scan_id: str,
                              manifest_xml: str = "") -> tuple[list[dict], dict]:
    """Attach manifest path/line/snippet to tagged findings, or drop them (P6.6).

    A finding carrying `manifest_evidence_spec` MUST resolve to a real manifest
    line. When it does, evidence is attached and the spec removed. When it does
    not (manifest unavailable, attribute/anchor absent), the finding is dropped.
    Returns (kept_findings, stats).
    """
    stats = {"checked": 0, "attached": 0, "dropped": 0, "examples": []}
    findings = findings or []
    if not any(isinstance(f, dict) and f.get("manifest_evidence_spec") for f in findings):
        return findings, stats

    text, mpath = _load_manifest_text(scan_id, manifest_xml)
    kept: list[dict] = []
    for f in findings:
        if not isinstance(f, dict) or not f.get("manifest_evidence_spec"):
            kept.append(f)
            continue
        stats["checked"] += 1
        spec = f.get("manifest_evidence_spec") or {}
        line, snippet = _find_manifest_line(text, spec)
        if not line:
            stats["dropped"] += 1
            continue
        f.pop("manifest_evidence_spec", None)
        f["file_path"] = mpath
        f["line"] = line
        f["line_number"] = line
        f["file_evidence"] = [{"path": mpath, "lines": [line], "snippet": snippet}]
        f["files"] = [mpath]
        f["snippet"] = snippet
        f["evidence"] = snippet
        f["evidence_type"] = "manifest"
        stats["attached"] += 1
        if len(stats["examples"]) < 6:
            stats["examples"].append({
                "title": f.get("title"), "line": line,
                "snippet": snippet.strip(),
            })
        kept.append(f)
    return kept, stats


# ═════════════════════════════════════════════════════════════════════════════
# Phase 5 — Source Resolution Validation + View Code gating
# ═════════════════════════════════════════════════════════════════════════════
# Every finding must EITHER resolve to a real source file + line, OR explicitly
# state why source is unavailable. View Code is only offered when resolution
# succeeds. A finding that *claims* a source location which cannot be resolved is
# downgraded (unresolved evidence) so it never masquerades as high-confidence.

def _looks_classref(p: str) -> bool:
    """True for dotted/JVM class references (taint flow file_path), not paths."""
    if not p:
        return False
    t = str(p).strip()
    if t.startswith("L") and "/" in t and t.endswith(";"):
        return True
    return ("/" not in t and "\\" not in t and "." in t
            and (t.endswith(";") or t.split("$", 1)[0].split(".")[-1][:1].isupper()))


def _class_ref_to_source_candidates(file_path: str) -> list[str]:
    """Candidate source rel-paths for a dotted/JVM class reference."""
    t = str(file_path or "").strip()
    if t.startswith("L") and "/" in t:
        t = t[1:].rstrip(";").replace("/", ".")
    t = t.rstrip(";")
    if "/" in t or "\\" in t or "." not in t:
        return []
    outer = t.split("$", 1)[0]
    parts = [s for s in outer.split(".") if s]
    if len(parts) < 2:
        return []
    rel = "/".join(parts)
    return [f"sources/{rel}.java", f"{rel}.java", f"smali/{rel}.smali", f"{rel}.smali"]


def _taint_tokens(finding: dict) -> list[str]:
    """Method-name tokens to locate the relevant line inside a resolved source."""
    toks = []
    tf = finding.get("taint_flow") or {}
    for key in ("sink", "source"):
        v = tf.get(key)
        if v and "." in str(v):
            toks.append(str(v).rsplit(".", 1)[-1])
    if finding.get("method_name"):
        toks.append(str(finding["method_name"]))
    return [t for t in toks if t]


def _snippet_around(lines: list[str], i: int, ctx: int = 2) -> str:
    start = max(1, i - ctx)
    end = min(len(lines), i + ctx)
    out = []
    for j in range(start, end + 1):
        marker = ">" if j == i else " "
        out.append(f"{marker} {j:5d} | {lines[j - 1][:300]}")
    return "\n".join(out)


def _locate_line(text: str, tokens: list[str]) -> tuple[int, str]:
    if not text or not tokens:
        return 0, ""
    lines = text.splitlines()
    for i, ln in enumerate(lines, 1):
        if any(tok in ln for tok in tokens):
            return i, _snippet_around(lines, i)
    return 0, ""


_CLASS_DECL_CACHE: dict[str, "re.Pattern"] = {}


def _short_class_name(*candidates: str) -> str:
    """Best short class name from a component FQN / class-ref / source basename."""
    for c in candidates:
        if not c:
            continue
        t = str(c).strip().rstrip(";").replace("\\", "/")
        seg = t.split("/")[-1].split(".")[-1].split("$", 1)[0]
        if seg and seg[:1].isupper():
            return seg
        # source basename like "SendMoney.java" -> strip extension, retry
        base = os.path.splitext(os.path.basename(t))[0].split("$", 1)[0]
        if base and base[:1].isupper():
            return base
    return ""


def _locate_class_decl(text: str, short_name: str) -> tuple[int, str]:
    """Locate the class/interface/enum/object declaration line for short_name.

    Lets class-level findings (e.g. exported components) that carry no usage line
    land View Code on the exact declaration instead of the top of the file.
    """
    if not text or not short_name:
        return 0, ""
    pat = _CLASS_DECL_CACHE.get(short_name)
    if pat is None:
        pat = re.compile(r"\b(?:class|interface|enum|object)\s+" + re.escape(short_name) + r"\b")
        _CLASS_DECL_CACHE[short_name] = pat
    lines = text.splitlines()
    for i, ln in enumerate(lines, 1):
        if pat.search(ln):
            return i, _snippet_around(lines, i)
    return 0, ""


def _unresolved_reason(finding: dict, claimed: list[str]) -> str:
    fp = finding.get("file_path")
    if _looks_classref(fp):
        return f"Decompiled source for class {str(fp).rstrip(';')} was not found in jadx/apktool output."
    if any(_is_binary_dump_path(p) for p in claimed):
        return "Evidence is a compiled binary artifact; no decompiled source line is available."
    return "The referenced source file could not be resolved in the decompiled output."


def _no_source_reason(finding: dict) -> str:
    cat = str(finding.get("category") or "").lower()
    if cat == "certificate":
        return "Signing-certificate finding — evidence is the certificate metadata block, not a source line."
    if "binary" in cat or "native" in cat:
        return "Native binary finding — no Java/Kotlin source location applies."
    if finding.get("capability"):
        return "Capability detected in compiled code; no decompiled source location available."
    return "Manifest / configuration finding — no single source line (review AndroidManifest.xml)."


def validate_source_resolution(findings: list[dict], scan_id: str, manifest_xml: str = "") -> dict:
    """Resolve each finding to a real source file+line or explain why not (P5.1/5.3).

    Sets per finding: source_resolved (bool), view_code (bool),
    source_unavailable_reason (str when unresolved), unresolved_evidence (bool
    when a claimed path fails). Rewrites taint class refs to the real source
    path + line + snippet. Returns small stats. Run BEFORE refine_findings so
    the confidence engine can penalise unresolved evidence.
    """
    from . import scan_storage  # lazy: avoids import cycle

    stats = {"resolved": 0, "unresolved_claim": 0, "no_source": 0}
    for f in findings:
        if not isinstance(f, dict):
            continue
        # Collect claimed evidence paths (skip binary dumps outright).
        claimed = []
        for p in [f.get("file_path"), *( (e or {}).get("path") for e in (f.get("file_evidence") or []) ), *(f.get("files") or [])]:
            if p and p not in claimed:
                claimed.append(p)
        has_claim = bool(claimed)

        # Expand to resolvable candidates. Only dotted/JVM CLASS references are
        # rewritten to source paths; real filenames (AndroidManifest.xml,
        # foo.json) are tried literally — otherwise "AndroidManifest.xml" would
        # be mis-parsed as the class AndroidManifest.xml -> sources/.../xml.java
        # and never resolve.
        candidates = []
        for p in claimed:
            if _is_binary_dump_path(p):
                continue
            if _looks_classref(p):
                cref = _class_ref_to_source_candidates(p)
                candidates.extend(cref if cref else [p])
            else:
                candidates.append(p)

        resolved_rel = resolved_path = None
        for cand in candidates:
            try:
                rp = scan_storage.resolve_source_file(scan_id, cand)
            except Exception:
                rp = None
            if rp and rp.is_file() and not _is_binary_dump_path(rp.name):
                resolved_rel, resolved_path = cand, rp
                break

        if resolved_path is not None:
            line = f.get("line") if isinstance(f.get("line"), int) and f.get("line") > 0 else 0
            snippet = f.get("snippet") if isinstance(f.get("snippet"), str) else ""
            need_locate = _looks_classref(f.get("file_path")) or not line
            try:
                text = resolved_path.read_text(errors="replace")
            except Exception:
                text = ""
            if need_locate and text:
                ln, snip = _locate_line(text, _taint_tokens(f) or [])
                if not ln and not line:
                    # Class-level finding (e.g. exported component) with no usage
                    # token: land on the class declaration so View Code opens the
                    # exact component, not line 1.
                    short = _short_class_name(f.get("component"), f.get("file_path"), resolved_rel)
                    ln, snip = _locate_class_decl(text, short)
                if ln:
                    line, snippet = ln, snip
            if (not snippet) and line and text:
                snippet = _snippet_around(text.splitlines(), line)
            # Validate snippet retrievable; if not, treat as unresolved.
            if snippet or text:
                f["source_resolved"] = True
                f["view_code"] = True
                f["file_path"] = resolved_rel
                if line:
                    f["line"] = line
                f["file_evidence"] = [{"path": resolved_rel, "lines": [line] if line else [], "snippet": snippet}]
                f["files"] = [resolved_rel]
                f.pop("source_unavailable_reason", None)
                f.pop("unresolved_evidence", None)
                stats["resolved"] += 1
                continue

        # Manifest / config fallback: an app-scoped manifest or configuration
        # finding that resolved to no code line can still open the decoded
        # AndroidManifest.xml in the viewer (Phase B fallback chain). This covers
        # min-SDK, permission-overlap, app-links and similar manifest-derived
        # findings that carry no explicit path.
        if _is_manifest_viewable(f):
            try:
                mp = scan_storage.resolve_source_file(scan_id, "AndroidManifest.xml")
            except Exception:
                mp = None
            if mp and mp.is_file():
                line = f.get("line") if isinstance(f.get("line"), int) and f.get("line") > 0 else 0
                snippet = f.get("snippet") if isinstance(f.get("snippet"), str) else ""
                # Component-scoped manifest findings (exported activity/service/
                # receiver) carry the full class name but no line. Resolve it to
                # the real `android:name="<component>"` declaration line in the
                # DECODED manifest (the on-disk copy is often binary AXML, so use
                # _load_manifest_text which falls back to the decoded string) —
                # this is a real line lookup, never a fabricated one.
                comp = f.get("component") or f.get("component_name")
                if not line and comp:
                    try:
                        mtext, _ = _load_manifest_text(scan_id, manifest_xml)
                        cline, csnip = _find_manifest_line(mtext, {"attr": "name", "value": comp})
                        if cline:
                            line, snippet = cline, csnip
                    except Exception:
                        pass
                if not snippet and line:
                    try:
                        snippet = _snippet_around(mp.read_text(errors="replace").splitlines(), line)
                    except Exception:
                        snippet = ""
                f["source_resolved"] = True
                f["view_code"] = True
                f["file_path"] = "AndroidManifest.xml"
                f["files"] = ["AndroidManifest.xml"]
                if line:
                    f["line"] = line
                    f["line_number"] = line
                f["file_evidence"] = [{"path": "AndroidManifest.xml",
                                       "lines": [line] if line else [], "snippet": snippet}]
                f.pop("source_unavailable_reason", None)
                f.pop("unresolved_evidence", None)
                stats["resolved"] += 1
                continue

        # Not resolved.
        f["source_resolved"] = False
        f["view_code"] = False
        non_binary_claim = any(not _is_binary_dump_path(p) for p in claimed)
        if has_claim and non_binary_claim:
            f["unresolved_evidence"] = True
            f["source_unavailable_reason"] = _unresolved_reason(f, claimed)
            stats["unresolved_claim"] += 1
        else:
            f.pop("unresolved_evidence", None)
            reason = _no_source_reason(f)
            f["source_unavailable_reason"] = reason
            # Native-binary symbols and certificate metadata have no Java/Kotlin
            # source line by nature — their evidence is the symbol / cert block.
            # Flag them so they are reported separately, not counted as a gap.
            if "Native binary" in reason or f.get("category") == "Certificate":
                f["source_applicable"] = False
            stats["no_source"] += 1
    return stats


# Categories whose findings are manifest-derived and can fall back to opening
# the decoded AndroidManifest.xml when no code line resolves. Deliberately
# EXCLUDES Certificate (cert block) and native Binary-Hardening (ELF symbol).
_MANIFEST_VIEW_CATEGORIES = {
    "configuration", "permissions", "deeplinks", "deeplink", "network security",
    "data storage", "manifest", "attack surface", "attack chain",
}


def _is_manifest_viewable(finding: dict) -> bool:
    if finding.get("evidence_type") == "manifest":
        return True
    cat = str(finding.get("category") or "").lower()
    if cat == "certificate":
        return False
    # Native binary-hardening findings (ELF) are not manifest-viewable.
    if cat == "binary hardening" and finding.get("evidence_type") != "manifest":
        # Only treat as manifest-viewable if it actually came from the manifest
        # (e.g. the missing-debuggable-flag check).
        title = str(finding.get("title") or "").lower()
        return "debuggable" in title or "backup" in title
    return cat in _MANIFEST_VIEW_CATEGORIES


# ── Finding Quality Report (Phase 5.4) ───────────────────────────────────────
def build_finding_quality_report(findings: list[dict]) -> list[dict]:
    """One row per finding: id, ownership, confidence, source/view-code/library."""
    report = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        label = f.get("ownership_label") or UNKNOWN
        report.append({
            "finding_id": f.get("canonical_id") or f.get("rule_id") or f.get("id") or f.get("title"),
            "title": f.get("title"),
            "severity": normalize_severity_label(f.get("severity")),
            "ownership": label,
            "confidence": _coerce_int(f.get("confidence_score"), 0),
            "source_resolvable": bool(f.get("source_resolved")),
            "view_code_available": bool(f.get("view_code")),
            "library_or_framework_owned": label not in (APPLICATION, UNKNOWN, ""),
            "source_unavailable_reason": f.get("source_unavailable_reason", ""),
        })
    return report


def log_finding_quality_report(report: list[dict], *, platform: str = "android") -> None:
    if not report:
        return
    resolvable = sum(1 for r in report if r["source_resolvable"])
    viewable = sum(1 for r in report if r["view_code_available"])
    lib = sum(1 for r in report if r["library_or_framework_owned"])
    lines = [
        "", "===== FINDING QUALITY REPORT =====", "",
        f"Findings: {len(report)} | source-resolvable: {resolvable} | "
        f"view-code: {viewable} | library/framework-owned: {lib}", "",
        f"{'ID':<18}{'OWN':<13}{'CONF':<6}{'SRC':<5}{'VIEW':<6}{'LIB':<5}TITLE",
    ]
    for r in report:
        lines.append(
            f"{str(r['finding_id'])[:17]:<18}{r['ownership'][:12]:<13}"
            f"{r['confidence']:<6}{('Y' if r['source_resolvable'] else 'N'):<5}"
            f"{('Y' if r['view_code_available'] else 'N'):<6}"
            f"{('Y' if r['library_or_framework_owned'] else 'N'):<5}{str(r['title'])[:50]}"
        )
    lines += ["", "=================================="]
    log.info("\n".join(lines))


# ── The Phase 3 entry point ──────────────────────────────────────────────────
def refine_findings(findings: list[dict], *, app_package: str = "",
                    platform: str = "android") -> tuple[list[dict], list[dict], dict]:
    """Reduce noise + improve quality. Pure-ish: mutates findings, returns parts.

    Returns (kept, suppressed, stats):
      * kept       — primary findings (real; library/low-confidence still here
                     but de-prioritized via fields, hidden by default in views).
      * suppressed — known false positives, partitioned out (never deleted).
      * stats      — before/after counts for the noise-reduction report.

    Run AFTER canonicalize_findings() so ownership/canonical fields exist.
    """
    findings = [f for f in (findings or []) if isinstance(f, dict)]
    raw_total = len(findings)

    # 1. Per-finding annotation: label, badge, confidence, reclassification.
    reclassified_count = 0
    for f in findings:
        coarse, label, owner_pkg = resolve_finding_ownership(f, app_package)
        f["ownership"] = coarse
        if owner_pkg and not f.get("owner_package"):
            f["owner_package"] = owner_pkg
        f["ownership_label"] = label
        f["ownership_badge"] = OWNERSHIP_BADGES.get(label, label)
        f["is_app_code"] = (label == APPLICATION)

        text = _finding_text(f)
        if _reclassify_root_detection(f, text):
            reclassified_count += 1
            text = _finding_text(f)  # title/desc changed

        conf = compute_confidence(f, text)
        f["confidence_score"] = conf
        f["confidence_band"] = confidence_band(conf)

    # 1b. Phase G — prune low-value taint flows (Input→Log / →Intent / →prefs
    # without sensitive PII source) BEFORE grouping so they neither inflate the
    # report nor the collapsed-duplicate count. High-value sinks are untouched.
    taint_pruned: list[dict] = []
    survivors: list[dict] = []
    for f in findings:
        if _is_low_value_taint(f):
            f["suppressed"] = True
            f["suppressed_reason"] = "low_value_taint_sink"
            taint_pruned.append(f)
        else:
            survivors.append(f)
    findings = survivors

    # 2. Taint-flow grouping (collapses duplicates; evidence preserved).
    findings, collapsed = _group_taint_findings(findings)

    # 3. Suppression of known false positives + final quality scoring.
    kept: list[dict] = []
    suppressed: list[dict] = list(taint_pruned)
    for f in findings:
        f["evidence_count"] = _evidence_count(f)
        text = _finding_text(f)
        reason = _suppression_reason(f, text, _coerce_int(f.get("confidence_score"), 0))
        # Phase A — hard evidence gate: a visible finding MUST carry at least one
        # concrete piece of evidence (decompiled/manifest/xml/resource/cert
        # snippet or a taint chain). Anything that cannot be evidenced is moved
        # out of the primary list rather than shown unsupported.
        if not reason and not _has_extractable_evidence(f):
            reason = "no_extractable_evidence"
        f["signal_quality"] = compute_signal_quality(f)
        if reason:
            f["suppressed"] = True
            f["suppressed_reason"] = reason
            suppressed.append(f)
        else:
            f["suppressed"] = False
            kept.append(f)

    stats = _build_quality_stats(raw_total, kept, suppressed, collapsed, reclassified_count)
    return kept, suppressed, stats


def _build_quality_stats(raw_total: int, kept: list[dict], suppressed: list[dict],
                         collapsed: int, reclassified: int) -> dict:
    by_label = Counter(f.get("ownership_label", UNKNOWN) for f in kept)
    by_band = Counter(f.get("confidence_band", "informational") for f in kept)
    by_quality = Counter(f.get("signal_quality", "LOW") for f in kept)

    app_only = [f for f in kept if f.get("is_app_code")]
    high_conf = [f for f in kept if _coerce_int(f.get("confidence_score"), 0) >= 70]
    # Default view = application-owned AND high confidence AND not suppressed.
    default_view = [f for f in app_only if _coerce_int(f.get("confidence_score"), 0) >= 70]
    # Phase E: library / framework / SDK findings are kept but hidden from the
    # default analyst view ("39 library findings hidden"). Count them explicitly.
    _LIB_LABELS = (THIRD_PARTY_LIBRARY, ANDROID_FRAMEWORK, GOOGLE_SDK, FIREBASE, JETPACK)
    library_hidden = [f for f in kept if f.get("ownership_label") in _LIB_LABELS]

    # Noise reduction is measured against the raw (pre-Phase-3) finding count:
    # collapsed dups + suppressed FPs + library/low-confidence hidden by default.
    default_n = len(default_view)
    reduction = round((1 - (default_n / raw_total)) * 100) if raw_total else 0

    return {
        "raw_total": raw_total,
        "collapsed_duplicates": collapsed,
        "reclassified_controls": reclassified,
        "suppressed_count": len(suppressed),
        "kept_total": len(kept),
        "application_only_count": len(app_only),
        "high_confidence_count": len(high_conf),
        "suppressed_library_count": len(library_hidden),
        "default_view_count": default_n,
        "noise_reduction_pct": reduction,
        "by_ownership_label": dict(by_label),
        "by_confidence_band": dict(by_band),
        "by_signal_quality": dict(by_quality),
        "suppressed_reasons": dict(Counter(f.get("suppressed_reason", "") for f in suppressed)),
    }


_FP_SUPPRESSION_REASONS = (
    "hashcode_not_crypto", "import_only_no_instantiation",
    "android_namespace_url", "no_extractable_evidence",
)
_NOISE_SUPPRESSION_REASONS = ("low_value_taint_sink", "framework_library_taint")


def build_executive_summary(stats: dict, suppressed: list[dict]) -> dict:
    """Phase K — the "top of report" funnel: raw detections → high-signal set.

    Turns the internal quality stats into the analyst-facing breakdown of how
    raw detections were reduced to the presented set (duplicates grouped,
    library noise hidden, false positives removed, low-value flows pruned).
    """
    reasons = Counter(f.get("suppressed_reason", "") for f in (suppressed or []))
    false_positives = sum(reasons.get(r, 0) for r in _FP_SUPPRESSION_REASONS)
    low_value = sum(reasons.get(r, 0) for r in _NOISE_SUPPRESSION_REASONS)

    raw = stats.get("raw_total", 0)
    dups = stats.get("collapsed_duplicates", 0)
    lib = stats.get("suppressed_library_count", 0)
    high_signal = stats.get("default_view_count", 0)

    return {
        "raw_detections": raw,
        "duplicates_grouped": dups,
        "library_findings_hidden": lib,
        "false_positives_suppressed": false_positives,
        "low_value_flows_pruned": low_value,
        "high_signal_findings": high_signal,
        "lines": [
            f"{raw} detections found",
            f"{dups} duplicates grouped",
            f"{lib} library findings hidden",
            f"{false_positives} false positives removed",
            f"{low_value} low-value data flows pruned",
            f"{high_signal} high-signal findings presented",
        ],
    }


def log_quality_stats(stats: dict, *, platform: str = "android") -> None:
    """Emit the before/after SIGNAL QUALITY block at INFO."""
    if not stats:
        return
    lines = [
        "",
        "===== SIGNAL QUALITY (Phase 3) =====",
        "",
        f"Raw findings:            {stats.get('raw_total', 0)}",
        f"Collapsed duplicates:    {stats.get('collapsed_duplicates', 0)}",
        f"Reclassified controls:   {stats.get('reclassified_controls', 0)}",
        f"Suppressed FPs:          {stats.get('suppressed_count', 0)}",
        f"Kept (all ownership):    {stats.get('kept_total', 0)}",
        f"Application-only:        {stats.get('application_only_count', 0)}",
        f"High confidence (>=70):  {stats.get('high_confidence_count', 0)}",
        f"DEFAULT VIEW:            {stats.get('default_view_count', 0)}",
        f"Noise reduction:         {stats.get('noise_reduction_pct', 0)}%",
        "",
        f"By ownership: {stats.get('by_ownership_label', {})}",
        f"By signal:    {stats.get('by_signal_quality', {})}",
        "====================================",
    ]
    log.info("\n".join(lines))


# ═════════════════════════════════════════════════════════════════════════════
# Beetle 2.0 Phase 1.1 — Canonical Finding Model (re-export)
# ═════════════════════════════════════════════════════════════════════════════
# The typed source-of-truth finding lives in `canonical_finding.py`. It is
# re-exported here so existing importers of this module can reach it and so it is
# unambiguously THE finding model, not a competing one. The phase-based functions
# above continue to operate on plain dicts; `CanonicalFinding` standardizes that
# shape and is the substrate later phases (ownership, confidence, evidence,
# report) will migrate onto. Importing it here is additive and does not alter any
# pipeline behavior.
from .canonical_finding import (  # noqa: E402,F401  (re-export, end-of-module by design)
    CanonicalFinding,
    from_legacy as canonical_from_legacy,
    to_legacy as canonical_to_legacy,
    from_legacy_list as canonical_from_legacy_list,
    canonicalize_dict,
)


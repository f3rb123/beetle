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
    "behavior analysis",
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
    """Local, dependency-free severity normalizer (mirrors common.normalize)."""
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

    # 2. Taint-flow grouping (collapses duplicates; evidence preserved).
    findings, collapsed = _group_taint_findings(findings)

    # 3. Suppression of known false positives + final quality scoring.
    kept: list[dict] = []
    suppressed: list[dict] = []
    for f in findings:
        f["evidence_count"] = _evidence_count(f)
        text = _finding_text(f)
        reason = _suppression_reason(f, text, _coerce_int(f.get("confidence_score"), 0))
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
        "default_view_count": default_n,
        "noise_reduction_pct": reduction,
        "by_ownership_label": dict(by_label),
        "by_confidence_band": dict(by_band),
        "by_signal_quality": dict(by_quality),
        "suppressed_reasons": dict(Counter(f.get("suppressed_reason", "") for f in suppressed)),
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


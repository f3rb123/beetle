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


def _path_to_package(path: str) -> str:
    """Best-effort dotted package from a decompiled source path.

    "sources/com/example/app/Foo.java" -> "com.example.app"
    "smali_classes2/androidx/work/Worker.smali" -> "androidx.work"
    Returns "" when no package can be derived (resources, manifest, dex root).
    """
    if not path:
        return ""
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


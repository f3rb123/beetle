"""
Cortex OSV.dev Supply Chain Scanner
=====================================
Extracts library dependencies from decompiled Android source and queries
the OSV.dev API (https://api.osv.dev/v1/query) for known vulnerabilities.

No API key required. Free and open service by Google.

Supported dependency sources:
  - build.gradle / build.gradle.kts  (Groovy + Kotlin DSL)
  - gradle/libs.versions.toml        (version catalog)
  - pom.xml                          (Maven)
  - package.json                     (npm / React Native)
  - pubspec.yaml                     (Flutter / Dart)
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


# ─── Config ───────────────────────────────────────────────────────────────────
OSV_API_URL    = "https://api.osv.dev/v1/query"
OSV_BATCH_URL  = "https://api.osv.dev/v1/querybatch"
REQUEST_TIMEOUT = 8
MAX_DEPS_TO_QUERY = 60   # cap per scan to avoid long waits
MAX_WORKERS       = 8


# ─── Ecosystem mapping ────────────────────────────────────────────────────────
# Maps source type → OSV ecosystem name
_ECOSYSTEM = {
    "gradle":  "Maven",
    "maven":   "Maven",
    "npm":     "npm",
    "pypi":    "PyPI",
    "pub":     "Pub",     # Flutter/Dart
}


# ─── Gradle dependency extraction ────────────────────────────────────────────
_GRADLE_DEP_PATTERN = re.compile(
    r"""(?:implementation|api|compile|runtimeOnly|testImplementation|debugImplementation|
         kapt|annotationProcessor|classpath|compileOnly)\s*
        [\(\s]*['"]
        ([a-zA-Z0-9_\-\.]+):([a-zA-Z0-9_\-\.]+):([^\s'":\)]+)
        ['"][\)\s]*""",
    re.VERBOSE | re.IGNORECASE,
)

_GRADLE_KTS_DEP_PATTERN = re.compile(
    r"""(?:implementation|api|runtimeOnly|testImplementation|debugImplementation|
         kapt|annotationProcessor|classpath|compileOnly)\s*\(
        ['"]([a-zA-Z0-9_\-\.]+):([a-zA-Z0-9_\-\.]+):([^\s'":\)]+)['"]
        \)""",
    re.VERBOSE | re.IGNORECASE,
)

_TOML_DEP_PATTERN = re.compile(
    r'^\s*\w+\s*=\s*\{[^}]*module\s*=\s*"([^"]+)"[^}]*version\s*=\s*"([^"]+)"',
    re.MULTILINE,
)
_TOML_VERSION_REF = re.compile(
    r'^\s*\w+\s*=\s*\{[^}]*module\s*=\s*"([^"]+)"[^}]*version\.ref\s*=\s*"([^"]+)"',
    re.MULTILINE,
)
_TOML_VERSIONS_SECTION = re.compile(
    r'^\[versions\](.*?)(?=^\[|\Z)',
    re.MULTILINE | re.DOTALL,
)
_TOML_VERSION_ENTRY = re.compile(r'^\s*(\w[\w\-]*)\s*=\s*"([^"]+)"', re.MULTILINE)


def _parse_gradle(content: str, filename: str) -> list:
    deps = []
    pattern = _GRADLE_KTS_DEP_PATTERN if filename.endswith(".kts") else _GRADLE_DEP_PATTERN
    for m in pattern.finditer(content):
        group, artifact, version = m.group(1), m.group(2), m.group(3)
        version = version.strip()
        # Skip variable refs like ${versions.foo}
        if "$" in version or version.startswith("["):
            continue
        deps.append({
            "group":     group,
            "artifact":  artifact,
            "version":   version,
            "name":      f"{group}:{artifact}",
            "ecosystem": "Maven",
            "source":    filename,
        })
    return deps


def _parse_toml(content: str) -> list:
    """Parse gradle/libs.versions.toml version catalog."""
    deps = []
    # Extract [versions] block for ref resolution
    versions: dict[str, str] = {}
    ver_block = _TOML_VERSIONS_SECTION.search(content)
    if ver_block:
        for vm in _TOML_VERSION_ENTRY.finditer(ver_block.group(1)):
            versions[vm.group(1)] = vm.group(2)

    # Direct versions
    for m in _TOML_DEP_PATTERN.finditer(content):
        module, version = m.group(1), m.group(2)
        if ":" in module:
            group, artifact = module.split(":", 1)
            deps.append({
                "group": group, "artifact": artifact,
                "version": version, "name": module,
                "ecosystem": "Maven", "source": "libs.versions.toml",
            })

    # version.ref= entries
    for m in _TOML_VERSION_REF.finditer(content):
        module, ref = m.group(1), m.group(2)
        version = versions.get(ref, "")
        if version and ":" in module:
            group, artifact = module.split(":", 1)
            deps.append({
                "group": group, "artifact": artifact,
                "version": version, "name": module,
                "ecosystem": "Maven", "source": "libs.versions.toml",
            })

    return deps


def _parse_pom(content: str) -> list:
    """Extract <dependency> blocks from pom.xml."""
    deps = []
    dep_blocks = re.findall(r"<dependency>(.*?)</dependency>", content, re.DOTALL)
    for block in dep_blocks:
        group    = re.search(r"<groupId>(.*?)</groupId>",    block, re.DOTALL)
        artifact = re.search(r"<artifactId>(.*?)</artifactId>", block, re.DOTALL)
        version  = re.search(r"<version>(.*?)</version>",    block, re.DOTALL)
        if group and artifact and version:
            ver = version.group(1).strip()
            if "$" in ver or not ver:
                continue
            g = group.group(1).strip()
            a = artifact.group(1).strip()
            deps.append({
                "group": g, "artifact": a, "version": ver,
                "name": f"{g}:{a}", "ecosystem": "Maven", "source": "pom.xml",
            })
    return deps


def _parse_package_json(content: str) -> list:
    """Extract npm dependencies from package.json."""
    deps = []
    try:
        data = json.loads(content)
    except Exception:
        return deps
    for section in ("dependencies", "devDependencies"):
        for name, version_spec in (data.get(section) or {}).items():
            # Clean up version spec — strip ^, ~, >=, etc.
            clean = re.sub(r"[\^~>=<]", "", version_spec.strip()).split(" ")[0]
            if clean and re.match(r"\d+\.\d+", clean):
                deps.append({
                    "group": "", "artifact": name,
                    "version": clean, "name": name,
                    "ecosystem": "npm", "source": "package.json",
                })
    return deps


def _parse_pubspec(content: str) -> list:
    """Extract Flutter/Dart dependencies from pubspec.yaml."""
    deps = []
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped in ("dependencies:", "dev_dependencies:"):
            in_deps = True
            continue
        if in_deps:
            if not line.startswith(" ") and not line.startswith("\t") and stripped:
                in_deps = False
                continue
            m = re.match(r"\s+(\w[\w_\-]*)\s*:\s*\^?(\d[\d\.]+)", line)
            if m:
                name, version = m.group(1), m.group(2)
                deps.append({
                    "group": "", "artifact": name,
                    "version": version, "name": name,
                    "ecosystem": "Pub", "source": "pubspec.yaml",
                })
    return deps


# ─── Directory walker ─────────────────────────────────────────────────────────
def extract_dependencies(scan_dirs: list) -> list:
    """Walk scan_dirs and extract all declared library dependencies."""
    all_deps: list[dict] = []
    seen: set[str] = set()

    target_files = {
        "build.gradle", "build.gradle.kts",
        "libs.versions.toml",
        "pom.xml",
        "package.json",
        "pubspec.yaml",
    }

    for scan_dir in (scan_dirs or []):
        if not scan_dir or not os.path.exists(scan_dir):
            continue
        for root, dirs, files in os.walk(scan_dir):
            # Skip heavy dirs
            dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "build", "dist", ".gradle"}]
            for fname in files:
                if fname not in target_files:
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", errors="replace") as f:
                        content = f.read()
                except Exception:
                    continue

                if fname.startswith("build.gradle"):
                    parsed = _parse_gradle(content, fname)
                elif fname == "libs.versions.toml":
                    parsed = _parse_toml(content)
                elif fname == "pom.xml":
                    parsed = _parse_pom(content)
                elif fname == "package.json":
                    parsed = _parse_package_json(content)
                elif fname == "pubspec.yaml":
                    parsed = _parse_pubspec(content)
                else:
                    parsed = []

                for dep in parsed:
                    key = f"{dep['ecosystem']}:{dep['name']}:{dep['version']}"
                    if key not in seen:
                        seen.add(key)
                        all_deps.append(dep)

    return all_deps


# ─── OSV.dev API ──────────────────────────────────────────────────────────────
def _osv_query_batch(deps: list) -> dict:
    """
    POST to /v1/querybatch with up to 1000 queries.
    Returns {idx: [vuln, ...]} mapping.
    """
    queries = []
    for dep in deps:
        q: dict = {"version": dep["version"]}
        if dep["ecosystem"] == "Maven":
            q["package"] = {
                "name":      dep["name"],
                "ecosystem": "Maven",
            }
        else:
            q["package"] = {
                "name":      dep["artifact"],
                "ecosystem": dep["ecosystem"],
            }
        queries.append(q)

    payload = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        OSV_BATCH_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent":   "Cortex-Scanner/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT * 2) as resp:
        body = resp.read(1024 * 1024).decode("utf-8", errors="replace")
    data = json.loads(body)
    results = {}
    for i, item in enumerate(data.get("results", [])):
        vulns = item.get("vulns", [])
        if vulns:
            results[i] = vulns
    return results


def _severity_from_vuln(vuln: dict) -> str:
    """Derive Cortex severity from CVSS or database severity."""
    # Try database_specific severity first
    db_sev = (vuln.get("database_specific") or {}).get("severity", "").lower()
    if db_sev == "critical":
        return "critical"
    if db_sev == "high":
        return "high"
    if db_sev == "moderate":
        return "medium"
    if db_sev == "low":
        return "low"

    # Try severity array
    for sev in (vuln.get("severity") or []):
        score_type = sev.get("type", "")
        score      = sev.get("score", "")
        if "CVSS" in score_type:
            try:
                # CVSS score in score field or parse from vector
                # Try numeric score
                val = float(score)
                if val >= 9.0:   return "critical"
                if val >= 7.0:   return "high"
                if val >= 4.0:   return "medium"
                return "low"
            except ValueError:
                pass

    # Try aliases for well-known CVEs
    for alias in (vuln.get("aliases") or []):
        if alias.startswith("CVE-"):
            return "high"   # default for known CVEs

    return "medium"


def _fixed_version(vuln: dict, ecosystem: str, pkg_name: str) -> str:
    """Extract the first fixed version from affected ranges."""
    for affected in (vuln.get("affected") or []):
        for rng in (affected.get("ranges") or []):
            for event in (rng.get("events") or []):
                if "fixed" in event:
                    return event["fixed"]
    return ""


def _vuln_to_finding(vuln: dict, dep: dict) -> dict:
    """Convert an OSV vuln + dep into a Cortex finding."""
    vuln_id     = vuln.get("id", "OSV-UNKNOWN")
    aliases     = vuln.get("aliases") or []
    cve_ids     = [a for a in aliases if a.startswith("CVE-")]
    cve_str     = cve_ids[0] if cve_ids else vuln_id
    summary     = vuln.get("summary") or vuln.get("details") or f"Vulnerability in {dep['name']}"
    summary     = summary[:200]

    severity    = _severity_from_vuln(vuln)
    fixed       = _fixed_version(vuln, dep["ecosystem"], dep["name"])
    fixed_str   = f" Fixed in: {fixed}." if fixed else " No fix available."

    pkg_display = dep["name"] if dep["name"] else dep["artifact"]
    title       = f"{pkg_display} {dep['version']} — {cve_str}"

    description = (
        f"**{vuln_id}** ({', '.join(aliases[:3]) if aliases else 'no aliases'})\n\n"
        f"{summary}\n\n"
        f"Affected: **{pkg_display} {dep['version']}** ({dep['ecosystem']}).{fixed_str}"
    )
    recommendation = (
        f"Upgrade {pkg_display} to version **{fixed}** or later." if fixed
        else f"No upstream fix available. Monitor {vuln_id} for patches and consider removing this dependency."
    )

    refs = [r.get("url", "") for r in (vuln.get("references") or []) if r.get("url")]

    return {
        # One detector ("known-vulnerable dependency"); the vulnerable package
        # and advisory identity live in `package` / `vuln_id`, not the rule id.
        "rule_id":        "osv_vulnerable_dependency",
        "title":          title,
        "severity":       severity,
        "category":       "Supply Chain / Dependencies",
        "description":    description,
        "recommendation": recommendation,
        "cve":            cve_str,
        "vuln_id":        vuln_id,
        "aliases":        aliases,
        "fixed_version":  fixed,
        "package":        pkg_display,
        "version":        dep["version"],
        "ecosystem":      dep["ecosystem"],
        "source":         "osv",
        "references":     refs[:3],
        "owasp":          "M8",
        "masvs":          "MASVS-CODE-3",
        "confidence":     95,
        "exploitability": 60,
        "validation_status": "detected",
    }


# ─── Public entry point ───────────────────────────────────────────────────────
def scan_dependencies(scan_dirs: list, results: dict) -> dict:
    """
    Extract dependencies from scan_dirs, query OSV.dev for CVEs,
    append findings to results["findings"], store deps in results["dependencies"].

    Returns metrics dict: {dep_count, vuln_count, duration_ms, error}.
    """
    metrics = {"dep_count": 0, "vuln_count": 0, "duration_ms": 0, "error": None}
    t0 = time.perf_counter()

    # Extract
    try:
        deps = extract_dependencies(scan_dirs)
    except Exception as e:
        metrics["error"] = f"extraction error: {e}"
        results["dependencies"] = {"deps": [], "vulnerable": [], "safe": [], "total": 0}
        return metrics

    metrics["dep_count"] = len(deps)

    # Trim to cap
    query_deps = deps[:MAX_DEPS_TO_QUERY]

    # Store all deps regardless of querying
    results["dependencies"] = {
        "deps":       deps,
        "vulnerable": [],
        "safe":       [],
        "total":      len(deps),
        "queried":    len(query_deps),
    }

    if not query_deps:
        metrics["duration_ms"] = int((time.perf_counter() - t0) * 1000)
        return metrics

    # Batch query OSV.dev
    try:
        vuln_map = _osv_query_batch(query_deps)
    except Exception as e:
        metrics["error"] = f"OSV API error: {e}"
        metrics["duration_ms"] = int((time.perf_counter() - t0) * 1000)
        # Still mark all as safe (unqueried)
        results["dependencies"]["safe"] = deps
        return metrics

    vuln_count = 0
    vulnerable_deps = []
    safe_deps = []

    for i, dep in enumerate(query_deps):
        vulns = vuln_map.get(i, [])
        if vulns:
            dep["vulnerabilities"] = [{"id": v.get("id"), "summary": v.get("summary", "")[:100]} for v in vulns[:5]]
            dep["vuln_count"] = len(vulns)
            vulnerable_deps.append(dep)
            for vuln in vulns[:5]:  # cap at 5 CVEs per library
                finding = _vuln_to_finding(vuln, dep)
                results["findings"].append(finding)
                vuln_count += 1
        else:
            dep["vulnerabilities"] = []
            dep["vuln_count"] = 0
            safe_deps.append(dep)

    # Deps beyond cap are unqueried — mark safe (unknown)
    for dep in deps[MAX_DEPS_TO_QUERY:]:
        dep["vulnerabilities"] = []
        dep["vuln_count"] = 0
        dep["unqueried"] = True
        safe_deps.append(dep)

    results["dependencies"]["vulnerable"] = vulnerable_deps
    results["dependencies"]["safe"] = safe_deps
    metrics["vuln_count"]   = vuln_count
    metrics["duration_ms"]  = int((time.perf_counter() - t0) * 1000)
    return metrics

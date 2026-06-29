"""
Repository analysis entry point (Beetle 2.6) — CI/CD Security Intelligence.

Mirrors analyze_apk / analyze_ipa: takes an uploaded repository archive (.zip),
runs the CI/CD Security Intelligence engine over the extracted tree, and runs the
SAME finalize engines every other platform uses (Finding Fusion → Ownership →
Confidence → Evidence → Triage → Attack Chains → Scoring). No separate pipeline.

The extracted tree is persisted under the scan's ``repo/`` subdir so the Source
Explorer (``/files`` + ``/file``) renders the pipeline + source files and
finding → source navigation works.
"""
from __future__ import annotations

import logging
import os
import shutil
import tempfile
import time
import zipfile

from . import cicd_intel
from . import scan_storage
from .common import compute_severity_summary, sort_findings

log = logging.getLogger("cortex.repo_analyzer")

# Repo archives are source, not binaries — keep extraction bounded.
_MAX_FILES = 20000
_MAX_TOTAL_BYTES = 500 * 1024 * 1024
_MAX_MEMBER_BYTES = 5 * 1024 * 1024
_PERSIST_EXTS = {
    ".yml", ".yaml", ".json", ".xml", ".txt", ".sh", ".py", ".js", ".jsx", ".ts",
    ".tsx", ".gradle", ".properties", ".toml", ".cfg", ".ini", ".md", ".tf",
    ".groovy", ".env",
}
_PERSIST_NAMES = {"jenkinsfile", "dockerfile", "makefile"}


def _safe_extract(zip_path: str, dest: str) -> int:
    """Extract a zip with zip-slip + size protection. Returns files extracted."""
    count = 0
    total = 0
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or ".." in name.split("/"):
                continue  # zip-slip attempt — skip
            if info.file_size > _MAX_MEMBER_BYTES:
                continue
            total += info.file_size
            if count >= _MAX_FILES or total > _MAX_TOTAL_BYTES:
                break
            target = os.path.join(dest, *name.split("/"))
            rt = os.path.realpath(target)
            if not rt.startswith(os.path.realpath(dest) + os.sep):
                continue  # containment check
            os.makedirs(os.path.dirname(target), exist_ok=True)
            try:
                with zf.open(info) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
                count += 1
            except Exception:
                continue
    return count


def _persist_repo(src_dir: str, scan_id: str) -> int:
    """Copy pipeline + source text files into ``<scan_root>/repo`` for the viewer."""
    dest_root = scan_storage.ensure_scan_root(scan_id) / "repo"
    copied = 0
    for root, dirs, files in os.walk(src_dir):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "vendor", ".venv", "venv")]
        for fname in files:
            if copied >= _MAX_FILES:
                return copied
            ext = os.path.splitext(fname)[1].lower()
            if ext not in _PERSIST_EXTS and fname.lower() not in _PERSIST_NAMES:
                continue
            sp = os.path.join(root, fname)
            try:
                if os.path.getsize(sp) > _MAX_MEMBER_BYTES:
                    continue
                rel = os.path.relpath(sp, src_dir)
                dp = dest_root / rel
                dp.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(sp, dp)
                copied += 1
            except Exception:
                continue
    return copied


def _repo_name(filename: str) -> str:
    base = os.path.basename(filename or "repository")
    for ext in (".zip", ".tar.gz", ".tgz", ".tar"):
        if base.lower().endswith(ext):
            return base[: -len(ext)]
    return base or "repository"


def analyze_repository(zip_path: str, scan_id: str, filename: str) -> dict:
    """Analyze an uploaded repository archive for CI/CD security weaknesses."""
    started = time.perf_counter()
    repo_name = _repo_name(filename)
    results: dict = {
        "scan_id": scan_id,
        "app_name": repo_name,
        "filename": filename,
        "platform": "cicd",
        "findings": [],
        "secrets": [],
        "suppressed_secrets": [],
        "endpoints": [],
        "app_info": {"package": "", "platform": "cicd", "app_name": repo_name},
        "scan_metrics": {"modules": {}, "summary": {}},
        "decompile_info": {"tools_used": ["repo-extract"], "errors": []},
    }

    tmpdir = tempfile.mkdtemp(prefix=f"cortex_repo_{scan_id[:8]}_")
    try:
        extracted = _safe_extract(zip_path, tmpdir)
        log.info("[%s] repo extracted: %d files", scan_id, extracted)

        scan = cicd_intel.analyze_tree(tmpdir)
        results["findings"] = scan["findings"]
        results["cicd"] = {
            "version": cicd_intel.CICD_INTEL_VERSION,
            "platforms": scan["platforms"],
            "platform_labels": [cicd_intel.PLATFORM_LABELS.get(p, p) for p in scan["platforms"]],
            "pipeline_files": scan["files"],
            "total_findings": len(scan["findings"]),
        }
        results["scan_metrics"]["modules"]["cicd_intel"] = {
            "platforms": scan["platforms"], "findings": len(scan["findings"]),
        }

        # Persist the tree so Source Explorer + finding→source navigation work.
        try:
            results["scan_metrics"]["modules"]["repo_persist"] = {"files": _persist_repo(tmpdir, scan_id)}
        except Exception:
            log.exception("[%s] repo persist failed", scan_id)

        _finalize(results)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    results["scan_metrics"]["summary"]["total_ms"] = int((time.perf_counter() - started) * 1000)
    return results


def _finalize(results: dict) -> None:
    """Run the shared finding pipeline on the CI/CD findings — reuses every engine,
    each guarded so one failure never aborts the scan."""
    app_pkg = ""

    # Finding Fusion — collapse multi-engine duplicates, stamp Detected By.
    try:
        from . import fusion
        fusion.fuse(results, platform="cicd")
    except Exception:
        log.exception("[cicd] fusion failed; falling back to raw findings")

    # Canonical normalization + ownership metadata.
    try:
        from . import finding_model
        finding_model.canonicalize_findings(results["findings"], app_pkg)
    except Exception:
        log.exception("[cicd] canonicalize_findings failed")

    for mod_name in ("ownership", "confidence", "evidence", "triage"):
        try:
            mod = __import__(f"analyzers.{mod_name}", fromlist=[mod_name])
            mod.annotate(results)
        except Exception:
            log.exception("[cicd] %s.annotate failed", mod_name)

    # Attack-chain correlation (best-effort — mobile-oriented, may no-op for CI/CD).
    try:
        from .chain_analyzer import correlate_attack_chains
        correlate_attack_chains(results)
    except Exception:
        log.exception("[cicd] attack-chain correlation skipped")

    try:
        results["findings"] = sort_findings(results["findings"])
    except Exception:
        log.exception("[cicd] sort_findings failed")

    try:
        results["severity_summary"] = compute_severity_summary(results["findings"])
    except Exception:
        results["severity_summary"] = {}

    try:
        from .scoring import calculate_score
        results["score"] = calculate_score(results)
    except Exception:
        log.exception("[cicd] scoring failed; using severity-derived fallback")
        results["score"] = _fallback_score(results.get("severity_summary", {}))


def _fallback_score(sev: dict) -> dict:
    penalty = (sev.get("critical", 0) * 25 + sev.get("high", 0) * 12
               + sev.get("medium", 0) * 5 + sev.get("low", 0) * 1)
    score = max(0, 100 - min(100, penalty))
    grade = ("A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70
             else "D" if score >= 60 else "F")
    return {"score": score, "grade": grade}

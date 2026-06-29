"""
Scan Target abstraction (Beetle 2.6 refinement).

Cleanly separates WHAT is analyzed (the *scan target* / ingestion layer) from HOW
it is analyzed (the shared intelligence engines — Ownership → Evidence →
Confidence → Finding Fusion → Attack Chains → Reports — which every analyzer runs
identically). The pipeline is target-agnostic; only ingestion differs per target.

A :class:`ScanTarget` owns ONLY ingestion concerns for one input type:
  * ``extensions``      — which uploaded file extensions select this target,
  * ``platform``        — the results ``platform`` tag downstream surfaces read,
  * ``needs_decompile`` — whether the (APK-only) decompile prepare step runs,
  * ``analyze``         — the analyzer entry point, called with a uniform
                          ``(file_path, scan_id, filename, artifacts)`` signature.

``main.py`` resolves the target from the uploaded file and drives prepare()/analyze
generically, so adding a future target (Infrastructure-as-Code, AI project, cloud
configuration) is a single registry entry here — NO change to the upload endpoint,
the job runner, or any intelligence engine.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .android_analyzer import analyze_apk
from .ios_analyzer import analyze_ipa
from .repo_analyzer import analyze_repository


@dataclass(frozen=True)
class ScanTarget:
    id: str
    label: str
    platform: str
    extensions: tuple[str, ...]
    needs_decompile: bool
    analyze: Callable[[str, str, str, dict], dict]


# ── Analyzer adapters — map the uniform call to each analyzer's own signature ──
def _android(file_path: str, scan_id: str, filename: str, artifacts: dict) -> dict:
    return analyze_apk(file_path, scan_id, filename,
                       jadx_dir=artifacts.get("jadx_dir"),
                       apktool_dir=artifacts.get("apktool_dir"))


def _ios(file_path: str, scan_id: str, filename: str, artifacts: dict) -> dict:
    return analyze_ipa(file_path, scan_id, filename)


def _repository(file_path: str, scan_id: str, filename: str, artifacts: dict) -> dict:
    return analyze_repository(file_path, scan_id, filename)


# ── Registry — the single source of truth for supported scan targets ─────────
# Future targets plug in here (examples, intentionally NOT enabled yet):
#   ScanTarget("iac", "Infrastructure as Code", "iac", (".zip",), False, _iac)
#   ScanTarget("ai_project", "AI Project", "ai", (".zip",), False, _ai_project)
SCAN_TARGETS: tuple[ScanTarget, ...] = (
    ScanTarget("android", "Android APK", "android", (".apk",), True, _android),
    ScanTarget("ios", "iOS IPA", "ios", (".ipa",), False, _ios),
    ScanTarget("repository", "Repository / ZIP", "cicd", (".zip",), False, _repository),
)

_BY_EXT: dict[str, ScanTarget] = {
    ext: t for t in SCAN_TARGETS for ext in t.extensions
}


def resolve_target(ext_or_filename: str) -> ScanTarget | None:
    """Resolve a scan target from a file extension or filename. Returns None when
    no target accepts it (the caller surfaces a 400 with :func:`accepted_extensions`)."""
    s = (ext_or_filename or "").lower().strip()
    if not s:
        return None
    if "." in s:
        s = "." + s.rsplit(".", 1)[-1]   # filename or ".ext" → ".ext"
    else:
        s = "." + s                       # bare "apk" → ".apk"
    return _BY_EXT.get(s)


def accepted_extensions() -> list[str]:
    """Sorted list of every accepted upload extension across all targets."""
    return sorted(_BY_EXT.keys())

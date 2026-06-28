"""
Evidence Selection Engine — per-file library / ownership classifier (Phase 1.96).

Evidence selection needs to know WHO OWNS each *candidate proof file* — and a single
finding can have candidates in different packages (androidx, com.google, the app).
Rather than build a second SDK signature database, this thin layer REUSES the
Ownership Engine's data-driven fingerprints (``analyzers.ownership``): it classifies
a bare file path by constructing a minimal CanonicalFinding and calling the existing
classifier. AndroidX, Google Play Services, Firebase, OkHttp, Retrofit, Compose,
Kotlin stdlib, BouncyCastle, Apache Commons, Facebook, Cordova, RN, Flutter,
advertising / analytics / crash SDKs, generated code, etc. are therefore all
recognized through ONE catalog — adding an SDK there benefits ownership AND
evidence selection, with no logic duplicated here.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..canonical_finding import CanonicalFinding
from ..ownership import classify as _ownership_classify
from ..ownership.types import OwnerType, OwnershipContext

# Binary string-dump artifacts are never a real source location for an analyst.
_BINARY_DUMP_SUFFIXES = (".dex", ".so", ".dylib", ".arsc", ".odex", ".vdex", ".oat",
                         ".dex.txt", ".so.txt", ".dylib.txt", ".arsc.txt")


@dataclass
class FileClassification:
    """Ownership verdict for one candidate proof file (from the Ownership Engine)."""
    owner_type: str = OwnerType.UNKNOWN
    owner_name: str = ""
    owner_confidence: int = 0
    reason: str = ""
    is_application: bool = False
    is_generated: bool = False
    is_binary_dump: bool = False


def is_binary_dump(path: str) -> bool:
    p = (path or "").replace("\\", "/").lower()
    return p.endswith(_BINARY_DUMP_SUFFIXES)


def classify_file(path: str, ctx: OwnershipContext | None = None) -> FileClassification:
    """Classify a candidate proof file's ownership by reusing the Ownership Engine.

    ``ctx`` carries the app's own package(s)/bundle id so files under the application
    namespace are recognized as Application rather than Unknown.
    """
    res = _ownership_classify(
        CanonicalFinding(title="_evidence_candidate", file_path=path or "",
                         platform=(ctx.platform if ctx else "unknown")),
        ctx,
    )
    return FileClassification(
        owner_type=res.owner_type,
        owner_name=res.owner_name or "",
        owner_confidence=res.owner_confidence or 0,
        reason=res.owner_reason or "",
        is_application=res.owner_type == OwnerType.APPLICATION,
        is_generated=res.owner_type == OwnerType.GENERATED_CODE,
        is_binary_dump=is_binary_dump(path),
    )

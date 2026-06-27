"""
Detection Source registry (Beetle 2.0, Phase 1.9).

Beetle's intelligence pipeline is fed by *detection sources*. Today that is the
Beetle Native analyzers plus, from this phase, the ported APKLeaks pattern engine.
The registry exists so future engines — Semgrep, MobSF modules, YARA, custom
detectors — plug in the SAME way without touching the analyzers or the pipeline:
each implements the small :class:`DetectionSource` protocol and is registered here.

A source does ONE job: given a decompiled tree, return raw detections in Beetle's
existing internal shapes (secret dicts / finding dicts / endpoint strings), tagged
with its own name. It does NOT dedupe across sources, mask, score ownership, or
emit a report — those are the pipeline's responsibility. Cross-source
de-duplication / merging is the fusion layer's job (``fusion.py``), the seam the
upcoming Finding Fusion Engine builds on.

This keeps the architecture honest: ONE canonical finding model, ONE intelligence
pipeline, many pluggable detection sources.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Protocol, runtime_checkable

log = logging.getLogger("cortex.detection_sources")


@dataclass
class SourceResult:
    """What a detection source returns. All fields optional/additive.

    * ``secrets``   — secret dicts (``name``/``value``/``file_path``/``line``/
      ``snippet``/``severity``/``category`` …) destined for ``results["secrets"]``.
    * ``findings``  — finding dicts destined for ``results["findings"]``.
    * ``endpoints`` — URL strings destined for ``results["endpoints"]``.

    Every item is expected to carry ``detected_by`` / ``source`` attribution so the
    fusion layer can union sources on a duplicate instead of dropping one.
    """
    secrets: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)


@runtime_checkable
class DetectionSource(Protocol):
    """The contract every pluggable detection source implements."""

    name: str

    def supports(self, platform: str) -> bool:
        """True if this source runs for the given platform ("android"/"ios")."""
        ...

    def scan(self, source_dirs: list[str], *, platform: str, context: dict | None = None) -> SourceResult:
        """Scan already-decompiled ``source_dirs`` and return raw detections."""
        ...


# ── Registry ─────────────────────────────────────────────────────────────────
_REGISTRY: dict[str, DetectionSource] = {}


def register(source: DetectionSource) -> DetectionSource:
    """Register a detection source (idempotent on ``name``). Returns the source."""
    _REGISTRY[source.name] = source
    log.debug("[detection_sources] registered %s", source.name)
    return source


def sources_for(platform: str) -> list[DetectionSource]:
    """Registered sources that run for ``platform``, registration order."""
    return [s for s in _REGISTRY.values() if _safe_supports(s, platform)]


def get(name: str) -> DetectionSource | None:
    return _REGISTRY.get(name)


def all_sources() -> list[DetectionSource]:
    return list(_REGISTRY.values())


def _safe_supports(source: DetectionSource, platform: str) -> bool:
    try:
        return bool(source.supports(platform))
    except Exception:  # noqa: BLE001 — a misbehaving source must never break a scan
        log.exception("[detection_sources] %s.supports() raised", getattr(source, "name", "?"))
        return False


def run_source(source: DetectionSource, source_dirs: list[str], *,
               platform: str, context: dict | None = None) -> SourceResult:
    """Run one source defensively — never let a source crash the scan."""
    try:
        return source.scan(source_dirs, platform=platform, context=context)
    except Exception:  # noqa: BLE001
        log.exception("[detection_sources] %s.scan() failed; skipping its output",
                      getattr(source, "name", "?"))
        return SourceResult()

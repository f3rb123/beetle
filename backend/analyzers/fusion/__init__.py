"""
Finding Fusion Engine (Beetle 2.0, Phase 1.95).

The central, deterministic, explainable layer that merges detections from MANY
engines (Beetle Native, APKLeaks, and future Semgrep / MobSF / YARA / custom / AI)
into ONE canonical security finding — so the user never sees a duplicate just
because several engines found the same issue.

Public API::

    from analyzers import fusion
    fusion.fuse(results, platform="android")          # the pipeline stage
    fusion.identity.register_alias(engine, rule, cls)  # data-only extensibility

See ``internal/FINDING_FUSION_ENGINE.md`` for architecture and merge strategy.
"""
from __future__ import annotations

from . import conflict, identity
from .config import FUSION_VERSION
from .engine import fuse

__all__ = ["fuse", "identity", "conflict", "FUSION_VERSION"]

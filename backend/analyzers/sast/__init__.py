"""
SAST adapter layer (Beetle 2.0, Phase 2.4).

External SAST engines feed Beetle's ONE canonical pipeline through a thin adapter that
ONLY executes the engine, parses its output, and converts to canonical findings —
exactly the role APKLeaks plays for pattern detection. Semgrep is the first adapter;
the :class:`~.adapter.SastAdapter` contract + the reusable SARIF normalizer let future
engines (CodeQL, other SAST, raw SARIF import) plug in with no pipeline change.

Public API::

    from analyzers.sast import semgrep, SemgrepAdapter, SastAdapter, sarif_to_canonical, config
    semgrep.run_into(results, scan_dirs, platform="android", framework=...)
"""
from __future__ import annotations

from . import config  # noqa: F401
from .adapter import SastAdapter, sarif_to_canonical
from .semgrep_adapter import SEMGREP as semgrep, SemgrepAdapter

__all__ = ["SastAdapter", "SemgrepAdapter", "semgrep", "sarif_to_canonical", "config"]

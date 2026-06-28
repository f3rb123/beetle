"""
Detection Coverage Expansion & Benchmark Engine (Beetle 2.0, Phase 1.98).

Ensures Beetle never misses legitimate findings that mature scanners (MobSF,
APKLeaks) surface, while preserving Beetle's analyst-first experience. It is a
capability CATALOG + BENCHMARK layer, not a second detection engine:

* ``registry`` / ``catalog`` — the machine-readable record of every detection Beetle
  has, plus the genuine gaps this phase closes (new secret patterns wired into the
  unified ``secret_catalog``; new crypto rules in ``code_rules``).
* ``benchmark`` — compare Beetle vs MobSF vs APKLeaks (common / beetle-only /
  missing / duplicate / better-evidence).
* ``corpus`` — regression baselines (DVIA, InsecureShop, OWASP MSTG, …) so coverage
  never silently regresses.

See ``internal/DETECTION_COVERAGE_ENGINE.md``.
"""
from __future__ import annotations

from . import audit, benchmark, catalog, corpus, registry
from .registry import CoverageEntry, all_entries, register, summary

__all__ = [
    "registry", "catalog", "benchmark", "corpus", "audit",
    "CoverageEntry", "register", "all_entries", "summary",
]

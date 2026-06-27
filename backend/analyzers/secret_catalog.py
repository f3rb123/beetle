"""
Unified secret pattern catalog (Beetle 2.0, Phase 1.9).

Before this module Beetle carried independent secret pattern lists in different
files. This is the SINGLE architecture they register into, so secret rules have
one home and adding a rule means contributing to one catalog — not editing N lists.

A *contributor* registers its rules under a ``provenance`` tag:

* ``beetle_native``  — ``evidence_scanner.SECRET_PATTERNS_EVIDENCE`` (the evidence
  scanner's rule set, the one used over the decompiled tree).
* ``apkleaks``       — the ported APKLeaks catalog (``detection_sources.apkleaks_patterns``).

APKLeaks is therefore *a contributor to the unified catalog*, not a parallel
catalog. ``combined()`` returns native + apkleaks rules in one list, each carrying
``provenance`` / ``source`` / ``kind`` so a single filesystem walk can apply them
all and the routing layer can split the hits back out by source. Cross-source
de-duplication of the resulting hits is the fusion layer's job.

Note on ``common.SECRET_PATTERNS``: the legacy ``common`` text scanner applies a
richer false-positive filter set (ascii-ratio / crypto-prefix / UI-password) inside
``scan_text_for_secrets`` that the regex matcher does not. It is registered here
for visibility (``register_common``) but intentionally still scanned by its own
function to preserve that filtering — folding it into the regex walk would change
its behavior. Collapsing it fully is tracked as follow-up, not done blindly.
"""
from __future__ import annotations

import logging

log = logging.getLogger("cortex.secret_catalog")

# provenance -> {"patterns": [...], "source": "<display name>"}
_CONTRIBUTORS: dict[str, dict] = {}
_REGISTERED_NATIVE = False


def register(provenance: str, patterns: list[dict], *, source: str) -> None:
    """Register a contributor's rules under ``provenance`` (idempotent)."""
    _CONTRIBUTORS[provenance] = {"patterns": list(patterns or []), "source": source}
    log.debug("[secret_catalog] registered %s (%d rules)", provenance, len(patterns or []))


def _normalized(pat: dict, provenance: str, source: str) -> dict:
    """Return a copy of ``pat`` guaranteed to carry routing/provenance metadata.

    Never mutates the contributor's original dict (so a contributor list can be
    re-registered safely). Missing fields get safe defaults; ``kind`` defaults to
    ``"secret"`` so a legacy native rule routes as a secret exactly as today.
    """
    out = dict(pat)
    out.setdefault("kind", "secret")
    out["provenance"] = provenance
    out.setdefault("source", source)
    out.setdefault("redact_context", False)
    return out


def _ensure_native() -> None:
    """Lazily register the native + apkleaks contributors (forces their import)."""
    global _REGISTERED_NATIVE
    if _REGISTERED_NATIVE:
        return
    try:
        from .evidence_scanner import SECRET_PATTERNS_EVIDENCE
        register("beetle_native", SECRET_PATTERNS_EVIDENCE, source="Beetle Native")
    except Exception:
        log.exception("[secret_catalog] failed to register beetle_native patterns")
    try:
        from .detection_sources.apkleaks_patterns import APKLEAKS_PATTERNS
        register("apkleaks", APKLEAKS_PATTERNS, source="APKLeaks")
    except Exception:
        log.exception("[secret_catalog] failed to register apkleaks patterns")
    _REGISTERED_NATIVE = True


def patterns(*provenances: str) -> list[dict]:
    """Return normalized rules for the given provenances (all if none given)."""
    _ensure_native()
    wanted = provenances or tuple(_CONTRIBUTORS.keys())
    out: list[dict] = []
    for prov in wanted:
        c = _CONTRIBUTORS.get(prov)
        if not c:
            continue
        out.extend(_normalized(p, prov, c["source"]) for p in c["patterns"])
    return out


def combined() -> list[dict]:
    """Native + APKLeaks rules in one list for a single combined walk.

    Native rules come first so that, on an exact value collision, the native hit
    is produced first; provenance-aware dedup keeps the APKLeaks hit too, and the
    fusion layer merges them into ONE finding attributed to both.
    """
    return patterns("beetle_native", "apkleaks")


def provenance_summary() -> dict:
    """{provenance: rule_count} — for diagnostics/tests."""
    _ensure_native()
    return {prov: len(c["patterns"]) for prov, c in _CONTRIBUTORS.items()}

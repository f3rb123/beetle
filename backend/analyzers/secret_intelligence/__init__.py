"""
Secret Intelligence Engine (Beetle 2.0, Phase 1.4).

A deterministic, explainable, multi-stage validator that decides whether a
detected value is *actually* a secret — not merely something that matches a
regex. It enriches each detected secret with type/provider classification,
per-dimension confidence, deterministic validation (format / structure /
checksum / entropy), false-positive detection, environment classification and a
final status (Validated/Probable/Possible/False Positive/Documentation Example/
Public Value/Generated Constant/Unknown).

It ONLY improves detection quality: no suppression, no severity changes, no UI or
report changes. All constants live in `config.py`; type/format data in
`patterns.py` — both extensible without touching engine logic.

Public API:
    from analyzers.secret_intelligence import (
        assess, annotate, get_engine,
        SecretIntelligenceEngine, SecretAssessment, Status, SECRET_INTEL_VERSION,
    )
"""
from .config import SECRET_INTEL_VERSION, Status
from .engine import (
    SecretAssessment,
    SecretIntelligenceEngine,
    annotate,
    assess,
    get_engine,
)

__all__ = [
    "SecretIntelligenceEngine", "SecretAssessment", "Status",
    "assess", "annotate", "get_engine", "SECRET_INTEL_VERSION",
]

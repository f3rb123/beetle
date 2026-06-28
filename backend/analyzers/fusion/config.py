"""
Finding Fusion Engine — configuration (Beetle 2.0, Phase 1.95).

All tunables for the engine live here so the logic modules stay declarative and
the behavior is auditable in one place. Everything is deterministic.
"""
from __future__ import annotations

FUSION_VERSION = "1.0.0"

# ── Identity / grouping ───────────────────────────────────────────────────────
# Two detections of the SAME logical issue merge when they share a fusion key.
# The key is (issue_class, file, line_bucket[, value_fingerprint]). The line
# bucket tolerates small line drift between engines (e.g. Semgrep vs a regex
# pointing a line apart) WITHOUT merging genuinely separate issues, because the
# issue_class + file already scope the group.
LINE_BUCKET = 3          # lines per bucket; 0 disables line bucketing (exact line)

# ── Fusion score (0-100): corroboration strength of a fused finding ───────────
FUSION_SCORE_BASE        = 50    # a single-engine finding starts here
FUSION_SCORE_PER_ENGINE  = 18    # + per ADDITIONAL independent engine
FUSION_SCORE_EVIDENCE    = 4     # + per distinct evidence location (capped)
FUSION_SCORE_EVIDENCE_CAP = 16   # cap on the evidence contribution
FUSION_SCORE_CONFLICT_PENALTY = 15  # − when engines disagree on core metadata
FUSION_SCORE_MAX         = 100

# ── Conflict resolution precedence ────────────────────────────────────────────
# Severity is resolved by rank (handled via canonical severity_rank — highest
# wins). Category ties are broken by this precedence (earlier = stronger), so a
# fused finding adopts the most security-meaningful category deterministically.
CATEGORY_PRECEDENCE = (
    "private key", "cloud credentials", "payment credentials", "credentials",
    "api token", "api key", "secrets", "secret", "authentication",
    "cryptographic key", "cryptography", "injection", "command execution",
    "webview", "network security", "insecure storage", "data storage",
    "configuration", "manifest", "permissions", "privacy", "analytics",
    "information disclosure", "other",
)

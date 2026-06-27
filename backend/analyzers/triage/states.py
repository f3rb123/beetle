"""
Triage Engine — state vocabulary (Beetle 2.0, Phase 1.6).

Two related vocabularies:
  * `Decision`   — the explainable triage classification a rule assigns.
  * `Visibility` — the actionable recommendation (Show/Highlight/Review/Hidden).

Reports and the UI act on `Visibility`; `Decision` explains *why*. Nothing is
deleted — `HiddenByDefault` means "kept, hidden until the analyst opts in".
"""
from __future__ import annotations

TRIAGE_VERSION = "1.0.0"


class Decision:
    """The triage classification (extensible — add states without engine changes)."""
    SHOW = "Show"
    HIGHLIGHT = "Highlight"
    REVIEW = "Review"
    SUPPRESS = "Suppress"                  # explicit suppression (future policies)
    HIDDEN_BY_DEFAULT = "HiddenByDefault"
    FRAMEWORK_NOISE = "FrameworkNoise"
    SDK_NOISE = "SDKNoise"
    DOCUMENTATION = "Documentation"
    GENERATED_CODE = "GeneratedCode"
    FALSE_POSITIVE = "FalsePositive"
    NEEDS_HUMAN_REVIEW = "NeedsHumanReview"
    UNKNOWN = "Unknown"


class Visibility:
    """What a consumer should do with the finding by default."""
    SHOW = "Show"
    HIGHLIGHT = "Highlight"
    REVIEW = "Review"
    HIDDEN_BY_DEFAULT = "HiddenByDefault"


# Decision → default visibility. Classification states that mean "noise / not a
# real concern" map to HiddenByDefault; the rest stay visible.
DECISION_VISIBILITY = {
    Decision.HIGHLIGHT: Visibility.HIGHLIGHT,
    Decision.SHOW: Visibility.SHOW,
    Decision.REVIEW: Visibility.REVIEW,
    Decision.SUPPRESS: Visibility.HIDDEN_BY_DEFAULT,
    Decision.HIDDEN_BY_DEFAULT: Visibility.HIDDEN_BY_DEFAULT,
    Decision.FRAMEWORK_NOISE: Visibility.HIDDEN_BY_DEFAULT,
    Decision.SDK_NOISE: Visibility.HIDDEN_BY_DEFAULT,
    Decision.DOCUMENTATION: Visibility.HIDDEN_BY_DEFAULT,
    Decision.GENERATED_CODE: Visibility.HIDDEN_BY_DEFAULT,
    Decision.FALSE_POSITIVE: Visibility.HIDDEN_BY_DEFAULT,
    Decision.NEEDS_HUMAN_REVIEW: Visibility.REVIEW,
    Decision.UNKNOWN: Visibility.REVIEW,
}

# Secret statuses (Phase 1.4) that mean "not a real, live secret".
REJECT_SECRET_STATUSES = frozenset((
    "False Positive", "Documentation Example", "Public Value", "Generated Constant",
))
REAL_SECRET_STATUSES = frozenset(("Validated Secret", "Probable Secret", "Possible Secret"))

# Evidence qualities (Phase 1.5) considered weak enough to permit noise triage.
WEAK_QUALITIES = frozenset(("Weak", "Moderate", "Missing"))

# Categories that are application security surface — never auto-suppressed when
# app-scoped (the SAFE-BY-DESIGN list).
# NOTE: "secrets" is intentionally NOT here — secret findings are governed by the
# dedicated secret rules (validated/real → visible; FP/doc/generated → hidden), so
# the generic app-security protection must not blanket-protect false-positive
# secrets. "cryptography" stays protected only via app-scoping in the safe rule.
SECURITY_CATEGORIES = frozenset((
    "network security", "certificate", "webview", "deeplinks", "deeplink",
    "permissions", "data storage", "cryptography", "crypto", "authentication",
    "authorization", "attack surface", "components", "component", "code signing",
    "biometric", "privacy",
))

# Categories that are app configuration (manifest-derived), used to app-scope.
APP_CONFIG_CATEGORIES = frozenset((
    "configuration", "manifest", "permissions", "network security",
    "attack surface", "deeplinks", "deeplink", "data storage", "backup", "privacy",
))


def visibility_for(decision: str) -> str:
    return DECISION_VISIBILITY.get(decision, Visibility.REVIEW)

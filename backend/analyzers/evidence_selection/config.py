"""
Evidence Selection Engine — configuration (Beetle 2.0, Phase 1.96).

The full scoring model lives here as DATA so the engine logic stays declarative and
the behavior is auditable and tunable in one place. Quality over quantity: one
excellent, application-owned, reachable proof must out-score ten weak SDK proofs.
"""
from __future__ import annotations

from ..ownership.types import OwnerType

SELECTION_VERSION = "1.0.0"

# ── Ownership / library deltas (the heart of the model) ───────────────────────
# Per-candidate score by who owns the file. Application code is strongly preferred;
# AndroidX / Google Play Services / frameworks / generated code are pushed down.
# Keyed on OwnerType; AndroidX is split out from generic ThirdPartySDK by name
# (see OWNER_NAME_OVERRIDES) because the brief weights it harder (−40 vs −30).
OWNER_TYPE_POINTS: dict[str, int] = {
    OwnerType.APPLICATION:        40,   # application-owned file
    OwnerType.UNKNOWN:            8,    # possibly obfuscated app code — mild credit
    OwnerType.OPEN_SOURCE_LIBRARY: -25,
    OwnerType.VENDOR_SDK:         -30,
    OwnerType.THIRD_PARTY_SDK:    -30,
    OwnerType.ANDROID_FRAMEWORK:  -30,
    OwnerType.APPLE_FRAMEWORK:    -30,
    OwnerType.GOOGLE_SDK:         -40,   # Google Play Services / Firebase libs
    OwnerType.GENERATED_CODE:     -30,
}

# Name-substring overrides applied on top of OWNER_TYPE_POINTS (case-insensitive),
# for libraries the brief weights distinctly from their generic owner type. Pure
# data — extend freely; the longest-matching entry wins.
OWNER_NAME_OVERRIDES: dict[str, int] = {
    "androidx":               -40,
    "android support":        -40,
    "google play services":   -40,
    "firebase":               -40,
}

# ── Application-relevance bonuses (developer usefulness) ───────────────────────
APP_BUSINESS_LOGIC_BONUS = 20   # app-owned AND carries a real code line/snippet
APP_USER_SOURCE_BONUS    = 10   # decompiled app source (not a resource/binary)

# ── Finding-level corroboration signals ───────────────────────────────────────
VALIDATED_BONUS          = 30   # finding is live-validated
REACHABLE_BONUS          = 25   # reachability == YES
REACHABLE_MAYBE_BONUS    = 8    # reachability == MAYBE
ATTACK_CHAIN_BONUS       = 20   # finding participates in an attack chain
MULTI_ENGINE_FILE_BONUS  = 15   # this file corroborated by >1 detection engine
PER_EXTRA_ENGINE         = 0    # (reserved) additional per-engine credit

# ── De-noise penalties ────────────────────────────────────────────────────────
DEAD_CODE_PENALTY        = -20  # app-owned but provably unreachable (heuristic)
ALREADY_SELECTED_PENALTY = -25  # this exact (file,line) is another finding's primary
BINARY_DUMP_PENALTY      = -15  # evidence points at a *.dex/.so string dump

# ── Selection thresholds ──────────────────────────────────────────────────────
# A candidate scoring below this is "rejected" (kept for transparency, not shown as
# proof) UNLESS it is the only candidate — a finding always keeps one primary.
REJECT_BELOW = 0
# Supporting evidence cap so reports stay focused (extra candidates still recorded
# under scored_candidates / rejected).
MAX_SUPPORTING = 4

# ── Bug Bounty Mode ───────────────────────────────────────────────────────────
# When enabled, sharpen toward reportable, exploitable, application-owned proof:
# third-party/framework/generated penalties are amplified and reachability counts
# for more. Applied as MULTIPLIERS/extra deltas on top of the base model.
BUG_BOUNTY_NONAPP_MULTIPLIER = 1.5   # multiply negative owner deltas for non-app code
BUG_BOUNTY_REACHABLE_BONUS   = 15    # extra on top of REACHABLE_BONUS when reachable
BUG_BOUNTY_UNREACHABLE_PENALTY = -20  # reachability == NO is a real liability here

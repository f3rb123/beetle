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

# Manifest declaration is the authoritative proof for manifest-derived findings
# (exported components, permissions, deep links, network-security config). Policy:
# "manifest findings ALWAYS prefer AndroidManifest.xml" — so the bonus is set high
# enough that the manifest outranks even an application source candidate for these
# findings. File-scope so it drives selection.
MANIFEST_DECLARATION_BONUS = 80
# Filenames treated as the security manifest/config of record, per platform.
MANIFEST_FILENAMES = ("androidmanifest.xml", "info.plist")
# A finding is "manifest-derived" when its evidence_type is manifest, a candidate is
# already the manifest, or its category is a DECLARATION-only category below. Kept
# strict on purpose: ambiguous categories like "Network Security"/"Configuration"
# span both manifest config AND code (e.g. a TrustManager), so they are NOT auto-
# treated as manifest unless evidence_type=="manifest" or a manifest candidate
# exists. Data — extend with declaration-only categories only.
MANIFEST_CATEGORIES = (
    "permissions", "permission", "deeplinks", "deep links",
    "exported component", "exported components", "components", "component",
    "manifest", "backup", "debuggable", "task affinity",
)

# XML-aware manifest snippet selection: map a finding (by title keyword) to the
# EXACT manifest attribute it triggers, so the snippet shows e.g.
# android:debuggable="true" — not a nearby unrelated attribute. (keyword, attr,
# default_value). Order matters: first keyword found in the title wins.
MANIFEST_FINDING_ATTRS = (
    ("debuggable", "debuggable", "true"),
    ("cleartext", "usesCleartextTraffic", "true"),
    ("allowbackup", "allowBackup", "true"),
    ("backup", "allowBackup", "true"),
    ("legacy external storage", "requestLegacyExternalStorage", "true"),
    ("legacy storage", "requestLegacyExternalStorage", "true"),
    ("test only", "testOnly", "true"),
    ("testonly", "testOnly", "true"),
    ("task affinity", "taskAffinity", None),
    ("taskaffinity", "taskAffinity", None),
    ("network security config", "networkSecurityConfig", None),
    ("network security configuration", "networkSecurityConfig", None),
    ("profileable", "profileable", "true"),
    ("exported", "exported", "true"),
)

# Manifest attributes worth surfacing as the focused evidence snippet (security-
# relevant). Benign attributes (label/icon/theme/name) are dropped. Data-driven.
SECURITY_MANIFEST_ATTRS = (
    "debuggable", "usescleartexttraffic", "allowbackup", "exported", "testonly",
    "networksecurityconfig", "requestlegacyexternalstorage", "shareduserid",
    "taskaffinity", "launchmode", "granturipermissions",
    "protectionlevel", "permission", "readpermission", "writepermission",
    "host", "scheme", "path", "pathprefix", "pathpattern", "mimetype",
    "profileable", "extractnativelibs", "directbootaware",
)

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

# ── Snippet quality & code relevance (Phase 1.96 — snippet quality) ───────────
# Selecting the right proof FILE is only half of report quality; among candidates in
# the SAME file (different lines) the one whose snippet actually shows the triggering
# code must win. These are FILE-scope but deliberately SMALL — they reorder candidates
# without ever rejecting application code (app base +40 ≫ these), honoring the spec's
# "reject weak-relevance evidence UNLESS there is no better alternative".
SNIPPET_BLANK_PENALTY        = -4   # no code snippet captured at this location
SNIPPET_IMPORT_ONLY_PENALTY  = -8   # snippet is only imports/package/comments/braces
SNIPPET_METHOD_SIG_BONUS     = 6    # snippet includes the enclosing method signature
SNIPPET_CALL_BONUS           = 5    # snippet shows an API call (usage / call proximity)
SNIPPET_RELEVANT_TOKEN_BONUS = 10   # snippet contains the flagged value / variable / API

# ── Rule specificity (Phase 1.96) ─────────────────────────────────────────────
# Source confidence / rule specificity is a FINDING-wide signal (same for every
# candidate, so it never changes WHICH file wins) that raises the displayed evidence
# score for findings from precise, high-confidence rules. Derived from the detector's
# numeric confidence; specific (non-generic) CWEs add a little more.
RULE_SPECIFICITY_HIGH = 12   # detector confidence >= 90
RULE_SPECIFICITY_MED  = 6    # detector confidence >= 75
RULE_SPECIFICITY_CWE_BONUS = 4   # a specific CWE is present (not a broad umbrella)
# Broad umbrella CWEs that do not, by themselves, indicate a specific rule (mirrors
# the Finding Fusion Engine's broad-CWE list; kept local so this module is standalone).
BROAD_CWES_FOR_SPECIFICITY = frozenset((
    "cwe-200", "cwe-284", "cwe-693", "cwe-664", "cwe-noinfo",
))

# ── Framework suppression (Phase 1.997) ───────────────────────────────────────
# Framework / well-known-library code must almost never become Primary Evidence.
# Ownership already classifies most of these (ThirdPartySDK/GoogleSDK → negative),
# but this is a deterministic, data-driven SECOND gate keyed on the path itself so a
# framework file is deprioritized even when ownership returns Unknown (obfuscated or
# not-yet-fingerprinted). Matched as path segments (case-insensitive). Extend freely.
FRAMEWORK_PATH_PREFIXES = (
    "androidx/", "android/support/", "com/android/support/",
    "com/google/", "com/google/android/material/", "com/google/firebase/",
    "kotlin/", "kotlinx/", "okhttp3/", "okhttp/", "okio/",
    "retrofit2/", "retrofit/", "com/bumptech/glide/", "coil/",
    "androidx/compose/", "com/google/android/gms/", "dagger/", "hilt_aggregated_deps/",
    "io/reactivex/", "com/squareup/", "org/jetbrains/", "scala/",
)
# Applied IN ADDITION to the ownership delta (file-scope). Big enough that no
# framework file outranks an application/manifest proof, regardless of ownership.
FRAMEWORK_PATH_PENALTY = -45

# A LOCALIZED resource string (res/values-<locale>/strings.xml) is a UI translation,
# never the app's detection logic. Penalized hard so a code site or the base resource
# always outranks it as proof (e.g. a root-check finding anchors to the isRooted
# source / su-path string, not a Serbian-Latin Play-Services UI label). Only affects
# RANKING among candidates — never blanks the sole evidence a finding has.
LOCALIZED_RESOURCE_PENALTY = -55

# ── Attack-chain evidence policy (Phase 1.997) ────────────────────────────────
# Chains pick evidence differently: Manifest → app business logic → configuration →
# resources → supporting → framework. These file-scope bonuses (only applied in
# chain mode) bias toward declaration/config evidence the analyst can act on.
CHAIN_MANIFEST_BONUS = 80
CHAIN_CONFIG_BONUS = 22
CHAIN_RESOURCE_BONUS = 14
CHAIN_FRAMEWORK_EXTRA_PENALTY = -20
CONFIG_PATH_HINTS = ("res/xml/", "network_security_config", ".properties", ".cfg",
                     ".conf", ".json", "build.gradle", "strings.xml", "/assets/")
RESOURCE_PATH_HINTS = ("res/values/", "res/raw/", "res/xml/", "/resources/")

# ── Certificate / artifact evidence (Phase 1.997) ─────────────────────────────
# Certificate / signing findings have no Java source — never render "Unknown file".
# Map the finding to the real artifact the analyst should inspect.
ARTIFACT_CATEGORIES = ("certificate", "signing", "code signing", "apk signing")
CERTIFICATE_ARTIFACT = "APK Signing Block"
CERTIFICATE_ARTIFACT_LANG = "Signing Metadata"
# Title keyword → artifact label, so each cert finding names its real evidence.
CERTIFICATE_ARTIFACT_LABELS = (
    ("chain", "Certificate Chain"),
    ("expired", "Signing Certificate"),
    ("self-signed", "Signing Certificate"),
    ("rsa", "Signing Certificate"),
    ("key", "Signing Certificate"),
    ("v1", "APK Signature Block"),
    ("v2", "APK Signature Block"),
    ("v3", "APK Signature Block"),
    ("scheme", "APK Signature Block"),
    ("debug", "Signing Certificate"),
    ("metadata", "APK Metadata"),
)

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

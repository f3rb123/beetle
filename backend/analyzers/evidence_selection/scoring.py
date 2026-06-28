"""
Evidence Selection Engine — scoring model (Beetle 2.0, Phase 1.96).

Every candidate proof file is scored by a list of independent SIGNAL CONTRIBUTORS.
A contributor is a pure function ``(candidate, ctx) -> list[(delta, reason)]``; the
candidate's score is the sum of all deltas and its explanation is the list of
reasons. This is the engine's EXTENSIBILITY SEAM: a future input — AI Reviewer,
runtime analysis, dynamic instrumentation, user feedback, deeper reachability, CVE
correlation — becomes a new contributor registered via :func:`register_contributor`
with NO change to the engine, the model, or the pipeline.

All weights come from ``config.py`` (data, not logic). Reasons are written so they
read as analyst-facing bullet points ("Application-owned", "AndroidX library").
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..ownership.types import OwnerType
from . import config as C
from .library import FileClassification


@dataclass
class Candidate:
    """One candidate proof location for a finding."""
    file_path: str
    line: int = 0
    snippet: str = ""
    source: str = "file_evidence"        # where the candidate came from
    classification: FileClassification = field(default_factory=FileClassification)
    engines: tuple = ()                   # engines that referenced THIS file
    # populated by the engine:
    score: int = 0                        # total (file + finding) — for display/ranking
    file_score: int = 0                   # file-intrinsic only — drives the reject decision
    finding_score: int = 0                # finding-level corroboration (same for all candidates)
    reasons: list = field(default_factory=list)       # selected-because bullets
    penalties: list = field(default_factory=list)     # rejected-because bullets


@dataclass
class SelectionContext:
    """Finding-level signals + cross-finding state shared by all contributors."""
    bug_bounty: bool = False
    reachability: str = ""               # "YES" | "MAYBE" | "NO" | ""
    in_attack_chain: bool = False
    validated: bool = False
    detection_count: int = 1
    already_selected: set = field(default_factory=set)  # (file, line) primaries elsewhere
    file_engine_counts: dict = field(default_factory=dict)  # file -> #engines referencing it


# A contributor returns a list of (delta, reason) pairs.
Contributor = Callable[[Candidate, SelectionContext], list]

# Scope decides whether a contributor's deltas describe the FILE itself ("file" —
# ownership, generated, binary-dump: these gate the reject decision) or the FINDING
# ("finding" — reachability, attack-chain, validation: corroboration that applies
# equally to every candidate and must not rescue a library file from rejection).
FILE_SCOPE = "file"
FINDING_SCOPE = "finding"

_CONTRIBUTORS: list[tuple[Contributor, str]] = []


def register_contributor(fn: Contributor, *, scope: str = FINDING_SCOPE) -> Contributor:
    """Register a scoring contributor (future AI/runtime/CVE/feedback inputs).

    ``scope`` defaults to ``"finding"`` (additive corroboration that never rescues a
    non-application file from rejection); pass ``scope="file"`` for a contributor
    whose verdict is intrinsic to the file and should affect ranking/rejection.
    """
    _CONTRIBUTORS.append((fn, scope))
    return fn


def contributors() -> list[tuple[Contributor, str]]:
    return list(_CONTRIBUTORS)


# ── Built-in contributors ─────────────────────────────────────────────────────
def _ownership_signal(c: Candidate, ctx: SelectionContext) -> list:
    cl = c.classification
    out: list = []
    base = C.OWNER_TYPE_POINTS.get(cl.owner_type, 0)
    # Name override (e.g. AndroidX / GMS / Firebase weighted harder than generic SDK).
    name = (cl.owner_name or "").lower()
    override = None
    for needle, pts in C.OWNER_NAME_OVERRIDES.items():
        if needle in name:
            override = pts if override is None else min(override, pts)
    delta = override if override is not None else base
    if ctx.bug_bounty and delta < 0:
        delta = int(round(delta * C.BUG_BOUNTY_NONAPP_MULTIPLIER))
    if cl.owner_type == OwnerType.APPLICATION:
        out.append((delta, "Application-owned"))
    elif cl.is_generated:
        out.append((delta, "Generated code"))
    elif cl.owner_type == OwnerType.UNKNOWN:
        out.append((delta, "Unattributed code (possibly app)"))
    else:
        label = cl.owner_name or cl.owner_type
        out.append((delta, f"{label} library/framework"))
    return out


def _app_relevance_signal(c: Candidate, ctx: SelectionContext) -> list:
    cl = c.classification
    out: list = []
    if cl.is_application and not cl.is_generated:
        if c.line and c.snippet:
            out.append((C.APP_BUSINESS_LOGIC_BONUS, "Application business logic with a concrete code line"))
        if not cl.is_binary_dump:
            out.append((C.APP_USER_SOURCE_BONUS, "Developer source code"))
    return out


def _validation_signal(c: Candidate, ctx: SelectionContext) -> list:
    return [(C.VALIDATED_BONUS, "Finding is validated")] if ctx.validated else []


def _reachability_signal(c: Candidate, ctx: SelectionContext) -> list:
    out: list = []
    r = (ctx.reachability or "").upper()
    if r == "YES":
        out.append((C.REACHABLE_BONUS, "Reachable from an entry point"))
        if ctx.bug_bounty:
            out.append((C.BUG_BOUNTY_REACHABLE_BONUS, "Bug-bounty: reachable & exploitable"))
    elif r == "MAYBE":
        out.append((C.REACHABLE_MAYBE_BONUS, "Possibly reachable"))
    elif r == "NO":
        if ctx.bug_bounty:
            out.append((C.BUG_BOUNTY_UNREACHABLE_PENALTY, "Bug-bounty: not reachable"))
        # app-owned + unreachable = likely dead code (heuristic).
        if c.classification.is_application:
            out.append((C.DEAD_CODE_PENALTY, "Application code but unreachable (likely dead code)"))
    return out


def _attack_chain_signal(c: Candidate, ctx: SelectionContext) -> list:
    return [(C.ATTACK_CHAIN_BONUS, "Referenced by an attack chain")] if ctx.in_attack_chain else []


def _multi_engine_file_signal(c: Candidate, ctx: SelectionContext) -> list:
    n = ctx.file_engine_counts.get(c.file_path, len(c.engines))
    return [(C.MULTI_ENGINE_FILE_BONUS, f"Corroborated by {n} detection engines")] if n >= 2 else []


def _already_selected_signal(c: Candidate, ctx: SelectionContext) -> list:
    return [(C.ALREADY_SELECTED_PENALTY, "Already shown as another finding's primary proof")] \
        if (c.file_path, c.line) in ctx.already_selected else []


def _binary_dump_signal(c: Candidate, ctx: SelectionContext) -> list:
    return [(C.BINARY_DUMP_PENALTY, "Points at a binary string-dump, not source")] \
        if c.classification.is_binary_dump else []


# Built-ins. Registration order is irrelevant (deltas sum); kept logical so the
# reason bullets read in a sensible sequence. File-scope signals are intrinsic to
# the candidate file; finding-scope signals are finding-wide corroboration.
_BUILTIN_CONTRIBUTORS = (
    (_ownership_signal, FILE_SCOPE),
    (_app_relevance_signal, FILE_SCOPE),
    (_multi_engine_file_signal, FILE_SCOPE),
    (_already_selected_signal, FILE_SCOPE),
    (_binary_dump_signal, FILE_SCOPE),
    (_validation_signal, FINDING_SCOPE),
    (_reachability_signal, FINDING_SCOPE),
    (_attack_chain_signal, FINDING_SCOPE),
)
for _fn, _scope in _BUILTIN_CONTRIBUTORS:
    register_contributor(_fn, scope=_scope)


def score(candidate: Candidate, ctx: SelectionContext) -> Candidate:
    """Run every contributor, summing deltas (split by scope) and collecting reasons.

    ``file_score`` (file-intrinsic) drives ranking and the reject decision so a
    library/framework file is never rescued by finding-wide corroboration;
    ``score`` is the total shown to the analyst.
    """
    file_total = finding_total = 0
    reasons: list = []
    penalties: list = []
    for fn, scope in _CONTRIBUTORS:
        try:
            for delta, reason in fn(candidate, ctx) or []:
                if scope == FILE_SCOPE:
                    file_total += delta
                else:
                    finding_total += delta
                (reasons if delta >= 0 else penalties).append(reason)
        except Exception:  # noqa: BLE001 — a contributor must never break selection
            continue
    candidate.file_score = file_total
    candidate.finding_score = finding_total
    candidate.score = file_total + finding_total
    candidate.reasons = reasons
    candidate.penalties = penalties
    return candidate

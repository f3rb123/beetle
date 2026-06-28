"""
Finding Fusion Engine — semantic identity (Beetle 2.0, Phase 1.95).

The whole point of fusion is to recognize that two engines describing the SAME
logical issue are the same finding, even when they used different rule ids, titles
or pointed a line apart. This module derives a *semantic* identity for a finding
that is independent of which engine produced it, so grouping is by MEANING, not by
an engine-specific rule string.

A finding's fusion key is::

    (issue_class, file, line_bucket[, value_fingerprint])

* ``issue_class`` — what KIND of issue it is, normalized across engines. Resolved
  from (in priority order): an explicit alias-registry entry for this engine+rule,
  the CWE id, then a normalized category/title. CWE is the strongest cross-engine
  signal — Beetle "AWS Access Key ID" and a future Semgrep "hardcoded-aws-key"
  both carry CWE-798, so they land in one class.
* ``file`` / ``line_bucket`` — WHERE it is, with small line drift tolerated.
* ``value_fingerprint`` — for value-bearing findings (secrets), a fingerprint of
  the literal so two DIFFERENT secrets in the same file never collapse together.

Extensibility: a new detection engine merges correctly without code changes —
it only needs to emit findings carrying CWE (preferred) or a category/title. When
an engine uses an idiosyncratic rule name that should map to a known class, add a
data-only entry via :func:`register_alias` (or ``ALIAS_REGISTRY``) — no engine,
analyzer or pipeline code changes.
"""
from __future__ import annotations

import hashlib
import re

from . import config as C

# ── Extensible alias registry ─────────────────────────────────────────────────
# (engine_lower, rule_id_lower) -> canonical issue class. Pure data; extend freely.
# Empty by default: CWE + normalized title already unify the engines we ship. This
# exists so an engine whose rule name does NOT share a CWE/title with an existing
# rule can still be declared equivalent without touching logic.
ALIAS_REGISTRY: dict[tuple[str, str], str] = {}


def register_alias(engine: str, rule_id: str, canonical_class: str) -> None:
    """Declare that ``engine``'s ``rule_id`` is the given canonical issue class."""
    ALIAS_REGISTRY[(str(engine).strip().lower(), str(rule_id).strip().lower())] = \
        canonical_class.strip().lower()


_WS = re.compile(r"\s+")
_NONALNUM = re.compile(r"[^a-z0-9]+")
# Trailing engine/qualifier noise stripped from titles so "AWS Access Key ID
# (APKLeaks rule)" and "AWS Access Key ID" normalize identically.
_TITLE_NOISE = re.compile(
    r"\s*(\(apkleaks[^)]*\)|\(beetle[^)]*\)|\(semgrep[^)]*\)|\bdetected\b|\bfound\b)\s*",
    re.IGNORECASE,
)


def _norm(text: str) -> str:
    return _WS.sub(" ", (text or "").strip().lower())


def _norm_title(title: str) -> str:
    t = _TITLE_NOISE.sub(" ", title or "")
    return _NONALNUM.sub("-", _norm(t)).strip("-")


def _norm_cwe(cwe) -> str:
    """Normalize a CWE field (str or list) to e.g. 'cwe-798'. '' if absent."""
    if isinstance(cwe, (list, tuple)):
        cwe = cwe[0] if cwe else ""
    s = _norm(str(cwe or ""))
    if not s:
        return ""
    m = re.search(r"cwe[-\s]?(\d+)", s)
    return f"cwe-{m.group(1)}" if m else ""


def _norm_file(path) -> str:
    return _norm(str(path or "")).replace("\\", "/")


def issue_class(f: dict) -> str:
    """Engine-independent class of the issue this finding describes."""
    engine = ""
    db = f.get("detected_by") or []
    if isinstance(db, list) and db:
        engine = str(db[0])
    engine = engine or str(f.get("source") or f.get("source_module") or "")
    rule = str(f.get("rule_id") or f.get("id") or f.get("name") or f.get("title") or "")
    alias = ALIAS_REGISTRY.get((engine.strip().lower(), rule.strip().lower()))
    if alias:
        return alias
    cwe = _norm_cwe(f.get("cwe"))
    if cwe:
        # A broad umbrella CWE is shared by many distinct rules, so the CWE alone
        # would over-merge genuinely different findings (and drop one). For those,
        # also key on the normalized title — but ONLY when no value fingerprint is
        # present (a secret's literal already keeps distinct values apart, and two
        # engines naming the same secret differently must still merge on CWE+value).
        if cwe in C.BROAD_CWES and not _value_fingerprint(f):
            t = _norm_title(f.get("title") or f.get("name") or f.get("rule_id") or "")
            return f"{cwe}:{t}" if t else cwe
        return cwe
    cat = _norm_title(f.get("category") or "")
    title = _norm_title(f.get("title") or f.get("name") or f.get("rule_id") or "")
    # Category + title is more specific than either alone and stable across engines
    # that share neither a CWE nor a rule id but describe the same class.
    return f"{cat}:{title}" if cat else (title or "unclassified")


def _value_fingerprint(f: dict) -> str:
    """Stable short fingerprint of a value-bearing finding's literal, else ''.

    Lets two engines on the SAME secret literal merge while keeping two DIFFERENT
    secrets in the same file apart. Uses masked_value when present (post-masking),
    else value; ignores trivially short values.
    """
    val = str(f.get("masked_value") or f.get("value") or "")
    val = _norm(val)
    if len(val) < 6:
        return ""
    return hashlib.sha1(val.encode("utf-8", "replace")).hexdigest()[:10]


def _line_bucket(f: dict) -> int:
    line = f.get("line")
    if line in (None, ""):
        line = f.get("line_number")
    try:
        line = int(line or 0)
    except (TypeError, ValueError):
        line = 0
    if line <= 0 or C.LINE_BUCKET <= 0:
        return line if line > 0 else 0
    return (line - 1) // C.LINE_BUCKET


def fusion_key(f: dict) -> tuple:
    """The semantic grouping key. Findings sharing it are the same logical issue."""
    return (issue_class(f), _norm_file(f.get("file_path") or f.get("file")),
            _line_bucket(f), _value_fingerprint(f))

"""
Regex necessary-literal prefilter (v1.3 stabilization).

The hot analyzers (secrets, SAST, API behaviour, strings) each run large
pattern catalogs over ~15,000 decompiled files. Profiling shows nearly all of
that time is the regex engine scanning files that cannot possibly match: most
patterns contain literals ("AKIA", "sk_live_", "PendingIntent.") that MUST
appear in any match, and most files don't contain them.

This module derives, from the parsed regex structure itself, a set of
case-folded literals such that ANY case-insensitive match must contain at least
one of them. A C-speed substring test against the casefolded file content then
skips the regex entirely when no literal is present.

Safety model — detections are identical BY CONSTRUCTION:

* Literal extraction walks the ``re`` parse tree and only collects runs that
  are provably mandatory (top-level sequence literals, groups/repeats with
  min >= 1, and alternations where EVERY branch yields a literal).
* Anything the walker does not fully understand → ``None`` → the caller scans
  unconditionally, exactly as before.
* ``str.casefold()`` is used on both content and literals — the same full
  Unicode casefolding ``re.IGNORECASE`` is built on — so a match can never be
  filtered out by case differences.
"""
from __future__ import annotations

try:  # Python 3.12+: private location; older: top-level module
    from re import _parser as _sre_parse
except ImportError:  # pragma: no cover
    import sre_parse as _sre_parse  # type: ignore

_OPS = _sre_parse

# A lone literal must be reasonably long to be selective ("ac" appears in
# almost every Java file and would make the prefilter pure overhead).
_MIN_SINGLE = 4
# In an any-of set every alternative must be at least this long...
_MIN_BRANCH = 3
# ...and huge alternations aren't worth prechecking.
_MAX_BRANCH = 12

_cache: dict[str, tuple[str, ...] | None] = {}


def _walk(seq, lits: list, sets: list) -> None:
    """Collect mandatory literal runs (into `lits`) and mandatory any-of sets
    from alternations (into `sets`) for one parsed sequence."""
    run: list[str] = []

    def flush():
        if run:
            lits.append("".join(run))
            run.clear()

    for op, av in seq:
        name = str(op)
        if name == "LITERAL":
            if 32 <= av < 127:  # printable ASCII only — anything else ends the run
                run.append(chr(av).casefold())
            else:
                flush()
        elif name == "AT":  # zero-width anchor (\b, ^, $) splits runs
            flush()
        elif name == "SUBPATTERN":
            flush()
            _walk(av[3], lits, sets)
        elif name == "ATOMIC_GROUP":
            flush()
            _walk(av, lits, sets)
        elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            flush()
            lo = av[0]
            if isinstance(lo, int) and lo >= 1:  # repeated at least once → mandatory
                _walk(av[2], lits, sets)
        elif name == "BRANCH":
            # The parser factors common prefixes out of alternations
            # ("password|passwd|pwd" parses as 'p' + (assword|asswd|wd)), so
            # re-attach the literal run preceding the branch to each
            # alternative's literal PREFIX to recover the full alternatives.
            preceding = "".join(run)
            flush()
            alts, prefixes, ok = [], [], True
            for alt in av[1]:
                sub_lits: list = []
                _walk(alt, sub_lits, [])  # nested sets are ignored (conservative)
                best = max(sub_lits, key=len, default="")
                if not best:
                    ok = False
                    break
                alts.append(best)
                prefixes.append(_prefix_run(alt))
            if ok and alts:
                if preceding and all(prefixes):
                    sets.append(tuple(preceding + p for p in prefixes))
                sets.append(tuple(alts))
        else:
            # IN, ANY, NOT_LITERAL, CATEGORY, GROUPREF, ASSERT(_NOT), ... —
            # contributes nothing provable; just breaks the current run.
            flush()
    flush()


def _prefix_run(seq) -> str:
    """The literal run at the very START of a parsed sequence ('' if none)."""
    out: list[str] = []
    for op, av in seq:
        if str(op) == "LITERAL" and 32 <= av < 127:
            out.append(chr(av).casefold())
        else:
            break
    return "".join(out)


def _selective(lit: str) -> bool:
    """Long enough to skip most files: 4+ chars, or 3 with a symbol ('sk-')."""
    return len(lit) >= _MIN_SINGLE or (
        len(lit) == 3 and any(not c.isalnum() for c in lit))


def necessary_literals(pattern: str) -> tuple[str, ...] | None:
    """Casefolded literals such that any IGNORECASE match of ``pattern``
    contains at least one, or ``None`` when no safe set can be derived."""
    try:
        seq = _sre_parse.parse(pattern)
    except Exception:
        return None
    lits: list[str] = []
    sets: list[tuple[str, ...]] = []
    try:
        _walk(seq, lits, sets)
    except Exception:  # unknown parse node shape on a future Python — no filter
        return None
    best = max(lits, key=len, default="")
    if _selective(best):
        return (best,)
    # Prefer the longest-alternative set (prefix-recombined sets come first
    # and are strictly more selective than their factored counterparts).
    for s in sorted(sets, key=lambda s: -min(len(a) for a in s)):
        if len(s) <= _MAX_BRANCH and all(len(a) >= _MIN_BRANCH for a in s):
            return tuple(dict.fromkeys(s))  # dedup, keep order
    return None


def anchors_for(pattern: str) -> tuple[str, ...] | None:
    """Cached :func:`necessary_literals`."""
    if pattern not in _cache:
        _cache[pattern] = necessary_literals(pattern)
    return _cache[pattern]


def fold(content: str) -> str:
    """The content key anchors are tested against (full Unicode casefold)."""
    return content.casefold()


def may_match(pattern: str, folded_content: str) -> bool:
    """False only when ``pattern`` provably cannot match the file whose
    casefolded content is ``folded_content``."""
    anchors = anchors_for(pattern)
    if anchors is None:
        return True
    return any(a in folded_content for a in anchors)

"""
Evidence Selection Engine — snippet quality analysis (Beetle 2.0, Phase 1.96).

Selecting the right proof FILE is only half of report quality; the proof SNIPPET
must also show the analyst the actual code that triggered the finding — not a block
of imports, a lone brace, or an unrelated line. This module is the small, pure,
deterministic toolkit the scoring contributors and the engine use to:

* recognize a weak snippet (imports/package/comments/braces only, or blank);
* recognize a strong one (carries the enclosing method signature, an API call, or
  the exact flagged value/variable the finding is about);
* derive the finding's "relevant tokens" (the matched value / variable / API) so a
  candidate snippet can be checked for genuine relevance;
* refine a captured snippet to the single most relevant line (dropping import/comment
  noise) when a richer multi-line context is available.

No file I/O, no network — it operates only on text already captured on the finding.
"""
from __future__ import annotations

import re

# A line that is only structural noise — import/package/using, a comment, or a lone
# brace/punctuation. A snippet made entirely of these is not real proof.
_IMPORT_RE = re.compile(r"^\s*(import|package|using|#include|#import|from\s+[\w.]+\s+import)\b", re.I)
_COMMENT_RE = re.compile(r"^\s*(//|/\*|\*/|\*|#|<!--|-->)")
_NOISE_RE = re.compile(r"^\s*[{}()\[\];,<>]*\s*$")

# A method / function declaration (Java / Kotlin / Swift / ObjC / Python-ish): a
# leading modifier/keyword followed by a name + parameter list. Kept conservative so
# it does not fire on a bare call.
_METHOD_SIG_RE = re.compile(
    r"\b(fun|func|void|public|private|protected|internal|override|static|def|"
    r"suspend|operator|final|abstract|[A-Za-z_][\w<>\[\]]*\s+[A-Za-z_]\w*)\s*"
    r"[A-Za-z_]\w*\s*\([^;{]*\)\s*[:{]?", re.I)

# A method / function call — the "API usage / call proximity" signal.
_CALL_RE = re.compile(r"\b[A-Za-z_][\w.]*\s*\(")

# camelCase (an internal lowercase→uppercase transition) marks a code identifier /
# API name in a finding title (e.g. getInstance, loadUrl, MessageDigest), as opposed
# to a plain English word ("Hardcoded", "Crypto").
_CAMEL_RE = re.compile(r"[a-z][A-Z]")


def _nonblank_lines(snippet: str) -> list[str]:
    return [ln for ln in (snippet or "").splitlines() if ln.strip()]


def is_blank(snippet: str) -> bool:
    return not _nonblank_lines(snippet)


def is_import_only(snippet: str) -> bool:
    """True when every non-blank line is an import/package/comment/brace — i.e. the
    snippet shows no actual logic (the classic 'imports only' proof to avoid)."""
    lines = _nonblank_lines(snippet)
    if not lines:
        return False
    return all(_IMPORT_RE.match(ln) or _COMMENT_RE.match(ln) or _NOISE_RE.match(ln)
               for ln in lines)


def has_method_signature(snippet: str) -> bool:
    return bool(_METHOD_SIG_RE.search(snippet or ""))


def has_call(snippet: str) -> bool:
    return bool(_CALL_RE.search(snippet or ""))


def _looks_like_api(tok: str) -> bool:
    """A title token that looks like a code identifier / API, not an English word."""
    return ("." in tok) or bool(_CAMEL_RE.search(tok))


def relevant_tokens(finding: dict) -> set[str]:
    """The concrete tokens a genuine proof snippet for this finding should contain:
    the flagged value / variable, plus API-looking identifiers from the title.

    Returns lower-cased tokens (and the trailing segment of any dotted token, so a
    snippet using ``getInstance(`` matches a ``Cipher.getInstance`` title token)."""
    toks: set[str] = set()

    def _add(v):
        if isinstance(v, str):
            v = v.strip()
            if len(v) >= 3:
                toks.add(v.lower())
                if "." in v:
                    tail = v.rsplit(".", 1)[-1]
                    if len(tail) >= 3:
                        toks.add(tail.lower())

    for key in ("matched_text", "matched_value", "match", "value", "masked_value",
                "variable", "symbol", "sink", "api"):
        _add((finding or {}).get(key))
    for m in re.findall(r"[A-Za-z_][\w.]{3,}", (finding or {}).get("title") or ""):
        if _looks_like_api(m):
            _add(m)
    # Masked secrets ("AKIA****MPLE") shouldn't drive relevance — they won't appear
    # literally in source; drop tokens that are mostly mask characters.
    return {t for t in toks if t.count("*") < max(1, len(t) // 2)}


def contains_tokens(snippet: str, tokens: set[str]) -> bool:
    if not snippet or not tokens:
        return False
    low = snippet.lower()
    return any(t in low for t in tokens)


def _line_quality(line: str, tokens: set[str]) -> int:
    """Rank a single line as proof. Priority: the flagged value/API (strongest) > a
    real API call (the usage site) > a method signature (context) > plain code;
    imports / comments / braces are worthless. A method *declaration* is ranked below
    a real call so the actual triggering call wins over the enclosing signature."""
    s = line.strip()
    if not s or _IMPORT_RE.match(line) or _COMMENT_RE.match(line) or _NOISE_RE.match(line):
        return 0
    if tokens and contains_tokens(line, tokens):
        return 5
    if has_method_signature(line):
        return 2          # the enclosing declaration — useful context, not the call
    if has_call(line):
        return 3          # a genuine API call / usage site
    return 1              # some other real code line


def refine_snippet(context: str, fallback: str, tokens: set[str]) -> str:
    """Pick the single most relevant line from a (possibly multi-line) ``context``.

    Prefers the line that contains the flagged value/API, then an API call, then a
    method signature, then any real code line — never an import/comment/brace line.
    Returns the chosen line (trimmed) or, when nothing better is found, the original
    ``fallback`` unchanged (so we never blank out a snippet)."""
    lines = (context or "").splitlines()
    best, best_q = "", 0
    for ln in lines:
        q = _line_quality(ln, tokens)
        if q > best_q:
            best_q, best = q, ln.strip()
    if best_q >= 1:
        return best[:240]
    return (fallback or "").strip()[:240]

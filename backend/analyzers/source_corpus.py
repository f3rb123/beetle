"""
SourceCorpus — one filesystem traversal, shared reads (Beetle 2.0, Priority 1).

Historically every text analyzer (secrets, IPs, JWTs, endpoints, strings, cloud
config, API/behaviour, SAST, …) independently ``os.walk``-ed the decompiled tree
and re-``open()``-read the same files. On a large APK the jadx/apktool tree was
walked and read 15-20 times — the single biggest scan-time cost.

``SourceCorpus`` fixes that WITHOUT changing what any analyzer detects:

* **walk once** — the exact ``os.walk`` sequence for a directory is computed a
  single time and cached, then replayed to every consumer. Order is preserved,
  so file-cap truncation picks the same files it always did.
* **read once** — file text (and bytes) are decoded a single time, keyed by the
  absolute path, and reused across consumers. A memory budget bounds the cache;
  past the budget reads still succeed, they just aren't retained.

Crucially the corpus applies **no** skip/extension/size policy of its own. Each
analyzer keeps its own filtering and simply iterates ``corpus.walk(dir)`` instead
of ``os.walk(dir)`` and calls ``corpus.read_text(path)`` instead of
``open(path).read()``. Because the yielded triples and returned content are
byte-for-byte what the standard-library calls produced, detections are identical
by construction — the only thing that changes is that the work happens once.

Adoption contract for a consumer:

    def scan(base_dir, extra_dirs=None, *, corpus=None):
        corpus = corpus or SourceCorpus()          # throwaway == today's behavior
        for root, subdirs, files in corpus.walk(scan_dir):
            ...
            content = corpus.read_text(fpath, max_bytes=CAP)
            if content is None:   # over cap / unreadable — same as the old `continue`
                continue

When the orchestrator passes ONE shared corpus to every consumer, all of them
share the single walk + single read. When a consumer is called standalone (unit
tests, ad-hoc callers) it makes its own throwaway corpus and behaves exactly as
it did before this module existed.
"""
from __future__ import annotations

import os
import logging

log = logging.getLogger("cortex.source_corpus")

# Byte → printable-ASCII map: printable bytes pass through, everything else
# becomes a space. Used by the .dex/.so string-dump fallbacks in several
# analyzers; translate+latin-1 is byte-for-byte identical to the historical
# `"".join(chr(b) if 32 <= b < 127 else " " for b in raw)` at ~100x the speed.
_PRINTABLE_TABLE = bytes(i if 32 <= i < 127 else 0x20 for i in range(256))


def printable_text(raw: bytes) -> str:
    """Printable-ASCII view of binary data (non-printables become spaces)."""
    return raw.translate(_PRINTABLE_TABLE).decode("latin-1")

# Total decoded text the content cache will retain per corpus. Past this the
# corpus still serves reads (never fails a consumer) but stops caching, so a
# pathologically large app cannot exhaust memory. Bytes are counted as decoded
# character length, which is the same order of magnitude as on-disk size.
_DEFAULT_TEXT_BUDGET = int(os.environ.get("CORTEX_CORPUS_TEXT_BUDGET_MB", "512")) * 1024 * 1024


class SourceCorpus:
    """A per-scan shared view of the decompiled source tree.

    Thread-safety: ``walk`` populates the walk cache lazily; the parallel phase
    in the analyzers reads content concurrently. Content reads are idempotent
    (same path → same bytes) so a benign race only risks reading a file twice,
    never corrupting state. The walk cache is populated once per directory before
    the parallel phase in practice (the secret walk runs first), so contention is
    not a concern; we keep it lock-free to avoid serializing the hot read path.
    """

    __slots__ = ("_walk_cache", "_text_cache", "_bytes_cache", "_text_used", "_text_budget")

    def __init__(self, text_budget: int | None = None):
        self._walk_cache: dict[str, list[tuple[str, list[str], list[str]]]] = {}
        self._text_cache: dict[str, str | None] = {}
        self._bytes_cache: dict[str, bytes | None] = {}
        self._text_used = 0
        self._text_budget = _DEFAULT_TEXT_BUDGET if text_budget is None else text_budget

    # ── Walk ──────────────────────────────────────────────────────────────────
    def walk(self, scan_dir: str):
        """Yield ``(root, subdirs, files)`` exactly like ``os.walk(scan_dir)``.

        The underlying traversal is performed once per absolute directory and
        cached; subsequent calls (from other analyzers) replay the cached
        sequence. Fresh copies of the ``subdirs``/``files`` lists are yielded so
        a caller may mutate them (e.g. ``subdirs[:] = []`` to prune) without
        corrupting the cache or affecting other consumers.
        """
        key = os.path.abspath(scan_dir)
        cached = self._walk_cache.get(key)
        if cached is None:
            cached = []
            try:
                for root, subdirs, files in os.walk(scan_dir):
                    cached.append((root, list(subdirs), list(files)))
            except Exception:
                log.exception("[source_corpus] walk failed for %s", scan_dir)
                cached = []
            self._walk_cache[key] = cached
        for root, subdirs, files in cached:
            yield root, list(subdirs), list(files)

    # ── Text reads ────────────────────────────────────────────────────────────
    def read_text(self, fpath: str, max_bytes: int | None = None) -> str | None:
        """Return decoded text for ``fpath`` (cached), or ``None``.

        Mirrors ``open(fpath, "r", errors="replace").read()`` exactly for files
        within ``max_bytes``. Returns ``None`` when the file is over the cap or
        unreadable — the consumer treats that identically to the old
        ``getsize > cap: continue`` / ``except: continue`` branches. The size
        gate uses the same ``os.path.getsize`` the callers used, so the set of
        files that pass is unchanged.
        """
        key = os.path.abspath(fpath)
        if key in self._text_cache:
            content = self._text_cache[key]
            if content is None:
                return None
            if max_bytes is not None and len(content) > max_bytes:
                # Cached from a more permissive caller; honor this caller's cap.
                return None
            return content

        if max_bytes is not None:
            try:
                if os.path.getsize(fpath) > max_bytes:
                    return None
            except OSError:
                self._text_cache[key] = None
                return None
        try:
            with open(fpath, "r", errors="replace") as f:
                content = f.read()
        except Exception:
            self._text_cache[key] = None
            return None

        if self._text_used + len(content) <= self._text_budget:
            self._text_cache[key] = content
            self._text_used += len(content)
        return content

    # ── Byte reads ────────────────────────────────────────────────────────────
    def read_bytes(self, fpath: str, max_bytes: int | None = None) -> bytes | None:
        """Return raw bytes for ``fpath`` (cached), or ``None``.

        For binary consumers (DEX/.so printable-string extraction). When
        ``max_bytes`` is given, at most that many bytes are read — matching the
        callers that do ``f.read(N)`` — and the truncated buffer is cached under
        a size-qualified key so a later full read is not served a short buffer.
        """
        key = f"{os.path.abspath(fpath)}::{max_bytes if max_bytes is not None else 'all'}"
        if key in self._bytes_cache:
            return self._bytes_cache[key]
        try:
            with open(fpath, "rb") as f:
                data = f.read() if max_bytes is None else f.read(max_bytes)
        except Exception:
            self._bytes_cache[key] = None
            return None
        if self._text_used + len(data) <= self._text_budget:
            self._bytes_cache[key] = data
            self._text_used += len(data)
        return data

    # ── Diagnostics ───────────────────────────────────────────────────────────
    def stats(self) -> dict:
        return {
            "dirs_walked": len(self._walk_cache),
            "text_files_cached": sum(1 for v in self._text_cache.values() if v is not None),
            "byte_blobs_cached": sum(1 for v in self._bytes_cache.values() if v is not None),
            "text_bytes_used": self._text_used,
            "text_budget": self._text_budget,
        }

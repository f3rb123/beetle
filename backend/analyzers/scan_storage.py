"""
Unified scan storage helper.

Owns the persistent scan directory (`<SCAN_ROOT>/<scan_id>/...`) and provides
one place to:
  - persist extracted source trees (APK zip, IPA Payload, jadx/apktool output)
  - resolve relative finding paths to on-disk files for the source viewer
  - clean up old scans (TTL)

All analyzers should route through this module instead of writing to /tmp
directly, so the `/api/scans/{id}/file` endpoint always finds what they stored.
"""
from __future__ import annotations

import os
import shutil
import time
from pathlib import Path
from typing import Iterable

SCAN_ROOT = Path(os.environ.get("CORTEX_SCAN_DIR", "/tmp/cortex/scans"))

# Keep reasonable defaults — these matter for the "Source file not found" bug.
# Old code hard-capped at 2000 files; in practice even mid-sized APKs blow that.
DEFAULT_MAX_FILES = int(os.environ.get("CORTEX_PERSIST_MAX_FILES", "20000"))
DEFAULT_MAX_BYTES = int(os.environ.get("CORTEX_PERSIST_MAX_BYTES", str(2 * 1024 * 1024)))
# Binaries have their OWN higher cap because we only keep a printable-strings
# dump from a prefix of the file. A real-world classes.dex is routinely 10–30 MB
# and we need it to land in apk_extract so the Strings viewer can resolve
# references to `classes.dex`. Read cap below caps what we actually slurp into
# memory regardless of file size.
DEFAULT_MAX_BINARY_BYTES = int(os.environ.get("CORTEX_PERSIST_MAX_BINARY_BYTES", str(64 * 1024 * 1024)))
DEFAULT_BINARY_READ_BYTES = int(os.environ.get("CORTEX_PERSIST_BINARY_READ_BYTES", str(16 * 1024 * 1024)))
DEFAULT_TTL_SECONDS = int(os.environ.get("CORTEX_SCAN_TTL", str(24 * 3600)))

TEXT_EXTS = frozenset({
    ".java", ".kt", ".kts", ".smali", ".groovy",
    ".swift", ".m", ".mm", ".h", ".hpp", ".c", ".cc", ".cpp",
    ".xml", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".config",
    ".properties", ".gradle", ".plist", ".strings", ".pbxproj", ".xcconfig",
    ".txt", ".md", ".mf", ".pro", ".env",
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".html", ".htm", ".css", ".scss",
    ".py", ".rb", ".go", ".rs", ".sh", ".bat", ".ps1",
    ".proto", ".graphql", ".sql",
})

BINARY_STRING_EXTS = frozenset({
    ".dex", ".so", ".dylib", ".arsc", ".odex", ".vdex", ".oat",
    ".jar", ".aar", ".class", ".bin", ".dat", ".pak", ".bundle",
})

# Files shipped inside a package as a compiled / binary blob that ALSO have a
# high-quality decoded representation elsewhere in the scan tree. The decoded
# form must ALWAYS win over the raw copy so the source viewer renders readable
# text instead of a "compiled binary" card. Keys are lowercased basenames;
# values are decoded locations to probe (in priority order) relative to the
# scan root.
PREFERRED_DECODED_SOURCES = {
    # AndroidManifest.xml ships as compiled AXML in apk_extract/; apktool (or,
    # as a fallback, the androguard-reconstructed manifest persisted by the
    # Android analyzer) writes the readable XML under apktool/.
    "androidmanifest.xml": (
        "apktool/AndroidManifest.xml",
        "jadx/resources/AndroidManifest.xml",
    ),
}

# Heavy / useless subtrees to skip when persisting.
# NOTE: we do NOT skip "test"/"tests" anymore — real app code often lives
# under those names (e.g. tests that ship in release builds), and the string
# analyzer WILL surface findings from there, which then need to resolve in
# the code viewer.
SKIP_DIRNAMES = frozenset({
    "META-INF", "_CodeSignature", "__MACOSX", ".git", "node_modules",
})


def scan_root(scan_id: str) -> Path:
    return SCAN_ROOT / scan_id


def ensure_scan_root(scan_id: str) -> Path:
    p = scan_root(scan_id)
    p.mkdir(parents=True, exist_ok=True)
    return p


def persist_tree(
    src_dir: str | Path,
    scan_id: str,
    subdir: str,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    extra_binary_dump: bool = False,
    skip_dirs: Iterable[str] = SKIP_DIRNAMES,
) -> dict:
    """Copy text source files from `src_dir` into `<scan_root>/<subdir>`.

    Returns a small stats dict. Optionally dumps printable strings of .dex / .so
    files as `<path>.txt` so the viewer can still render something useful for
    binaries when jadx is unavailable.
    """
    src = Path(src_dir)
    dest = ensure_scan_root(scan_id) / subdir
    # Idempotent: if we've already persisted, do not re-walk.
    if dest.exists() and any(dest.iterdir()):
        return {"status": "exists", "dest": str(dest)}
    dest.mkdir(parents=True, exist_ok=True)

    copied = 0
    skipped = 0
    skip = set(skip_dirs)

    for root, dirs, files in os.walk(src):
        # Prune skipped dirs in-place for os.walk
        dirs[:] = [d for d in dirs if d not in skip]
        for fname in files:
            if copied >= max_files:
                return {"status": "truncated", "files": copied, "dest": str(dest)}
            ext = os.path.splitext(fname)[1].lower()
            sp = os.path.join(root, fname)
            try:
                size = os.path.getsize(sp)
            except OSError:
                continue
            is_text = ext in TEXT_EXTS
            # Text files get the strict cap — we copy them verbatim and there's
            # no good reason to persist a 50 MB minified JSON. Binaries get the
            # much larger cap because we only read a prefix for strings
            # extraction. Without this split, a real classes.dex (10–30 MB) was
            # silently skipped, leaving the Strings viewer with dangling links.
            limit = max_bytes if is_text else DEFAULT_MAX_BINARY_BYTES
            if size > limit:
                skipped += 1
                continue
            try:
                rel = os.path.relpath(sp, src).replace("\\", "/")
            except ValueError:
                continue
            dp = dest / rel

            if is_text:
                try:
                    dp.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(sp, dp)
                    copied += 1
                except Exception:
                    skipped += 1
            elif extra_binary_dump:
                # For ANY non-text file (known binary or unknown blob), dump its
                # printable strings so the code viewer can render SOMETHING and
                # findings that reference it don't 404. Only read up to
                # DEFAULT_BINARY_READ_BYTES to keep memory bounded on huge
                # .dex / .so / .arsc files.
                try:
                    with open(sp, "rb") as f:
                        raw = f.read(DEFAULT_BINARY_READ_BYTES)
                    text = _printable_strings(raw)
                    if text:
                        dp2 = dest / (rel + ".txt")
                        dp2.parent.mkdir(parents=True, exist_ok=True)
                        dp2.write_text(text, encoding="utf-8", errors="replace")
                        copied += 1
                except Exception:
                    skipped += 1
    return {"status": "ok", "files": copied, "skipped": skipped, "dest": str(dest)}


def _printable_strings(data: bytes, min_len: int = 6, max_chars: int = 1_500_000) -> str:
    out: list[str] = []
    cur: list[str] = []
    total = 0
    for b in data:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                s = "".join(cur)
                out.append(s)
                total += len(s) + 1
                if total >= max_chars:
                    break
            cur = []
    if cur and len(cur) >= min_len and total < max_chars:
        out.append("".join(cur))
    return "\n".join(out)


def _file_is_binary(path: Path, rel: str = "") -> bool:
    """Best-effort: does this resolved file hold compiled / binary bytes?

    Used so the resolver never hands back a binary copy (e.g. the compiled AXML
    AndroidManifest.xml, a Mach-O, an .arsc) when a decoded, human-readable
    representation exists. Delegates to the shared binary_inspector and degrades
    to a NUL-byte sniff if that module is unavailable.
    """
    try:
        from analyzers import binary_inspector
        return binary_inspector.is_binary(path, rel or path.name)
    except Exception:
        try:
            with open(path, "rb") as fh:
                return b"\x00" in fh.read(4096)
        except Exception:
            return False


def resolve_source_file(scan_id: str, rel_path: str) -> Path | None:
    """Given a finding's relative file_path, find it under any known subdir.

    Resolution always prefers the highest-quality human-readable representation
    and only falls back to a compiled/binary copy when no decoded version exists
    anywhere — so e.g. AndroidManifest.xml opens as readable XML (apktool output)
    rather than the compiled AXML extracted straight from the APK.
    """
    if not rel_path:
        return None
    root = scan_root(scan_id)
    if not root.exists():
        return None

    # Normalize and strip tmpdir-style leading segments
    clean = rel_path.replace("\\", "/").lstrip("/")
    # Drop leading `tmp/xxxx/` residues that may have been serialized from tmpdirs
    import re
    clean = re.sub(r"^tmp/[^/]+/", "", clean)
    clean = re.sub(r"^private/var/folders/[^/]+/[^/]+/T/[^/]+/", "", clean)

    # Remove absolute prefixes that may have been stored accidentally
    for prefix in ("var/folders/", "Payload/"):
        if clean.startswith(prefix):
            clean = clean[len(prefix):]

    subdirs = ("jadx", "apktool", "apk_extract", "ipa_extract", ".")
    basename = os.path.basename(clean)
    ext = os.path.splitext(clean)[1].lower()
    # Treat anything that isn't a well-known text extension as potentially
    # binary, so we always also probe for a .txt strings-dump sibling.
    is_binary = ext not in TEXT_EXTS

    # 0) Special files: a compiled/binary copy ships in the package but a decoded
    #    representation exists under apktool/ (or jadx resources). ALWAYS prefer
    #    the decoded form. Matched by basename so a prefixed finding path
    #    (e.g. apk_extract/AndroidManifest.xml) still resolves to the decoded
    #    file and never to the binary AXML.
    for preferred in PREFERRED_DECODED_SOURCES.get(basename.lower(), ()):
        cand = root / preferred
        if cand.is_file() and not _file_is_binary(cand, preferred):
            return cand

    # We may encounter a binary copy before a decoded one (or only a binary copy
    # exists). Remember the first binary match and keep looking for readable
    # source; only return the binary as a last resort.
    binary_fallback: Path | None = None

    # 1) Try direct path under each subdir (both exact and .txt sidecar).
    for sub in subdirs:
        base = root / sub
        cands = [base / clean]
        if is_binary:
            cands.append(base / (clean + ".txt"))
        for candidate in cands:
            if not candidate.is_file():
                continue
            # `.txt` strings-dump siblings are always plain text.
            if str(candidate).endswith(".txt") or not _file_is_binary(candidate, clean):
                return candidate
            if binary_fallback is None:
                binary_fallback = candidate

    # 2) Fallback: walk for basename match, bounded. Still prefer non-binary.
    checked = 0
    for sub in subdirs:
        base = root / sub
        if not base.exists():
            continue
        for r, _, files in os.walk(base):
            for name in files:
                checked += 1
                if checked > 50000:
                    return binary_fallback
                if name == basename or name == basename + ".txt":
                    p = Path(r) / name
                    if name.endswith(".txt") or not _file_is_binary(p, name):
                        return p
                    if binary_fallback is None:
                        binary_fallback = p
    return binary_fallback


def cleanup_scan(scan_id: str) -> bool:
    path = scan_root(scan_id)
    if not path.exists():
        return False
    shutil.rmtree(path, ignore_errors=True)
    return True


def cleanup_expired(ttl_seconds: int = DEFAULT_TTL_SECONDS) -> int:
    """Remove scan dirs older than ttl. Returns count removed."""
    if not SCAN_ROOT.exists():
        return 0
    now = time.time()
    removed = 0
    for child in SCAN_ROOT.iterdir():
        try:
            age = now - child.stat().st_mtime
        except OSError:
            continue
        if age > ttl_seconds:
            shutil.rmtree(child, ignore_errors=True)
            removed += 1
    return removed

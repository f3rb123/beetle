import os
import re


def normalize_relative_path(path: str) -> str:
    """Return a clean, slash-delimited relative path for viewer-safe linking."""
    if not path:
        return ""
    clean = path.replace("\\", "/").strip()
    clean = re.sub(r"^[A-Za-z]:/+", "", clean)
    clean = re.sub(r"^/+", "", clean)
    clean = re.sub(r"/+", "/", clean)
    return clean


def relativize_path(path: str, *roots: str) -> str:
    """
    Convert an absolute file path into a stable relative path inside one of the
    known scan roots. Falls back to a normalized path if no root matches.
    """
    if not path:
        return ""

    for root in roots:
        if not root:
            continue
        try:
            rel = os.path.relpath(path, root)
            if rel != "." and not rel.startswith(".."):
                return normalize_relative_path(rel)
        except Exception:
            continue

    return normalize_relative_path(path)


def make_file_evidence(path: str, line: int = 0, snippet: str = "") -> dict:
    entry = {"path": normalize_relative_path(path), "lines": [], "snippet": snippet or ""}
    if line:
        entry["lines"] = [line]
    return entry

"""
Binary content inspector — Phase 12 (source-viewer garbage fix).

The single most-reported source-viewer defect was that opening a compiled
artifact (a Mach-O executable, a `.dylib`, a framework binary, a `.dex`, an
`.so`) rendered its raw bytes decoded with replacement characters — the
`@##c#h###` garbage. The viewer had no way to know the file was not source.

This module gives the API one job: decide whether a resolved file is binary,
and if so describe it with real metadata (type, architecture, size, what *is*
recoverable) instead of ever shipping decoded bytes to the browser.

Design notes
------------
* Detection is content-first (magic bytes + a non-printable-ratio sniff on the
  head of the file), with the file extension only as a tie-breaker. We never
  trust the extension alone — decompilers happily emit extension-less Mach-O.
* Enrichment via LIEF is best-effort and fully optional; the module degrades to
  pure magic-byte identification if LIEF is unavailable. It never raises.
* No MobSF code is used. The magic constants are the published, public on-disk
  format identifiers (Mach-O / ELF / DEX / ZIP / PE / Java class).
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

# Mach-O / fat magics (all byte orders).
_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",  # 32-bit, big-endian
    b"\xce\xfa\xed\xfe",  # 32-bit, little-endian
    b"\xfe\xed\xfa\xcf",  # 64-bit, big-endian
    b"\xcf\xfa\xed\xfe",  # 64-bit, little-endian
}
_MACHO_FAT = {
    b"\xca\xfe\xba\xbe",  # universal (fat) — NOTE: identical to Java .class
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",  # fat 64
}

# CPU type constants we care to name (subset of <mach/machine.h>).
_MACHO_CPU = {
    0x0100000C: "arm64",
    0x0200000C: "arm64e",
    0x0000000C: "armv7",
    0x01000007: "x86_64",
    0x00000007: "i386",
}

# Extensions that, by convention in our scan tree, are stored as compiled
# artifacts even when the magic sniff is inconclusive.
_BINARY_HINT_EXTS = frozenset({
    ".dex", ".so", ".dylib", ".arsc", ".odex", ".vdex", ".oat",
    ".jar", ".aar", ".class", ".bin", ".dat", ".pak", ".bundle",
    ".a", ".o", ".framework", ".nib", ".car", ".ttf", ".otf",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf",
    ".zip", ".gz", ".mp3", ".mp4", ".mov",
})


def _read_head(path: Path, n: int = 8192) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(n)
    except Exception:
        return b""


def _looks_binary(head: bytes) -> bool:
    """Heuristic: a NUL byte, or >12% non-text bytes in the head, means binary."""
    if not head:
        return False
    if b"\x00" in head:
        return True
    # Count bytes outside the printable + common-whitespace range.
    text_bytes = bytes(range(0x20, 0x7F)) + b"\t\n\r\f\b"
    nonprintable = sum(1 for b in head if b not in text_bytes)
    return (nonprintable / len(head)) > 0.12


def _kind_from_magic(head: bytes, ext: str) -> tuple[str, str] | None:
    """Return (kind, human_label) from magic bytes, or None if not recognized."""
    m4 = head[:4]
    if m4 in _MACHO_MAGICS:
        bits = "64-bit" if m4 in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe") else "32-bit"
        return ("macho", f"Mach-O {bits} binary")
    if m4 in _MACHO_FAT:
        # CAFEBABE collides with Java class files — disambiguate by extension
        # and by the fat-arch count, which is a sane small number for Mach-O.
        if ext == ".class":
            return ("javaclass", "Compiled Java class")
        try:
            (narch,) = struct.unpack(">I", head[4:8])
            if 0 < narch < 64:
                return ("macho", "Mach-O universal (fat) binary")
        except Exception:
            pass
        return ("javaclass", "Compiled Java class")
    if m4 == b"\x7fELF":
        return ("elf", "ELF binary")
    if head[:3] == b"dex" and head[3:4] in (b"\n", b"\r", b"6", b"7", b"8", b"9"):
        return ("dex", "Dalvik DEX bytecode")
    if m4 == b"PK\x03\x04":
        label = {
            ".apk": "Android package (APK / ZIP)",
            ".jar": "Java archive (JAR / ZIP)",
            ".aar": "Android library (AAR / ZIP)",
            ".ipa": "iOS package (IPA / ZIP)",
        }.get(ext, "ZIP archive")
        return ("zip", label)
    if m4[:2] == b"MZ":
        return ("pe", "Windows PE binary")
    if m4 == b"\x89PNG":
        return ("image", "PNG image")
    if head[:3] == b"\xff\xd8\xff":
        return ("image", "JPEG image")
    if m4[:6] == b"GIF89a"[:4]:
        return ("image", "GIF image")
    if m4 == b"%PDF":
        return ("document", "PDF document")
    return None


def is_binary(path: str | Path, rel_path: str = "") -> bool:
    """True when the file must NOT be rendered as source text."""
    p = Path(path)
    head = _read_head(p)
    ext = os.path.splitext(rel_path or p.name)[1].lower()
    if _kind_from_magic(head, ext) is not None:
        return True
    if ext in _BINARY_HINT_EXTS:
        return True
    return _looks_binary(head)


def _human_size(num: int) -> str:
    val = float(num)
    for unit in ("B", "KB", "MB", "GB"):
        if val < 1024 or unit == "GB":
            return f"{val:.0f} {unit}" if unit == "B" else f"{val:.1f} {unit}"
        val /= 1024
    return f"{num} B"


def _macho_cpu_name(head: bytes) -> str | None:
    try:
        m4 = head[:4]
        if m4 in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):       # big-endian
            (cpu,) = struct.unpack(">I", head[4:8])
        elif m4 in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):     # little-endian
            (cpu,) = struct.unpack("<I", head[4:8])
        else:
            return None
        return _MACHO_CPU.get(cpu)
    except Exception:
        return None


def _enrich_macho(p: Path, info: dict) -> None:
    """Best-effort protection/arch metadata via the existing LIEF analyzer."""
    try:
        from analyzers import lief_analyzer
        if not lief_analyzer.available():
            return
        data = lief_analyzer.analyze_macho(str(p))
    except Exception:
        return
    if not data:
        return
    protections = []
    for key, label in (
        ("has_pie", "PIE (ASLR)"),
        ("has_nx_stack", "NX (no-exec stack)"),
        ("has_code_signature", "Code signature"),
        ("has_encryption", "Encrypted (FairPlay)"),
    ):
        if key in data:
            protections.append({"label": label, "present": bool(data[key])})
    if protections:
        info["protections"] = protections
    libs = data.get("imported_libs") or []
    if libs:
        info["linked_libraries"] = libs[:40]
    rpaths = data.get("rpaths") or []
    if rpaths:
        info["rpaths"] = rpaths[:20]


def describe(path: str | Path, rel_path: str = "") -> dict:
    """
    Structured description of a binary file for the source viewer.

    Returns a dict the frontend renders as a "compiled binary" card:
        { kind, label, name, size, size_bytes, arch?, details[], protections?,
          linked_libraries?, rpaths?, note, recoverable[] }
    """
    p = Path(path)
    head = _read_head(p)
    ext = os.path.splitext(rel_path or p.name)[1].lower()
    km = _kind_from_magic(head, ext)
    kind, label = km if km else ("binary", "Compiled / binary file")

    try:
        size_bytes = p.stat().st_size
    except Exception:
        size_bytes = 0

    name = (rel_path or p.name).replace("\\", "/")
    info: dict = {
        "kind": kind,
        "label": label,
        "name": name,
        "size": _human_size(size_bytes),
        "size_bytes": size_bytes,
        "details": [],
    }

    # Frameworks: surface the framework name explicitly (Part 5 / Part 7).
    if ".framework/" in name or name.endswith(".framework"):
        fw = name.split(".framework")[0].split("/")[-1] + ".framework"
        info["framework"] = fw
        info["details"].append({"label": "Framework", "value": fw})

    arch = _macho_cpu_name(head) if kind == "macho" else None
    if arch:
        info["arch"] = arch
        info["details"].append({"label": "Architecture", "value": arch})

    if kind == "macho":
        _enrich_macho(p, info)
        info["recoverable"] = ["symbols", "linked frameworks", "imports", "strings"]
        info["note"] = (
            "This is compiled machine code, not source. Protection flags appear "
            "under Binary Analysis; class/method metadata under Reconstruction."
        )
    elif kind == "elf":
        info["recoverable"] = ["symbols", "imports", "strings"]
        info["note"] = "Compiled native ELF library. Protection flags appear under Binary Analysis."
    elif kind == "dex":
        info["recoverable"] = ["classes", "methods", "strings"]
        info["note"] = "Dalvik bytecode. Decompiled Java for this package is under the Code Browser."
    elif kind in ("zip",):
        info["note"] = "Archive container. Its extracted contents are listed individually in the file tree."
    elif kind == "javaclass":
        info["recoverable"] = ["methods", "strings"]
        info["note"] = "Compiled JVM class. Decompiled Java is available via the Code Browser."
    elif kind == "image":
        info["note"] = "Image asset — not source code."
    else:
        info["recoverable"] = ["strings"]
        info["note"] = "Binary content. Source text is not available for this file."

    return info

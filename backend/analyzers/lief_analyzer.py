"""
Deep binary analysis using LIEF.

Gives us what the existing `elf_analyzer.py` and the inline Mach-O probe in
`ios_analyzer.py` cannot: full import/export tables, ObjC class enumeration,
code-signing entitlements, Frida/objection/Substrate artifact detection,
embedded dylib dependencies, and section-level hardening flags.

All functions are **defensive**: if `lief` is not installed, they return a
`{"available": False}` sentinel and emit no findings. Existing analyzers
continue to work unchanged.
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path

log = logging.getLogger("cortex.lief")

try:
    import lief
    # Silence LIEF's own logger — otherwise every parse prints to stderr.
    try:
        lief.logging.disable()
    except Exception:
        pass
    _LIEF_OK = True
except Exception:
    _LIEF_OK = False


# ─── Dangerous / notable imports and symbols ─────────────────────────────────
# These are matched against dylib / dependency names and imported symbols.
_DYNAMIC_CODE_APIS = {
    "dlopen", "dlsym", "NSCreateObjectFileImageFromMemory",
    "NSLinkModule",
}
_MEMORY_UNSAFE_LIBC = {
    "strcpy", "strcat", "sprintf", "gets", "scanf",
    "vsprintf", "wcscpy", "wcscat",
}
_SHELL_EXEC = {"system", "popen", "execve", "execvp"}
_ANTI_DEBUG = {"ptrace", "sysctl", "proc_info"}
_CRYPTO_WEAK = {"MD5_Update", "SHA1_Update", "CC_MD5", "CC_SHA1"}

# Dylib-path patterns that betray instrumentation or jailbroken-device helpers.
_INSTRUMENTATION_DYLIBS = [
    (re.compile(r"FridaGadget|frida-gadget|libfrida-gadget", re.IGNORECASE),
     "Frida instrumentation gadget",
     "critical"),
    (re.compile(r"libsubstrate|MobileSubstrate|CydiaSubstrate", re.IGNORECASE),
     "Cydia/Mobile Substrate hook engine",
     "critical"),
    (re.compile(r"libobjection", re.IGNORECASE),
     "Objection runtime",
     "critical"),
    (re.compile(r"libhooker|libellekit|RocketBootstrap", re.IGNORECASE),
     "iOS jailbreak tweak runtime",
     "high"),
    (re.compile(r"libcycript|cynject", re.IGNORECASE),
     "Cycript runtime (jailbreak tooling)",
     "high"),
]


def available() -> bool:
    return _LIEF_OK


# ─────────────────────────────────────────────────────────────────────────────
# Mach-O
# ─────────────────────────────────────────────────────────────────────────────
def analyze_macho(binary_path: str) -> dict:
    """Deep Mach-O inspection. Returns {} if lief not available or parse fails."""
    if not _LIEF_OK or not os.path.isfile(binary_path):
        return {"available": _LIEF_OK}

    try:
        binary = lief.MachO.parse(binary_path)
    except Exception as e:
        return {"available": True, "error": str(e)}

    if binary is None:
        return {"available": True, "error": "lief parse returned None"}

    # FAT binaries: pick the preferred slice (arm64 first, then first available).
    if hasattr(binary, "at") and binary.size > 1:
        slices = [binary.at(i) for i in range(binary.size)]
        m = next((s for s in slices if "ARM64" in str(s.header.cpu_type)), slices[0])
    else:
        m = binary[0] if hasattr(binary, "__getitem__") else binary

    out: dict = {
        "available":       True,
        "cpu":             str(getattr(m.header, "cpu_type", "")),
        "filetype":        str(getattr(m.header, "file_type", "")),
        "nlibs":           0,
        "imported_libs":   [],
        "imported_syms":   [],
        "exported_syms":   [],
        "objc_classes":    [],
        "entitlements":    None,
        "has_code_signature": False,
        "has_pie":         False,
        "has_nx_stack":    True,   # Mach-O default
        "has_encryption":  False,
        "rpaths":          [],
        "findings":        [],
    }

    try:
        out["has_pie"]            = bool(m.is_pie)
        out["has_code_signature"] = m.has_code_signature
        out["has_encryption"]     = m.has_encryption_info and any(
            getattr(c, "crypt_id", 0) != 0 for c in getattr(m, "encryption_info", [])
        ) if hasattr(m, "encryption_info") else False
    except Exception:
        pass

    try:
        out["imported_libs"] = [cmd.name for cmd in m.libraries]
        out["nlibs"]         = len(out["imported_libs"])
    except Exception:
        pass

    try:
        out["rpaths"] = [rp.path for rp in getattr(m, "rpaths", [])]
    except Exception:
        pass

    try:
        _all_imports = [s.name for s in m.imported_symbols]
        out["imported_syms"] = _all_imports[:2000]
        # The 2000 cap is for DISPLAY and really does truncate (webview_flutter_wkwebview
        # imports 2432). Record it so a truncated list is never mistaken for a complete one.
        out["imported_syms_total"] = len(_all_imports)
        out["imported_syms_truncated"] = len(_all_imports) > 2000
        # Scan the FULL, UNCAPPED list: _fopen/_malloc/_sscanf/_strlen appear ONLY past index
        # 2000 in that framework, so scanning out["imported_syms"] would silently miss them.
        # Mach-O only — the ELF path below is untouched, so Android output cannot change.
        from . import binary_api_scan
        hits = binary_api_scan.match_symbols(_all_imports)
        if hits:
            out["api_scan"] = hits
    except Exception:
        pass

    try:
        out["exported_syms"] = [s.name for s in m.exported_symbols][:2000]
    except Exception:
        pass

    # ObjC class enumeration (LIEF >= 0.13 exposes this).
    try:
        if hasattr(m, "objc_metadata") and m.objc_metadata is not None:
            classes = []
            for cls in m.objc_metadata.classes:
                classes.append(cls.name)
                if len(classes) >= 2000:
                    break
            out["objc_classes"] = classes
    except Exception:
        pass

    # Code-signing entitlements embedded in the code signature.
    try:
        for cmd in m.commands:
            if getattr(cmd, "command", None) == lief.MachO.LOAD_COMMAND_TYPES.CODE_SIGNATURE:
                # LIEF returns bytes; embedded plist/xml visible by scanning.
                raw = bytes(cmd.data) if hasattr(cmd, "data") else b""
                xml_start = raw.find(b"<?xml")
                if xml_start != -1:
                    xml_end = raw.find(b"</plist>", xml_start)
                    if xml_end != -1:
                        out["entitlements"] = raw[xml_start:xml_end + 8].decode(
                            "utf-8", errors="replace"
                        )
                break
    except Exception:
        pass

    # ── Derive findings ───────────────────────────────────────────────────────
    rel = os.path.basename(binary_path)

    if not out["has_pie"]:
        # PIE is only meaningful for the main MH_EXECUTE image. Dynamic libraries
        # (`.dylib`) and framework binaries are loaded at a relocatable address
        # regardless, so a missing MH_PIE on them is informational, not a finding
        # — flagging it produced noisy false positives on every embedded library.
        _ext = os.path.splitext(rel)[1].lower()
        _is_lib = _ext == ".dylib" or (not _ext and ".framework" in binary_path.replace("\\", "/"))
        out["findings"].append({
            "title":          "Mach-O Binary Not Position-Independent (PIE)",
            "severity":       "info" if _is_lib else "high",
            "category":       "Binary Hardening",
            "rule_id":        "macho_no_pie",
            "evidence_type":  "regex_match",
            "cwe":            "CWE-121",
            "masvs":          "MASVS-CODE-4",
            "owasp":          "M7",
            "file_path":      rel,
            "description":    (
                "Mach-O header lacks MH_PIE. ASLR is disabled for the main executable. "
                "Not applicable to dynamic libraries / frameworks, which relocate regardless."
                if not _is_lib else
                "Library/framework Mach-O without MH_PIE — expected and not a hardening gap "
                "(only the main executable image benefits from MH_PIE / ASLR)."
            ),
            "recommendation": "Rebuild the main executable with -Wl,-pie (MH_EXECUTE + MH_PIE).",
            "confidence":     "high",
        })

    if not out["has_code_signature"]:
        out["findings"].append({
            "title":          "Mach-O Binary Not Code-Signed",
            "severity":       "high",
            "category":       "Binary Hardening",
            "rule_id":        "macho_not_signed",
            "evidence_type":  "regex_match",
            "masvs":          "MASVS-RESILIENCE-1",
            "file_path":      rel,
            "description":    "LIEF did not find a LC_CODE_SIGNATURE command — the binary is unsigned.",
            "recommendation": "Sign all Mach-O binaries with a valid Apple Developer certificate.",
            "confidence":     "high",
        })

    # Instrumentation dylibs (Frida, Substrate, Objection, etc.)
    for libname in out["imported_libs"]:
        for regex, label, sev in _INSTRUMENTATION_DYLIBS:
            if regex.search(libname):
                out["findings"].append({
                    "title":          f"{label} Linked Into Mach-O",
                    "severity":       sev,
                    "category":       "Tampering",
                    "rule_id":        "macho_instrumentation_dylib",
                    "evidence_type":  "regex_match",
                    "cwe":            "CWE-506",
                    "masvs":          "MASVS-RESILIENCE-2",
                    "owasp":          "M7",
                    "file_path":      rel,
                    "description":    f"Mach-O links against `{libname}` — {label}. Not safe for production.",
                    "recommendation": "Remove from release builds. Verify the build pipeline does not embed debug frameworks.",
                    "confidence":     "high",
                })
                break

    # Dangerous imports
    symset = set(out["imported_syms"])
    risky = {
        "Dynamic code loading (dlopen/dlsym)": symset & _DYNAMIC_CODE_APIS,
        "Memory-unsafe libc":                   symset & _MEMORY_UNSAFE_LIBC,
        "Shell / command execution":            symset & _SHELL_EXEC,
    }
    for label, hits in risky.items():
        if hits:
            out["findings"].append({
                "title":          f"{label} API Used: {', '.join(sorted(hits)[:5])}",
                "severity":       "medium",
                "category":       "Binary Hardening",
                "rule_id":        "macho_risky_imports",
                "evidence_type":  "regex_match",
                "file_path":      rel,
                "description":    f"Binary imports {label.lower()} APIs.",
                "recommendation": "Avoid shell execution and dynamic loading; prefer bounded libc (strlcpy, snprintf).",
                "confidence":     "medium",
            })

    # RPATH abuse surface
    writable_rpath = [r for r in out["rpaths"] if r.startswith("@executable_path") or r.startswith("@loader_path")]
    if len(writable_rpath) > 1:
        out["findings"].append({
            "title":          f"Multiple @-Relative RPATHs Set ({len(writable_rpath)})",
            "severity":       "low",
            "category":       "Binary Hardening",
            "rule_id":        "macho_multiple_rpaths",
            "evidence_type":  "regex_match",
            "file_path":      rel,
            "description":    f"Binary has {len(writable_rpath)} @executable_path/@loader_path RPATHs — expands the dylib hijacking surface.",
            "recommendation": "Consolidate RPATHs; prefer a single well-known Frameworks directory.",
            "confidence":     "low",
        })

    return out


def analyze_all_macho(app_bundle_dir: str) -> list[dict]:
    """Scan every Mach-O inside an .app bundle (main binary, frameworks, dylibs)."""
    if not _LIEF_OK or not os.path.isdir(app_bundle_dir):
        return []
    results: list[dict] = []
    for dirpath, _dirs, files in os.walk(app_bundle_dir):
        for name in files:
            full = os.path.join(dirpath, name)
            try:
                if os.path.getsize(full) < 256:
                    continue
                with open(full, "rb") as f:
                    magic = f.read(4)
                if magic not in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                                 b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                                 b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
                    continue
            except OSError:
                continue
            res = analyze_macho(full)
            if res.get("available") and not res.get("error"):
                res["binary"] = os.path.relpath(full, app_bundle_dir)
                results.append(res)
            if len(results) >= 40:
                return results
    return results


# ─────────────────────────────────────────────────────────────────────────────
# ELF (Android .so)
# ─────────────────────────────────────────────────────────────────────────────
def analyze_elf(so_path: str) -> dict:
    """Deep ELF inspection for Android native libs."""
    if not _LIEF_OK or not os.path.isfile(so_path):
        return {"available": _LIEF_OK}
    try:
        elf = lief.ELF.parse(so_path)
    except Exception as e:
        return {"available": True, "error": str(e)}
    if elf is None:
        return {"available": True, "error": "parse returned None"}

    out: dict = {
        "available":     True,
        "imported_libs": [],
        "imported_syms": [],
        "exported_syms": [],
        "has_nx":        False,
        "has_canary":    False,
        "has_pie":       False,
        "relro":         "none",
        "findings":      [],
    }

    try:
        out["imported_libs"] = list(elf.libraries)
    except Exception:
        pass
    try:
        out["imported_syms"] = [s.name for s in elf.imported_symbols][:2000]
    except Exception:
        pass
    try:
        out["exported_syms"] = [s.name for s in elf.exported_symbols][:2000]
    except Exception:
        pass

    try:
        out["has_pie"] = (elf.header.file_type == lief.ELF.E_TYPE.DYNAMIC)
    except Exception:
        pass

    try:
        out["has_canary"] = any("__stack_chk" in (s.name or "") for s in elf.imported_symbols)
    except Exception:
        pass

    try:
        flags = {seg.type for seg in elf.segments}
        out["has_nx"] = lief.ELF.SEGMENT_TYPES.GNU_STACK in flags  # absence = no NX
    except Exception:
        pass

    try:
        has_relro   = any(seg.type == lief.ELF.SEGMENT_TYPES.GNU_RELRO for seg in elf.segments)
        has_bindnow = any(e.tag == lief.ELF.DYNAMIC_TAGS.FLAGS_1 and (e.value & 0x1)
                          for e in elf.dynamic_entries)
        out["relro"] = "full" if has_relro and has_bindnow else "partial" if has_relro else "none"
    except Exception:
        pass

    rel = os.path.basename(so_path)
    if _LIEF_OK:
        symset = set(out["imported_syms"])
        unsafe = symset & _MEMORY_UNSAFE_LIBC
        if unsafe:
            out["findings"].append({
                "title":          f".so Imports Memory-Unsafe libc: {', '.join(sorted(unsafe)[:5])}",
                "severity":       "medium",
                "category":       "Binary Hardening",
                "rule_id":        "elf_unsafe_libc_lief",
                "evidence_type":  "regex_match",
                "file_path":      rel,
                "description":    "Native library imports classic buffer-overflow sinks.",
                "recommendation": "Use bounded equivalents (strlcpy, snprintf). Enable _FORTIFY_SOURCE=2.",
                "confidence":     "medium",
            })

    return out

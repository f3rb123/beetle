import os
import re
import struct
from pathlib import Path
from .path_utils import normalize_relative_path

# ELF constants
ELFMAG              = b'\x7fELF'
ET_DYN              = 3      # Position-Independent Executable (PIE)
PT_LOAD             = 1
PT_GNU_STACK        = 0x6474e551
PT_GNU_RELRO        = 0x6474e552
PT_DYNAMIC          = 2
DT_NEEDED           = 1
DT_FLAGS_1          = 0x6ffffffb
DT_BIND_NOW         = 24
DT_RPATH            = 15
DT_RUNPATH          = 29
DF_1_NOW            = 0x00000001  # BIND_NOW in FLAGS_1
SHT_SYMTAB          = 2
SHT_DYNSYM          = 11
SHT_STRTAB          = 3


# Known Android ABI directory names, used to group a library's per-ABI copies.
_ABI_DIRS = ("armeabi-v7a", "arm64-v8a", "armeabi", "x86_64", "x86",
             "mips64", "mips", "riscv64")
_RELRO_RANK = {"none": 0, "partial": 1, "full": 2}


def _abi_from_path(path: str) -> str:
    """Extract the ABI directory (e.g. ``arm64-v8a``) from a library path."""
    for part in re.split(r"[\\/]+", path or ""):
        if part in _ABI_DIRS:
            return part
    return ""


def _collapse_by_library(binary_results: list) -> list:
    """Collapse per-ABI copies of the same ``.so`` into one entry.

    An app ships ``libfoo.so`` once per ABI (armeabi-v7a / arm64-v8a / x86); listing
    each copy separately triples the report for no analytic gain. This groups by
    library name, records the ``architectures`` it was built for, and merges the
    hardening flags WEAKEST-WINS — a protection is reported present only if present
    in EVERY ABI, so a weakness in any single architecture is never hidden."""
    groups: dict = {}
    order: list = []
    for b in binary_results:
        name = b.get("name") or Path(b.get("path", "")).name
        abi = _abi_from_path(b.get("path", ""))
        if name not in groups:
            g = dict(b)
            g["name"] = name
            g["architectures"] = []
            g["abi_paths"] = []
            groups[name] = g
            order.append(name)
        g = groups[name]
        if abi and abi not in g["architectures"]:
            g["architectures"].append(abi)
        if b.get("path"):
            g["abi_paths"].append(b["path"])
        # Weakest-wins: a protection counts only if present in every ABI copy.
        for flag in ("nx", "stack_canary", "pie", "fortify", "stripped"):
            g[flag] = bool(g.get(flag)) and bool(b.get(flag))
        if _RELRO_RANK.get(b.get("relro"), 0) < _RELRO_RANK.get(g.get("relro"), 0):
            g["relro"] = b.get("relro")
        # Liabilities: present if present in ANY ABI copy.
        if b.get("rpath"):
            g["rpath"] = True
        if b.get("dangerous_imports"):
            g["dangerous_imports"] = sorted(
                set(g.get("dangerous_imports") or []) | set(b["dangerous_imports"]))
    out = []
    for n in order:
        g = groups[n]
        g["architectures"] = sorted(g["architectures"])
        out.append(g)
    return out


def _lib_name(b: dict) -> str:
    """Base library name for a collapsed binary entry."""
    return b.get("name") or Path(b.get("path", "")).name


def _lib_names(bins: list, limit: int = 5) -> str:
    """Human-readable library list for finding text: ``libfoo.so (arm64-v8a, x86)``."""
    parts = []
    for b in bins[:limit]:
        archs = b.get("architectures") or []
        name = _lib_name(b)
        parts.append(f"{name} ({', '.join(archs)})" if archs else name)
    return ", ".join(parts)


def _detect_flutter(binary_results: list, results: dict | None = None) -> bool:
    """Whether this is a Flutter app.

    A Flutter app ships the Flutter engine (``libflutter.so``) alongside the Dart
    AOT snapshot (``libapp.so``). Detected primarily from the binary set already in
    scope; falls back to the framework recorded on the scan results.
    """
    names = {_lib_name(b).lower() for b in binary_results}
    if "libflutter.so" in names:
        return True
    if results:
        fw = str((results.get("app_info") or {}).get("framework")
                 or (results.get("framework") or {}).get("type") or "").lower()
        if fw == "flutter":
            return True
    return False


def _is_flutter_aot_blob(binary: dict, is_flutter: bool) -> bool:
    """True when this library is the Dart AOT snapshot (``libapp.so``) of a Flutter app.

    The snapshot is emitted by the Dart AOT compiler, not a C/C++ toolchain, so
    stack-canary / Full-RELRO / FORTIFY simply do not apply — the developer cannot
    add them. The real native hardening surface is ``libflutter.so``. This never
    reclassifies a genuine C/C++ ``.so`` (only ``libapp.so`` on a Flutter target).
    """
    if not is_flutter:
        return False
    return _lib_name(binary).lower() == "libapp.so"


def analyze_elf_binaries(tmpdir: str, results: dict):
    """Find and analyze all .so ELF binaries in the app."""
    so_files = []
    for root, _, files in os.walk(tmpdir):
        for fname in files:
            if fname.endswith(".so"):
                fpath = os.path.join(root, fname)
                if os.path.getsize(fpath) > 64:
                    so_files.append(fpath)

    if not so_files:
        return

    binary_results = []
    for fpath in so_files[:20]:  # cap at 20 binaries
        rel_path = normalize_relative_path(os.path.relpath(fpath, tmpdir))
        analysis = _analyze_elf(fpath, rel_path)
        if analysis:
            binary_results.append(analysis)

    # Collapse per-ABI duplicates (libfoo.so × 3 ABIs → one entry + architectures).
    binary_results = _collapse_by_library(binary_results)
    results["binaries"] = binary_results

    _emit_jni_surface(binary_results, results)

    # ── Generate aggregate findings ───────────────────────────────────────────
    # Flutter's Dart AOT snapshot (libapp.so) inherently lacks stack canary / Full
    # RELRO / FORTIFY — it is Dart-compiled, not built by a C toolchain, so those
    # C hardening flags do not apply and cannot be added. Exclude it from exactly
    # those finding lists (never from NX/PIE, which the snapshot does carry) and
    # surface it once as an INFO note instead. Genuine C/C++ .so files are untouched.
    is_flutter  = _detect_flutter(binary_results, results)
    def _aot(b): return _is_flutter_aot_blob(b, is_flutter)
    flutter_aot = [b for b in binary_results if _aot(b)]

    no_nx      = [b for b in binary_results if not b.get("nx")]
    no_canary  = [b for b in binary_results if not b.get("stack_canary") and not _aot(b)]
    no_pie     = [b for b in binary_results if not b.get("pie")]
    no_relro   = [b for b in binary_results if b.get("relro") == "none" and not _aot(b)]
    partial_relro = [b for b in binary_results if b.get("relro") == "partial" and not _aot(b)]
    not_stripped  = [b for b in binary_results if not b.get("stripped")]
    rpath_bins    = [b for b in binary_results if b.get("rpath")]

    if no_nx:
        names = _lib_names(no_nx)
        results["findings"].append({
            "rule_id":        "elf_nx_missing",
            "title":          f"NX Bit Not Set in Native Libraries ({len(no_nx)} found)",
            "severity":       "high",
            "category":       "Binary Hardening",
            "description":    f"The following native libraries lack NX (No-Execute) bit: {names}. "
                               "This allows execution of code placed on the stack or heap.",
            "impact":         "Buffer overflow exploitation is easier without NX protection.",
            "recommendation": "Compile with -z noexecstack (default in modern NDK). Ensure all .so files have GNU_STACK with RW permissions, not RWE.",
            "masvs":          "MASVS-CODE-4",
            "owasp":          "M7",
        })

    if no_canary:
        names = _lib_names(no_canary)
        results["findings"].append({
            "rule_id":        "elf_stack_canary_missing",
            "title":          f"Stack Canary Missing in Native Libraries ({len(no_canary)} found)",
            "severity":       "medium",
            "category":       "Binary Hardening",
            "description":    f"Stack canary protection not detected in: {names}. "
                               "Without canaries, stack buffer overflows can overwrite the return address undetected.",
            "recommendation": "Compile with -fstack-protector-all. Verify with: readelf -s lib.so | grep stack_chk",
            "masvs":          "MASVS-CODE-4",
            "owasp":          "M7",
        })

    if no_pie:
        names = _lib_names(no_pie)
        results["findings"].append({
            "rule_id":        "elf_pie_missing",
            "title":          f"PIE Not Enabled in Native Libraries ({len(no_pie)} found)",
            "severity":       "medium",
            "category":       "Binary Hardening",
            "description":    f"Position-Independent Executable (PIE/ASLR) not detected in: {names}. "
                               "Without PIE, ASLR is ineffective and memory addresses are predictable.",
            "recommendation": "Compile with -fPIE -pie. Modern Android NDK enables this by default.",
            "masvs":          "MASVS-CODE-4",
            "owasp":          "M7",
        })

    if no_relro:
        names = _lib_names(no_relro)
        results["findings"].append({
            "rule_id":        "elf_relro_missing",
            "title":          f"RELRO Not Configured ({len(no_relro)} libraries)",
            "severity":       "medium",
            "category":       "Binary Hardening",
            "description":    f"RELRO (Relocation Read-Only) not enabled in: {names}. "
                               "Without RELRO, GOT/PLT entries can be overwritten to redirect code execution.",
            "recommendation": "Compile with -Wl,-z,relro,-z,now for Full RELRO.",
            "masvs":          "MASVS-CODE-4",
            "owasp":          "M7",
        })
    elif partial_relro:
        results["findings"].append({
            "rule_id":        "elf_partial_relro",
            "title":          f"Partial RELRO in {len(partial_relro)} Libraries (Full RELRO Preferred)",
            "severity":       "low",
            "category":       "Binary Hardening",
            "description":    "Partial RELRO is enabled but not Full RELRO. The GOT is still writable after dynamic linking.",
            "recommendation": "Use -Wl,-z,relro,-z,now for Full RELRO protection.",
            "masvs":          "MASVS-CODE-4",
            "owasp":          "M7",
        })

    if not_stripped:
        names = _lib_names(not_stripped)
        results["findings"].append({
            "rule_id":        "elf_symbols_not_stripped",
            "title":          f"Debug Symbols Not Stripped ({len(not_stripped)} libraries)",
            "severity":       "low",
            "category":       "Binary Hardening",
            "description":    f"Native libraries with unstripped debug symbols: {names}. "
                               "Symbol names make reverse engineering significantly easier.",
            "recommendation": "Strip symbols from release builds using the NDK strip tool or CMake's STRIP command.",
            "masvs":          "MASVS-RESILIENCE-3",
            "owasp":          "M7",
        })

    if rpath_bins:
        results["findings"].append({
            "rule_id":        "elf_rpath_set",
            "title":          f"RPATH/RUNPATH Set — Dylib Hijacking Surface",
            "severity":       "medium",
            "category":       "Binary Hardening",
            "description":    f"{len(rpath_bins)} libraries have RPATH/RUNPATH set. If a writable directory is in the path, library hijacking may be possible.",
            "recommendation": "Remove unnecessary RPATH entries. Use @rpath sparingly and with absolute paths only.",
            "masvs":          "MASVS-CODE-4",
            "owasp":          "M7",
        })

    risky = [b for b in binary_results if b.get("dangerous_imports")]
    if risky:
        sample = risky[0]
        func_list = ", ".join(sample.get("dangerous_imports", [])[:5])
        results["findings"].append({
            "title":          f"Memory-Unsafe libc Functions In Native Libraries ({len(risky)})",
            "severity":       "medium",
            "category":       "Binary Hardening",
            "rule_id":        "elf_unsafe_libc_imports",
            "evidence_type":  "regex_match",
            "description":    f"{len(risky)} libraries reference memory-unsafe functions (e.g. {func_list}). "
                              "These are classic buffer-overflow sinks.",
            "recommendation": "Replace strcpy/strcat/sprintf with bounded equivalents (strlcpy, snprintf). "
                              "Enable _FORTIFY_SOURCE=2 and compile with -Wformat-security.",
            "masvs":          "MASVS-CODE-4",
            "owasp":          "M7",
            "confidence":     "medium",
        })

    # Flutter AOT snapshot note — replaces the C-hardening findings for libapp.so.
    if flutter_aot:
        results["findings"].append({
            "rule_id":        "elf_flutter_aot_snapshot",
            "title":          "Flutter AOT Snapshot (libapp.so) — hardening flags N/A",
            "severity":       "info",
            "category":       "Binary Hardening",
            "description":    f"{_lib_names(flutter_aot)} is the Dart AOT-compiled snapshot produced by the "
                              "Flutter/Dart toolchain, not a C/C++ library. Standard native C hardening "
                              "(stack canary, Full RELRO, FORTIFY) does not apply and cannot be enabled by the "
                              "developer. The real native hardening surface is libflutter.so (the Flutter engine).",
            "recommendation": "No action required for libapp.so. Ensure libflutter.so and any genuine C/C++ "
                              "libraries are hardened (NX, PIE, Full RELRO, stack canary).",
            "masvs":          "MASVS-CODE-4",
            "owasp":          "M7",
        })

    # Summary finding — the Dart AOT snapshot is excluded from the hardened/total
    # math (its C hardening flags are N/A) and footnoted instead of counted as an
    # unhardened app-owned C library.
    if binary_results:
        hardening_scope = [b for b in binary_results if not _aot(b)]
        total = len(hardening_scope)
        protected = sum(1 for b in hardening_scope
                       if b.get("nx") and b.get("stack_canary") and b.get("pie") and b.get("relro") != "none")
        aot_note = (f" {len(flutter_aot)} Dart AOT snapshot (libapp.so) excluded — C hardening flags N/A."
                    if flutter_aot else "")
        results["findings"].append({
            "rule_id":     "elf_hardening_summary",
            "title":       f"Native Binary Analysis — {protected}/{total} Fully Hardened",
            "severity":    "info",
            "category":    "Binary Hardening",
            "description": f"Analyzed {total} native .so libraries. {protected} have all protections (NX, PIE, RELRO, Stack Canary). "
                           f"{total - protected} have at least one missing protection.{aot_note}",
        })


# ── JNI symbol-level attribution (Phase 1) ───────────────────────────────────
# Statically-registered native methods use the JNIEXPORT name `Java_<pkg>_<Class>_<m>`
# and live in .dynsym (they must be exported), so they survive stripping and are
# recoverable by scanning the symbol string table bytes — no disassembler needed.
# Dynamically-registered methods (RegisterNatives in JNI_OnLoad) map a Java name to a
# raw function pointer at runtime; recovering that mapping needs disassembly/xref
# (radare2/LIEF pointer walking) and is deferred to Phase 2.
_JNI_SYM_RE = re.compile(rb"Java_[A-Za-z0-9_]{3,200}")
_MAX_JNI_METHODS = 200


def _demangle_jni(sym: str) -> str:
    """`Java_com_app_Foo_nativeDecrypt` → `com.app.Foo.nativeDecrypt`.

    Handles the common JNI escapes (_1 = literal underscore) and drops the overload
    signature suffix (after `__`). Best-effort — a reviewer-readable Java FQN."""
    s = sym[len("Java_"):].split("__", 1)[0]           # drop overload signature
    s = s.replace("_1", "\x00").replace("_2", ";").replace("_3", "[")
    parts = [p.replace("\x00", "_") for p in s.split("_")]
    return ".".join(parts) if len(parts) >= 2 else parts[0]


def _extract_jni_surface(data: bytes) -> dict:
    """The .so's JNI surface: statically-registered native methods (demangled),
    plus whether it uses JNI_OnLoad / RegisterNatives (dynamic registration).

    Symbol extraction reads the .dynsym string table directly from the bytes, so it
    works even on a stripped library. Returns {} when there is no JNI surface."""
    static_methods = sorted({
        _demangle_jni(m.group(0).decode("ascii", "ignore"))
        for m in _JNI_SYM_RE.finditer(data)
    })[:_MAX_JNI_METHODS]
    has_onload = b"JNI_OnLoad" in data
    uses_register = b"RegisterNatives" in data
    if not (static_methods or has_onload or uses_register):
        return {}
    return {
        "static_methods": static_methods,
        "static_method_count": len(static_methods),
        "has_jni_onload": has_onload,
        # Dynamic registration hides method↔function mapping from the symbol table —
        # precise per-method attribution needs Phase 2 (disassembly of JNI_OnLoad).
        "uses_register_natives": uses_register,
        "dynamic_registration": uses_register and not static_methods,
    }


def _emit_jni_surface(binary_results: list, results: dict) -> None:
    """Publish results["jni_surface"], attribute native-extracted secrets to the .so's
    JNI method surface (coarse — to the library's method SET; exact per-method needs
    Phase 2), and emit one INFO finding per library that exposes a JNI surface."""
    surface = []
    for b in binary_results:
        jni = b.get("jni")
        if not jni:
            continue
        surface.append({
            "library": _lib_name(b), "path": b.get("path", ""),
            "static_methods": jni.get("static_methods", []),
            "static_method_count": jni.get("static_method_count", 0),
            "has_jni_onload": jni.get("has_jni_onload", False),
            "uses_register_natives": jni.get("uses_register_natives", False),
            "dynamic_registration": jni.get("dynamic_registration", False),
        })
    if not surface:
        return
    results["jni_surface"] = surface

    # Coarse attribution: tag a native-extracted secret whose evidence file IS this
    # .so with the library's exported native methods, so a reviewer can pivot from a
    # native string to the Java↔native methods that library exposes.
    lib_by_name = {e["library"]: e for e in surface}
    for sec in (results.get("secrets") or []):
        if not isinstance(sec, dict):
            continue
        base = os.path.basename(str(sec.get("file_path") or "").replace("\\", "/"))
        e = lib_by_name.get(base)
        if e and base.endswith(".so"):
            sec.setdefault("jni_library", e["library"])
            sec.setdefault("jni_native_methods", e["static_methods"][:20])

    for e in surface:
        methods = ", ".join(e["static_methods"][:8]) or "(none exported by name)"
        more = f" (+{e['static_method_count'] - 8} more)" if e["static_method_count"] > 8 else ""
        dyn = (" It also calls RegisterNatives in JNI_OnLoad, so some native methods are "
               "registered dynamically and are NOT visible in the symbol table — precise "
               "method↔function mapping requires deeper (disassembly) analysis."
               if e["uses_register_natives"] else "")
        results["findings"].append({
            "rule_id":     "native_jni_surface",
            "title":       f"Native JNI Surface — {e['library']}",
            "severity":    "info",
            "category":    "Binary Hardening",
            "description": (f"`{e['library']}` exposes a JNI native surface. Statically-registered "
                            f"native methods: {methods}{more}.{dyn}"),
            "impact":      ("Native methods are the app's Java↔native boundary; a secret or endpoint "
                            "embedded in this library is reachable through these methods."),
            "recommendation": ("Audit native methods that handle secrets/credentials; prefer server-side "
                               "secrets and review any RegisterNatives-registered methods."),
            "file_path":   e["path"],
            "masvs":       "MASVS-CODE-4",
            "owasp":       "M7",
            "jni_static_methods": e["static_methods"][:50],
            "jni_uses_register_natives": e["uses_register_natives"],
            # Phase 1 is an informational inventory (no per-method attribution yet) —
            # keep it out of the default high-signal view; retained in the full export.
            "verbose_only": True,
        })


def _analyze_elf(fpath: str, rel_path: str) -> dict | None:
    """Parse ELF binary and return protection status dict."""
    try:
        with open(fpath, "rb") as f:
            data = f.read()

        if len(data) < 64 or data[:4] != ELFMAG:
            return None

        # ELF class (32 or 64 bit)
        elf_class = data[4]  # 1=32bit, 2=64bit
        is64 = elf_class == 2

        # Endianness
        endian = "<" if data[5] == 1 else ">"

        # e_type
        e_type = struct.unpack_from(endian + "H", data, 16)[0]

        if is64:
            # 64-bit ELF header
            e_phoff    = struct.unpack_from(endian + "Q", data, 32)[0]
            e_phentsize= struct.unpack_from(endian + "H", data, 54)[0]
            e_phnum    = struct.unpack_from(endian + "H", data, 56)[0]
            e_shoff    = struct.unpack_from(endian + "Q", data, 40)[0]
            e_shentsize= struct.unpack_from(endian + "H", data, 58)[0]
            e_shnum    = struct.unpack_from(endian + "H", data, 60)[0]
        else:
            # 32-bit ELF header
            e_phoff    = struct.unpack_from(endian + "I", data, 28)[0]
            e_phentsize= struct.unpack_from(endian + "H", data, 42)[0]
            e_phnum    = struct.unpack_from(endian + "H", data, 44)[0]
            e_shoff    = struct.unpack_from(endian + "I", data, 32)[0]
            e_shentsize= struct.unpack_from(endian + "H", data, 46)[0]
            e_shnum    = struct.unpack_from(endian + "H", data, 48)[0]

        result = {
            "path":          rel_path,
            "name":          Path(fpath).name,
            "arch":          "arm64" if is64 else "arm32",
            "pie":           e_type == ET_DYN,
            "nx":            False,
            "stack_canary":  False,
            "relro":         "none",
            "rpath":         False,
            "fortify":       False,
            "fortify_functions": [],
            "stripped":      True,
        }

        # ── Parse program headers ──────────────────────────────────────────────
        has_relro = False
        has_bind_now = False

        for i in range(min(e_phnum, 100)):
            offset = e_phoff + i * e_phentsize
            if offset + e_phentsize > len(data):
                break

            if is64:
                p_type  = struct.unpack_from(endian + "I", data, offset)[0]
                p_flags = struct.unpack_from(endian + "I", data, offset + 4)[0]
                p_offset= struct.unpack_from(endian + "Q", data, offset + 8)[0]
                p_filesz= struct.unpack_from(endian + "Q", data, offset + 32)[0]
            else:
                p_type  = struct.unpack_from(endian + "I", data, offset)[0]
                p_flags = struct.unpack_from(endian + "I", data, offset + 24)[0]
                p_offset= struct.unpack_from(endian + "I", data, offset + 4)[0]
                p_filesz= struct.unpack_from(endian + "I", data, offset + 16)[0]

            if p_type == PT_GNU_STACK:
                # Flags: 4=R, 2=W, 1=X. NX = X bit NOT set
                result["nx"] = not bool(p_flags & 1)

            elif p_type == PT_GNU_RELRO:
                has_relro = True

            elif p_type == PT_DYNAMIC and p_filesz > 0:
                # Parse dynamic section
                dyn_data = data[p_offset:p_offset + p_filesz]
                entry_size = 16 if is64 else 8

                for j in range(len(dyn_data) // entry_size):
                    dyn_offset = j * entry_size
                    if dyn_offset + entry_size > len(dyn_data):
                        break

                    if is64:
                        d_tag = struct.unpack_from(endian + "q", dyn_data, dyn_offset)[0]
                        d_val = struct.unpack_from(endian + "Q", dyn_data, dyn_offset + 8)[0]
                    else:
                        d_tag = struct.unpack_from(endian + "i", dyn_data, dyn_offset)[0]
                        d_val = struct.unpack_from(endian + "I", dyn_data, dyn_offset + 4)[0]

                    if d_tag == DT_BIND_NOW:
                        has_bind_now = True
                    elif d_tag == DT_FLAGS_1 and (d_val & DF_1_NOW):
                        has_bind_now = True
                    elif d_tag in (DT_RPATH, DT_RUNPATH):
                        result["rpath"] = True

        if has_relro and has_bind_now:
            result["relro"] = "full"
        elif has_relro:
            result["relro"] = "partial"

        # ── Check for stack canary (symbol scan) ───────────────────────────────
        result["stack_canary"] = (
            b"__stack_chk_guard" in data or
            b"___stack_chk_guard" in data or
            b"__stack_chk_fail" in data
        )

        # ── Check for FORTIFY ─────────────────────────────────────────────────
        result["fortify_functions"] = sorted({
            match.decode("ascii", errors="ignore")
            for match in re.findall(rb"__([A-Za-z0-9_]+_chk)", data)
        })
        result["fortify"] = bool(result["fortify_functions"])

        # ── Check if stripped (presence of symbol table) ───────────────────────
        # .symtab section present = not stripped
        result["stripped"] = b".symtab" not in data

        # ── JNI surface (Phase 1: symbol-table attribution) ────────────────────
        jni = _extract_jni_surface(data)
        if jni:
            result["jni"] = jni

        # ── Dangerous imported symbols (memory-unsafe libc calls) ──────────────
        dangerous = (b"strcpy", b"strcat", b"sprintf", b"gets", b"scanf",
                     b"system", b"popen", b"execve", b"dlopen", b"memcpy")
        found = [s.decode() for s in dangerous if s + b"\x00" in data]
        if found:
            result["dangerous_imports"] = found

        return result

    except Exception:
        return None

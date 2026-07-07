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

    results["binaries"] = binary_results

    # ── Generate aggregate findings ───────────────────────────────────────────
    no_nx      = [b for b in binary_results if not b.get("nx")]
    no_canary  = [b for b in binary_results if not b.get("stack_canary")]
    no_pie     = [b for b in binary_results if not b.get("pie")]
    no_relro   = [b for b in binary_results if b.get("relro") == "none"]
    partial_relro = [b for b in binary_results if b.get("relro") == "partial"]
    not_stripped  = [b for b in binary_results if not b.get("stripped")]
    rpath_bins    = [b for b in binary_results if b.get("rpath")]

    if no_nx:
        names = ", ".join(Path(b["path"]).name for b in no_nx[:5])
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
        names = ", ".join(Path(b["path"]).name for b in no_canary[:5])
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
        names = ", ".join(Path(b["path"]).name for b in no_pie[:5])
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
        names = ", ".join(Path(b["path"]).name for b in no_relro[:5])
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
        names = ", ".join(Path(b["path"]).name for b in not_stripped[:5])
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

    # Summary finding
    if binary_results:
        total = len(binary_results)
        protected = sum(1 for b in binary_results
                       if b.get("nx") and b.get("stack_canary") and b.get("pie") and b.get("relro") != "none")
        results["findings"].append({
            "rule_id":     "elf_hardening_summary",
            "title":       f"Native Binary Analysis — {protected}/{total} Fully Hardened",
            "severity":    "info",
            "category":    "Binary Hardening",
            "description": f"Analyzed {total} native .so libraries. {protected} have all protections (NX, PIE, RELRO, Stack Canary). "
                           f"{total - protected} have at least one missing protection.",
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

        # ── Dangerous imported symbols (memory-unsafe libc calls) ──────────────
        dangerous = (b"strcpy", b"strcat", b"sprintf", b"gets", b"scanf",
                     b"system", b"popen", b"execve", b"dlopen", b"memcpy")
        found = [s.decode() for s in dangerous if s + b"\x00" in data]
        if found:
            result["dangerous_imports"] = found

        return result

    except Exception:
        return None

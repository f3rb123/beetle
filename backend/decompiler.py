"""
Cortex Decompilation Pipeline
Runs jadx (Java decompile) and apktool (resource extract) on APKs.
Falls back gracefully if tools are unavailable.
"""
import os
import subprocess
import shutil
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

log = logging.getLogger("cortex.decompiler")

JADX_PATH    = os.environ.get("JADX_PATH", "jadx")
APKTOOL_PATH = os.environ.get("APKTOOL_PATH", "apktool")
SCAN_DIR     = Path(os.environ.get("CORTEX_SCAN_DIR", "/tmp/cortex/scans"))

try:
    from analyzers.scan_storage import resolve_source_file as _storage_resolve
except Exception:
    _storage_resolve = None


def jadx_available() -> bool:
    try:
        result = subprocess.run([JADX_PATH, "--version"], capture_output=True, timeout=10)
        return result.returncode == 0
    except Exception:
        return False


def apktool_available() -> bool:
    try:
        result = subprocess.run(["java", "-jar", "/usr/local/bin/apktool.jar", "--version"],
                                capture_output=True, timeout=10)
        return result.returncode == 0 or b"apktool" in result.stdout.lower() or b"apktool" in result.stderr.lower()
    except Exception:
        try:
            result = subprocess.run([APKTOOL_PATH, "--version"], capture_output=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False


def decompile_apk(apk_path: str, scan_id: str) -> dict:
    """
    Run jadx + apktool on the APK.
    Returns {
        jadx_dir: str | None,
        apktool_dir: str | None,
        tools_used: list,
        errors: list,
    }
    """
    SCAN_DIR.mkdir(parents=True, exist_ok=True)
    scan_work = SCAN_DIR / scan_id
    scan_work.mkdir(exist_ok=True)

    jadx_dir    = str(scan_work / "jadx")
    apktool_dir = str(scan_work / "apktool")

    # Jadx is REQUIRED — Java source is needed for the Code Viewer, high-quality
    # taint traces and Java-idiom SAST rules. The skip-by-size gate can still be
    # forced via CORTEX_JADX_MAX_MB if an operator really needs to bypass jadx
    # for a specific huge APK; default is effectively "always run".
    JADX_MAX_MB = int(os.environ.get("CORTEX_JADX_MAX_MB", "1000"))
    try:
        apk_size_mb = os.path.getsize(apk_path) / (1024 * 1024)
    except OSError:
        apk_size_mb = 0

    def _run_jadx() -> tuple[bool, str | None]:
        if apk_size_mb >= JADX_MAX_MB:
            log.warning(f"[{scan_id}] APK is {apk_size_mb:.0f} MB >= {JADX_MAX_MB} MB cap — skipping jadx")
            return False, f"jadx skipped: APK exceeds {JADX_MAX_MB} MB threshold"
        if not jadx_available():
            log.warning(f"[{scan_id}] jadx not available")
            return False, "jadx not installed — using DEX string extraction only"
        try:
            log.info(f"[{scan_id}] Running jadx ({apk_size_mb:.1f} MB)...")
            # Timeout scales with APK size: ~4s per MB, floor 90s, cap 420s (7 min).
            # Jadx writes output incrementally so partial output on timeout is
            # still usable downstream.
            jadx_timeout = int(os.environ.get(
                "CORTEX_JADX_TIMEOUT",
                str(min(420, max(90, int(apk_size_mb * 4))))
            ))
            result = subprocess.run(
                [JADX_PATH, "-d", jadx_dir, "--no-debug-info", "--no-res",
                 "--threads-count", "4", "--show-bad-code", apk_path],
                capture_output=True, timeout=jadx_timeout, text=True
            )
            if os.path.exists(jadx_dir) and os.listdir(jadx_dir):
                log.info(f"[{scan_id}] jadx complete")
                return True, None
            return False, f"jadx produced no output: {result.stderr[:200]}"
        except subprocess.TimeoutExpired:
            # Even on timeout, jadx may have written partial output — keep it.
            if os.path.exists(jadx_dir) and os.listdir(jadx_dir):
                log.info(f"[{scan_id}] jadx timed out but produced partial output — using it")
                return True, f"jadx timed out after {jadx_timeout}s (partial output kept)"
            return False, f"jadx timed out after {jadx_timeout}s — falling back to apktool/smali"
        except Exception as e:
            return False, f"jadx error: {e}"

    def _run_apktool() -> tuple[bool, str | None]:
        if not apktool_available():
            log.warning(f"[{scan_id}] apktool not available")
            return False, "apktool not installed — using ZIP extraction only"
        try:
            log.info(f"[{scan_id}] Running apktool...")
            cmd = [APKTOOL_PATH, "d", "-f", "-o", apktool_dir, apk_path]
            result = subprocess.run(cmd, capture_output=True, timeout=120, text=True)
            if result.returncode != 0:
                cmd = ["java", "-jar", "/usr/local/bin/apktool.jar", "d", "-f", "-o", apktool_dir, apk_path]
                result = subprocess.run(cmd, capture_output=True, timeout=120, text=True)
            if os.path.exists(apktool_dir) and os.listdir(apktool_dir):
                log.info(f"[{scan_id}] apktool complete")
                return True, None
            return False, f"apktool produced no output: {result.stderr[:200]}"
        except subprocess.TimeoutExpired:
            return False, "apktool timed out (120s)"
        except Exception as e:
            return False, f"apktool error: {e}"

    # Run jadx and apktool in parallel — they're independent, both heavy,
    # and combined serial time is the #1 pipeline bottleneck.
    tools_used: list[str] = []
    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        jadx_fut    = pool.submit(_run_jadx)
        apktool_fut = pool.submit(_run_apktool)
        jadx_ok, jadx_err       = jadx_fut.result()
        apktool_ok, apktool_err = apktool_fut.result()
    if jadx_ok:    tools_used.append("jadx")
    if jadx_err:   errors.append(jadx_err)
    if apktool_ok: tools_used.append("apktool")
    if apktool_err: errors.append(apktool_err)

    return {
        "jadx_dir":    jadx_dir    if "jadx"    in tools_used else None,
        "apktool_dir": apktool_dir if "apktool" in tools_used else None,
        "tools_used":  tools_used,
        "errors":      errors,
    }


def cleanup_decompiled(scan_id: str):
    """Remove decompiled files for a scan (save disk space)."""
    scan_work = SCAN_DIR / scan_id
    if scan_work.exists():
        shutil.rmtree(scan_work, ignore_errors=True)


def get_file_content(scan_id: str, rel_path: str) -> str | None:
    """Read a source file for the code viewer.

    Resolution is delegated to `analyzers.scan_storage.resolve_source_file`,
    which knows about every subdir we persist (`jadx`, `apktool`, `apk_extract`,
    `ipa_extract`) and tolerates paths recorded with tmpdir prefixes by older
    analyzer code.
    """
    # Reject absolute & traversal paths defensively — the API layer also checks,
    # but this function is called directly from tests and other code paths.
    if not rel_path:
        return None
    if rel_path.startswith(("/", "\\")) or "\x00" in rel_path:
        return None

    resolver = _storage_resolve
    candidate = resolver(scan_id, rel_path) if resolver else None

    # Fallback: legacy resolver logic, in case `analyzers.scan_storage` was not
    # importable (e.g. partial install).
    if candidate is None:
        import re as _re
        scan_work = SCAN_DIR / scan_id
        clean = rel_path.replace("\\", "/").lstrip("/")
        clean = _re.sub(r"^tmp/[^/]+/", "", clean)
        clean = _re.sub(r"^private/var/folders/[^/]+/[^/]+/T/[^/]+/", "", clean)
        ext = os.path.splitext(clean)[1].lower()
        is_binary = ext in (".dex", ".so", ".dylib", ".aar", ".jar", ".class")
        fname = os.path.basename(clean)
        tries = []
        for sub in ("jadx", "apktool", "apk_extract", "ipa_extract", "."):
            base = scan_work / sub
            tries.append(base / clean)
            if is_binary:
                tries.append(base / (clean + ".txt"))
            if fname:
                tries.append(base / fname)
        for c in tries:
            try:
                if c.is_file():
                    candidate = c
                    break
            except Exception:
                continue

    if candidate is None or not candidate.is_file():
        return None

    try:
        size = candidate.stat().st_size
        if size > 3_000_000:
            return f"// File too large to display inline ({size // 1024} KB)\n// Path: {rel_path}"
        return candidate.read_text(errors="replace")
    except Exception:
        return None


def list_source_files(scan_id: str, max_files: int = 10000) -> dict:
    """
    List all source files available in the decompiled output.
    Returns {jadx: [...], apktool: [...], apk_extract: [...]}
    """
    scan_work = SCAN_DIR / scan_id
    result = {}

    # jadx and apktool output - decompiled source
    for subdir in ["jadx", "apktool"]:
        base = scan_work / subdir
        if not base.exists():
            continue
        files = []
        for path in base.rglob("*"):
            if path.is_file() and len(files) < max_files:
                rel = str(path.relative_to(base))
                ext = path.suffix.lower()
                if ext in (".java", ".kt", ".xml", ".smali", ".json", ".yaml", ".properties", ".gradle"):
                    files.append(rel)
        result[subdir] = sorted(files)

    # apk_extract - raw APK content (XML resources, smali, etc.)
    apk_ext_base = scan_work / "apk_extract"
    if apk_ext_base.exists():
        files = []
        for path in apk_ext_base.rglob("*"):
            if path.is_file() and len(files) < max_files:
                rel = str(path.relative_to(apk_ext_base))
                ext = path.suffix.lower()
                if ext in (".xml", ".smali", ".json", ".txt", ".properties", ".yaml", ".js", ".html", ".mf"):
                    files.append(rel)
        if files:
            result["apk_extract"] = sorted(files)

    return result

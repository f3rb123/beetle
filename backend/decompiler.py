"""
Cortex Decompilation Pipeline
Runs jadx (Java decompile) and apktool (resource extract) on APKs.
Falls back gracefully if tools are unavailable.
"""
import os
import re
import subprocess
import shutil
import logging
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

log = logging.getLogger("cortex.decompiler")

JADX_PATH    = os.environ.get("JADX_PATH", "jadx")
APKTOOL_PATH = os.environ.get("APKTOOL_PATH", "apktool")
SCAN_DIR     = Path(os.environ.get("CORTEX_SCAN_DIR", "/tmp/cortex/scans"))

# Optional explicit JVM max-heap for jadx ONLY (e.g. "4g", "2048m"). When unset,
# jadx keeps its built-in default sizing (MaxRAMPercentage), preserving the
# previous behavior exactly. Scoped to the jadx subprocess so apktool / other
# tooling and the global JVM environment are never affected. Invalid values are
# ignored with a warning rather than failing the scan.
JADX_HEAP = os.environ.get("CORTEX_JADX_HEAP", "").strip()
_HEAP_RE = re.compile(r"^\d+[kmgtKMGT]$")

# Writable base for jadx runtime state (plugin store, cache, config). Under a
# read-only root filesystem jadx 1.5.0 fails at startup because it cannot create
# $HOME/.config/jadx/plugins/installed. We redirect HOME + the XDG base dirs here
# — defaulting to the tmpfs already mounted at /tmp — scoped to the jadx
# subprocess only, so the read-only hardening stays fully intact.
JADX_STATE_DIR = os.environ.get("CORTEX_JADX_STATE_DIR", "/tmp/jadx").strip() or "/tmp/jadx"


def _jadx_subprocess_env():
    """Build the environment for the jadx subprocess (scoped to that call only).

    Always returns an env dict — never None — because jadx needs a writable
    HOME/XDG location to initialize its plugin store under a read-only rootfs.
    We copy os.environ (never mutate it) so apktool, Python and the global
    environment are untouched, then:

      * redirect HOME / XDG_CONFIG_HOME / XDG_CACHE_HOME / XDG_DATA_HOME under
        CORTEX_JADX_STATE_DIR (tmpfs by default), and
      * optionally append `-Xmx<heap>` via JAVA_OPTS when CORTEX_JADX_HEAP is a
        valid size (unchanged behavior; invalid values are warned and ignored).
    """
    env = os.environ.copy()

    # --- jadx runtime-state redirect (HOME + XDG base dirs) ------------------
    config_dir = os.path.join(JADX_STATE_DIR, ".config")
    cache_dir  = os.path.join(JADX_STATE_DIR, ".cache")
    data_dir   = os.path.join(JADX_STATE_DIR, ".local", "share")
    try:
        for d in (config_dir, cache_dir, data_dir):
            os.makedirs(d, exist_ok=True)
    except OSError as e:
        # Don't fail the scan — jadx will attempt creation itself and the
        # failure (if any) is now captured by _describe_jadx_failure().
        log.warning(f"Could not pre-create jadx state dir under {JADX_STATE_DIR!r}: {e}")
    env["HOME"] = JADX_STATE_DIR
    env["XDG_CONFIG_HOME"] = config_dir
    env["XDG_CACHE_HOME"] = cache_dir
    env["XDG_DATA_HOME"] = data_dir

    # --- optional heap cap (unchanged semantics) ----------------------------
    if JADX_HEAP:
        if _HEAP_RE.match(JADX_HEAP):
            xmx = f"-Xmx{JADX_HEAP}"
            existing = (env.get("JAVA_OPTS") or "").strip()
            env["JAVA_OPTS"] = f"{existing} {xmx}".strip() if existing else xmx
            log.info(f"Applying jadx heap cap {xmx} (CORTEX_JADX_HEAP)")
        else:
            log.warning(
                f"Ignoring invalid CORTEX_JADX_HEAP={JADX_HEAP!r} — expected a JVM "
                "heap size such as '1g', '2g' or '4096m'. Using jadx default heap."
            )

    return env

try:
    from analyzers.scan_storage import resolve_source_file as _storage_resolve
except Exception:
    _storage_resolve = None


def _describe_jadx_failure(returncode, stdout: str, stderr: str) -> str:
    """Build a human-readable reason for a jadx run that produced no output.

    jadx rarely writes a clean error to stderr: it logs to stdout, and a
    container OOM-kill terminates the JVM with SIGKILL, leaving BOTH streams
    empty with only a non-zero return code behind. The old code surfaced
    `stderr[:200]` alone, which is why the real reason was lost ("jadx produced
    no output: " with an empty tail). We therefore fold the return code first,
    then the stderr tail, then the stdout tail into the message.
    """
    # OOM / killed: subprocess reports SIGKILL as -9; Docker/shells surface 137.
    if returncode in (-9, 137):
        return (
            f"jadx was killed (exit {returncode}, likely out-of-memory / SIGKILL). "
            "Raise container memory (CORTEX_BACKEND_MEM) or cap the jadx heap "
            "(CORTEX_JADX_HEAP)."
        )
    # Any other fatal signal — POSIX reports these as negative return codes.
    if isinstance(returncode, int) and returncode < 0:
        return f"jadx terminated by signal {-returncode} (exit {returncode})."

    stderr_tail = (stderr or "").strip()[-300:]
    stdout_tail = (stdout or "").strip()[-300:]
    detail = stderr_tail or stdout_tail or "no diagnostic output on stdout/stderr"
    return f"jadx exited {returncode}: {detail}"


def _dex_workload_mb(apk_path: str) -> float:
    """Total uncompressed size of the .dex files inside the APK, in MB.

    APK size is a poor proxy for jadx workload — assets/resources can dominate
    an APK while jadx only decompiles DEX bytecode. Read from the zip central
    directory (no extraction). Returns 0.0 when the APK is unreadable so
    callers fall back to APK-size-based budgeting.
    """
    try:
        with zipfile.ZipFile(apk_path) as z:
            return sum(i.file_size for i in z.infolist()
                       if i.filename.endswith(".dex")) / (1024 * 1024)
    except Exception:
        return 0.0


def _jadx_time_budget(dex_mb: float, apk_mb: float) -> int:
    """Soft timeout (seconds) for a jadx run.

    Preferred: scale with the actual DEX workload (~10s per uncompressed DEX
    MB with the default thread count), floor 120s, cap 600s. Fallback when the
    DEX size is unknown: the legacy APK-size formula (~4s/MB, 90–420s).
    CORTEX_JADX_TIMEOUT overrides both.
    """
    env = os.environ.get("CORTEX_JADX_TIMEOUT")
    if env:
        try:
            return int(env)
        except ValueError:
            log.warning(f"Ignoring invalid CORTEX_JADX_TIMEOUT={env!r}")
    if dex_mb > 0:
        return min(600, max(120, int(dex_mb * 10)))
    return min(420, max(90, int(apk_mb * 4)))


def _jadx_thread_count() -> int:
    """Decompile threads for jadx. Defaults to the CPUs actually available to
    this process (the container quota), clamped to 2–8 so jadx neither starves
    on big hosts nor oversubscribes small ones. CORTEX_JADX_THREADS overrides."""
    env = os.environ.get("CORTEX_JADX_THREADS")
    if env:
        try:
            return max(1, int(env))
        except ValueError:
            log.warning(f"Ignoring invalid CORTEX_JADX_THREADS={env!r}")
    cpus = getattr(os, "process_cpu_count", os.cpu_count)() or 4
    return max(2, min(8, cpus))


def _count_java_sources(jadx_dir: str) -> int:
    """Number of .java files jadx has written so far. Used both as the progress
    signal for the adaptive timeout and to validate partial output — a non-empty
    directory with zero .java files is NOT usable decompiled source."""
    count = 0
    try:
        for root, _dirs, names in os.walk(jadx_dir):
            count += sum(1 for n in names if n.endswith(".java"))
    except OSError:
        pass
    return count


# Adaptive-timeout tuning. Poll the output tree every 15s; once past the soft
# deadline, a run that has not produced a single new .java file for 60s is
# considered wedged and killed rather than allowed to burn the full hard cap.
_JADX_POLL_S = 15
_JADX_STALL_S = 60


def _wait_with_progress(proc, jadx_dir: str, soft_timeout: int, hard_cap: int):
    """Wait for jadx with an adaptive deadline.

    Up to `soft_timeout` the process simply runs (jadx front-loads DEX loading
    and writes nothing early on — that is not a stall). Past the soft deadline
    the run is EXTENDED as long as new .java files keep appearing, up to
    `hard_cap`; if output stops growing for _JADX_STALL_S the process is killed
    early. Returns (stdout, stderr, timed_out, elapsed_seconds).
    """
    start = time.monotonic()
    last_count = -1
    last_progress_at = start
    while True:
        try:
            stdout, stderr = proc.communicate(timeout=_JADX_POLL_S)
            return stdout, stderr, False, int(time.monotonic() - start)
        except subprocess.TimeoutExpired:
            pass
        now = time.monotonic()
        count = _count_java_sources(jadx_dir)
        if count > last_count:
            last_count = count
            last_progress_at = now
        past_soft = (now - start) >= soft_timeout
        stalled = (now - last_progress_at) >= _JADX_STALL_S
        if (now - start) >= hard_cap or (past_soft and stalled):
            proc.kill()
            try:
                stdout, stderr = proc.communicate(timeout=10)
            except Exception:
                stdout, stderr = "", ""
            return stdout, stderr, True, int(now - start)


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
            # Budget scales with the real workload (DEX bytes), not APK bytes.
            # Jadx writes output incrementally so partial output on timeout is
            # still usable downstream.
            dex_mb = _dex_workload_mb(apk_path)
            jadx_timeout = _jadx_time_budget(dex_mb, apk_size_mb)
            threads = _jadx_thread_count()
            # Adaptive extension: past the soft deadline jadx keeps running as
            # long as it is still writing sources, up to a hard cap. A stalled
            # process is killed early instead of burning the whole budget.
            hard_cap = min(900, jadx_timeout * 2)
            log.info(
                f"[{scan_id}] Running jadx ({apk_size_mb:.1f} MB APK, "
                f"{dex_mb:.1f} MB dex, threads={threads}, "
                f"soft_timeout={jadx_timeout}s, hard_cap={hard_cap}s)..."
            )
            proc = subprocess.Popen(
                [JADX_PATH, "-d", jadx_dir, "--no-debug-info", "--no-res",
                 "--threads-count", str(threads), "--show-bad-code", apk_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env=_jadx_subprocess_env(),
            )
            stdout, stderr, timed_out, elapsed = _wait_with_progress(
                proc, jadx_dir, soft_timeout=jadx_timeout, hard_cap=hard_cap)

            java_count = _count_java_sources(jadx_dir)
            if not timed_out:
                if java_count > 0:
                    log.info(f"[{scan_id}] jadx complete "
                             f"(exit {proc.returncode}, {java_count} java files)")
                    return True, None
                # No usable source. The reason is almost never in stderr alone —
                # jadx logs to stdout, and an OOM/SIGKILL leaves both streams
                # empty with only a non-zero return code. Capture all three so
                # the failure is diagnosable from both the logs and
                # decompile_info.errors.
                reason = _describe_jadx_failure(proc.returncode, stdout, stderr)
                log.warning(
                    f"[{scan_id}] jadx produced no usable source — {reason} | "
                    f"rc={proc.returncode} "
                    f"stdout_tail={(stdout or '')[-500:]!r} "
                    f"stderr_tail={(stderr or '')[-500:]!r}"
                )
                return False, f"jadx produced no output: {reason}"
            # Timed out. Partial output is kept — but only when it actually
            # contains decompiled source, not just an empty directory skeleton.
            if java_count > 0:
                log.info(f"[{scan_id}] jadx timed out after {elapsed}s but produced "
                         f"partial output ({java_count} java files) — using it")
                return True, (f"jadx timed out after {elapsed}s "
                              f"(partial output kept: {java_count} java files)")
            log.warning(f"[{scan_id}] jadx timed out after {elapsed}s with no "
                        f"usable source — falling back to apktool/smali")
            return False, f"jadx timed out after {elapsed}s — falling back to apktool/smali"
        except Exception as e:
            log.warning(f"[{scan_id}] jadx invocation error: {e}")
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


def resolve_source_path(scan_id: str, rel_path: str) -> Path | None:
    """Resolve a viewer-relative path to a real file under the scan tree.

    Delegates to `analyzers.scan_storage.resolve_source_file` (which knows every
    subdir we persist: `jadx`, `apktool`, `apk_extract`, `ipa_extract`, and
    tolerates tmpdir-prefixed paths from older analyzer code) and falls back to
    a self-contained resolver when that module is unavailable.
    """
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
        # Prefer the decoded AndroidManifest.xml (apktool / jadx resources) over
        # the compiled AXML extracted from the APK, mirroring scan_storage.
        if fname.lower() == "androidmanifest.xml":
            tries.append(scan_work / "apktool" / "AndroidManifest.xml")
            tries.append(scan_work / "jadx" / "resources" / "AndroidManifest.xml")
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
    return candidate


def _maybe_decode_plist(candidate: Path, rel_path: str) -> str | None:
    """Render a plist (binary `bplist` or XML) as readable XML, or None.

    iOS `Info.plist` (and many other .plist files) ship as a binary plist that
    would otherwise hit the binary-card path and show as a "compiled binary".
    We decode it to canonical XML so the source viewer shows readable, line-
    numbered text. XML plists are round-tripped for consistent formatting.
    """
    try:
        with open(candidate, "rb") as fh:
            head = fh.read(8)
    except Exception:
        return None
    is_bplist = head[:6] == b"bplist"
    if not is_bplist and os.path.splitext(rel_path or candidate.name)[1].lower() != ".plist":
        return None
    try:
        import plistlib
        with open(candidate, "rb") as fh:
            data = plistlib.load(fh)
        return plistlib.dumps(data, fmt=plistlib.FMT_XML).decode("utf-8", errors="replace")
    except Exception:
        return None


def get_file_content(scan_id: str, rel_path: str) -> str | None:
    """Read a source file for the code viewer, as text.

    Binary artifacts (Mach-O, ELF, DEX, archives, …) are NEVER decoded to text
    here — that produced the `@##c#h###` garbage. Callers that want rich binary
    metadata should use `inspect_file`; this function returns a short human
    notice for binaries so legacy text-only call sites still degrade gracefully.
    """
    candidate = resolve_source_path(scan_id, rel_path)
    if candidate is None:
        return None

    # Decode binary plists (e.g. iOS Info.plist) to readable XML rather than
    # treating them as opaque binaries.
    decoded_plist = _maybe_decode_plist(candidate, rel_path)
    if decoded_plist is not None:
        return decoded_plist

    # Never render compiled bytes as source.
    try:
        from analyzers import binary_inspector
        if binary_inspector.is_binary(candidate, rel_path):
            info = binary_inspector.describe(candidate, rel_path)
            return (
                f"// {info['label']} — source not available\n"
                f"// File: {info['name']}  ({info['size']})\n"
                f"// {info.get('note', '')}"
            )
    except Exception:
        pass

    try:
        size = candidate.stat().st_size
        if size > 3_000_000:
            return f"// File too large to display inline ({size // 1024} KB)\n// Path: {rel_path}"
        return candidate.read_text(errors="replace")
    except Exception:
        return None


def inspect_file(scan_id: str, rel_path: str) -> dict | None:
    """Resolve + classify a file for the source viewer.

    Returns one of:
      * {"kind": "text", "content": "<text>"}                 — render as source
      * {"kind": "binary", "info": {...}}                     — render binary card
      * None                                                   — not found
    """
    candidate = resolve_source_path(scan_id, rel_path)
    if candidate is None:
        return None

    # Decode binary plists (e.g. iOS Info.plist) to readable XML before the
    # binary classification, so they render as line-numbered source.
    decoded_plist = _maybe_decode_plist(candidate, rel_path)
    if decoded_plist is not None:
        return {"kind": "text", "content": decoded_plist}

    try:
        from analyzers import binary_inspector
        if binary_inspector.is_binary(candidate, rel_path):
            return {"kind": "binary", "info": binary_inspector.describe(candidate, rel_path)}
    except Exception:
        pass

    try:
        size = candidate.stat().st_size
        if size > 3_000_000:
            return {"kind": "text",
                    "content": f"// File too large to display inline ({size // 1024} KB)\n// Path: {rel_path}"}
        return {"kind": "text", "content": candidate.read_text(errors="replace")}
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

    # repo - CI/CD repository scan (pipeline + source files, incl. extensionless
    # well-known files like Jenkinsfile / Dockerfile that have no suffix).
    repo_base = scan_work / "repo"
    if repo_base.exists():
        files = []
        for path in repo_base.rglob("*"):
            if path.is_file() and len(files) < max_files:
                rel = str(path.relative_to(repo_base))
                ext = path.suffix.lower()
                name = path.name.lower()
                if ext in (".yml", ".yaml", ".json", ".xml", ".txt", ".sh", ".py",
                           ".js", ".ts", ".gradle", ".properties", ".toml", ".cfg",
                           ".ini", ".md", ".tf", ".groovy") or name in (
                           "jenkinsfile", "dockerfile", "makefile"):
                    files.append(rel)
        if files:
            result["repo"] = sorted(files)

    return result

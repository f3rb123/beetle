"""
Decompiler pipeline tests — jadx workload budgeting, adaptive timeout and
partial-output validation (v1.3 stabilization).

Runnable standalone or under pytest:
    python -m tests.test_decompiler       # from backend/
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import zipfile

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

import decompiler  # noqa: E402


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _no_env(fn):
    """Run fn with the jadx env overrides cleared, restoring them after."""
    saved = {}
    for k in ("CORTEX_JADX_TIMEOUT", "CORTEX_JADX_THREADS"):
        saved[k] = os.environ.pop(k, None)
    try:
        return fn()
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v


# ── DEX workload probe ───────────────────────────────────────────────────────

def test_dex_workload_reads_central_directory():
    with tempfile.TemporaryDirectory() as td:
        apk = os.path.join(td, "app.apk")
        with zipfile.ZipFile(apk, "w") as z:
            z.writestr("classes.dex", b"\x00" * (2 * 1024 * 1024))
            z.writestr("classes2.dex", b"\x00" * (1 * 1024 * 1024))
            z.writestr("assets/video.mp4", b"\x00" * (8 * 1024 * 1024))
        mb = decompiler._dex_workload_mb(apk)
        _check(abs(mb - 3.0) < 0.01, f"expected ~3.0 MB of dex, got {mb}")


def test_dex_workload_unreadable_apk_returns_zero():
    _check(decompiler._dex_workload_mb("/nonexistent/x.apk") == 0.0,
           "unreadable APK must yield 0.0 (fallback to APK-size budget)")


# ── Timeout budgeting ────────────────────────────────────────────────────────

def test_time_budget_scales_with_dex_not_apk():
    def run():
        # 40 MB of dex → 400s, regardless of an 800 MB APK.
        _check(decompiler._jadx_time_budget(40.0, 800.0) == 400,
               "budget must come from dex size when known")
        # No dex info → legacy APK formula (85 MB * 4 = 340).
        _check(decompiler._jadx_time_budget(0.0, 85.0) == 340,
               "must fall back to APK-size formula")
        # Floors and caps.
        _check(decompiler._jadx_time_budget(1.0, 1.0) == 120, "dex floor 120s")
        _check(decompiler._jadx_time_budget(500.0, 500.0) == 600, "dex cap 600s")
        _check(decompiler._jadx_time_budget(0.0, 1.0) == 90, "legacy floor 90s")
        _check(decompiler._jadx_time_budget(0.0, 900.0) == 420, "legacy cap 420s")
    _no_env(run)


def test_time_budget_env_override_wins():
    os.environ["CORTEX_JADX_TIMEOUT"] = "1234"
    try:
        _check(decompiler._jadx_time_budget(40.0, 85.0) == 1234,
               "CORTEX_JADX_TIMEOUT must override the formula")
    finally:
        del os.environ["CORTEX_JADX_TIMEOUT"]


def test_thread_count_env_and_bounds():
    os.environ["CORTEX_JADX_THREADS"] = "3"
    try:
        _check(decompiler._jadx_thread_count() == 3, "env override must win")
    finally:
        del os.environ["CORTEX_JADX_THREADS"]

    def run():
        n = decompiler._jadx_thread_count()
        _check(2 <= n <= 8, f"default thread count must be clamped to 2–8, got {n}")
    _no_env(run)


# ── Partial-output validation ────────────────────────────────────────────────

def test_count_java_sources():
    with tempfile.TemporaryDirectory() as td:
        _check(decompiler._count_java_sources(td) == 0, "empty dir → 0")
        os.makedirs(os.path.join(td, "sources", "com", "app"))
        _check(decompiler._count_java_sources(td) == 0,
               "directory skeleton without sources must count as 0 — this is "
               "the case the old non-empty-dir check wrongly accepted")
        for name in ("A.java", "B.java"):
            with open(os.path.join(td, "sources", "com", "app", name), "w") as fh:
                fh.write("class X {}")
        with open(os.path.join(td, "sources", "res.txt"), "w") as fh:
            fh.write("not java")
        _check(decompiler._count_java_sources(td) == 2, "must count only .java")


# ── Adaptive wait ────────────────────────────────────────────────────────────

def test_wait_with_progress_normal_exit():
    with tempfile.TemporaryDirectory() as td:
        proc = subprocess.Popen(
            [sys.executable, "-c", "print('done')"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, _stderr, timed_out, elapsed = decompiler._wait_with_progress(
            proc, td, soft_timeout=30, hard_cap=60)
        _check(not timed_out, "fast process must not be reported as timed out")
        _check("done" in stdout, "stdout must be captured")
        _check(elapsed < 30, f"elapsed sane, got {elapsed}")


def test_wait_with_progress_kills_stalled_process():
    saved_poll, saved_stall = decompiler._JADX_POLL_S, decompiler._JADX_STALL_S
    decompiler._JADX_POLL_S, decompiler._JADX_STALL_S = 1, 2
    try:
        with tempfile.TemporaryDirectory() as td:
            proc = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(120)"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            _stdout, _stderr, timed_out, elapsed = decompiler._wait_with_progress(
                proc, td, soft_timeout=1, hard_cap=60)
            _check(timed_out, "stalled process past soft deadline must be killed")
            _check(elapsed < 30, f"stall kill must fire well before hard cap, got {elapsed}s")
            _check(proc.poll() is not None, "process must actually be dead")
    finally:
        decompiler._JADX_POLL_S, decompiler._JADX_STALL_S = saved_poll, saved_stall


if __name__ == "__main__":
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all decompiler tests passed")

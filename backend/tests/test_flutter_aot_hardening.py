"""
Regression: Flutter's Dart AOT snapshot (libapp.so) must not be flagged for
missing C hardening (stack canary / Full RELRO / FORTIFY).

libapp.so is produced by the Dart AOT compiler, not a C toolchain, so those
protections cannot exist — the finding misfires on 100% of release Flutter apps.
It is reclassified to one INFO note; genuine C/C++ .so files are unaffected.

FAILS on old behavior (MEDIUM canary/RELRO findings for libapp.so), PASSES on new.
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import elf_analyzer  # noqa: E402


def _lib(name, *, nx=True, canary=True, pie=True, relro="full", stripped=True,
         fortify=True, rpath=False):
    return {
        "name": name, "path": f"lib/arm64-v8a/{name}", "arch": "arm64",
        "nx": nx, "stack_canary": canary, "pie": pie, "relro": relro,
        "stripped": stripped, "fortify": fortify, "fortify_functions": [],
        "rpath": rpath,
    }


def _run(monkeypatch, libs, tmp_path, results=None):
    """Drive analyze_elf_binaries with a controlled set of libraries.

    Real .so files (>64 bytes) are created so os.walk finds them, and _analyze_elf
    is stubbed to return the corresponding controlled analysis dict.
    """
    by_name = {}
    for lib in libs:
        name = lib["name"]
        by_name[name] = lib
        (tmp_path / name).write_bytes(b"\x7fELF" + b"\x00" * 128)

    def _fake_analyze(fpath, rel_path):
        base = os.path.basename(fpath)
        lib = dict(by_name[base])
        lib["path"] = rel_path
        return lib

    monkeypatch.setattr(elf_analyzer, "_analyze_elf", _fake_analyze)
    results = results if results is not None else {}
    results.setdefault("findings", [])
    elf_analyzer.analyze_elf_binaries(str(tmp_path), results)
    return results["findings"]


def _ids(findings):
    return {f.get("rule_id") for f in findings}


def _by_id(findings, rid):
    return [f for f in findings if f.get("rule_id") == rid]


# ── Flutter app: libapp.so reclassified ──────────────────────────────────────

def test_flutter_libapp_not_flagged_for_c_hardening(monkeypatch, tmp_path):
    libs = [
        _lib("libapp.so", canary=False, relro="none", fortify=False),  # Dart AOT snapshot
        _lib("libflutter.so"),                                          # fully hardened engine
    ]
    findings = _run(monkeypatch, libs, tmp_path)
    ids = _ids(findings)
    assert "elf_stack_canary_missing" not in ids, "libapp.so must not raise a canary finding"
    assert "elf_relro_missing" not in ids, "libapp.so must not raise a RELRO finding"
    aot = _by_id(findings, "elf_flutter_aot_snapshot")
    assert len(aot) == 1 and aot[0]["severity"] == "info"
    assert "libapp.so" in aot[0]["description"]


def test_flutter_summary_excludes_aot(monkeypatch, tmp_path):
    libs = [
        _lib("libapp.so", canary=False, relro="none"),
        _lib("libflutter.so"),
    ]
    findings = _run(monkeypatch, libs, tmp_path)
    summary = _by_id(findings, "elf_hardening_summary")[0]
    # Only libflutter.so is in scope; it is fully hardened → 1/1.
    assert "1/1 Fully Hardened" in summary["title"]
    assert "excluded" in summary["description"].lower()


def test_flutter_detected_via_framework_only(monkeypatch, tmp_path):
    # No libflutter.so binary, but the scan recorded the Flutter framework.
    libs = [_lib("libapp.so", canary=False, relro="none")]
    findings = _run(monkeypatch, libs, tmp_path, results={"framework": {"type": "flutter"}})
    ids = _ids(findings)
    assert "elf_stack_canary_missing" not in ids
    assert "elf_flutter_aot_snapshot" in ids


# ── Genuine C/C++ libraries unaffected ───────────────────────────────────────

def test_non_flutter_real_lib_still_flagged(monkeypatch, tmp_path):
    libs = [_lib("libtoolChecker.so", canary=False)]
    findings = _run(monkeypatch, libs, tmp_path)
    ids = _ids(findings)
    assert "elf_stack_canary_missing" in ids, "a real .so missing a canary must still be flagged"
    canary = _by_id(findings, "elf_stack_canary_missing")[0]
    assert canary["severity"] == "medium"
    assert "elf_flutter_aot_snapshot" not in ids


def test_flutter_real_lib_still_flagged(monkeypatch, tmp_path):
    # In a Flutter app, a genuine C/C++ lib lacking a canary is still flagged;
    # only libapp.so is excused.
    libs = [
        _lib("libapp.so", canary=False, relro="none"),
        _lib("libflutter.so"),
        _lib("libantihook_runtime.so", canary=False),
    ]
    findings = _run(monkeypatch, libs, tmp_path)
    canary = _by_id(findings, "elf_stack_canary_missing")
    assert canary, "genuine C lib without canary must still be flagged in a Flutter app"
    names = canary[0]["description"]
    assert "libantihook_runtime.so" in names and "libapp.so" not in names


def test_libapp_in_non_flutter_app_flagged(monkeypatch, tmp_path):
    # A libapp.so with NO Flutter signal (no libflutter.so, no framework) is not
    # assumed to be a Dart snapshot — treated as a normal library.
    libs = [_lib("libapp.so", canary=False)]
    findings = _run(monkeypatch, libs, tmp_path)
    ids = _ids(findings)
    assert "elf_stack_canary_missing" in ids
    assert "elf_flutter_aot_snapshot" not in ids


# ── helper units ─────────────────────────────────────────────────────────────

def test_is_flutter_aot_blob():
    assert elf_analyzer._is_flutter_aot_blob({"name": "libapp.so"}, True)
    assert not elf_analyzer._is_flutter_aot_blob({"name": "libapp.so"}, False)
    assert not elf_analyzer._is_flutter_aot_blob({"name": "libflutter.so"}, True)
    assert not elf_analyzer._is_flutter_aot_blob({"name": "libfoo.so"}, True)


def test_detect_flutter():
    assert elf_analyzer._detect_flutter([{"name": "libflutter.so"}, {"name": "libapp.so"}])
    assert elf_analyzer._detect_flutter([{"name": "libapp.so"}], {"app_info": {"framework": "Flutter"}})
    assert not elf_analyzer._detect_flutter([{"name": "libapp.so"}])


if __name__ == "__main__":
    import traceback
    # Minimal monkeypatch/tmp_path shim for standalone runs.
    import tempfile, pathlib

    class _MP:
        def __init__(self): self._orig = []
        def setattr(self, obj, name, val):
            self._orig.append((obj, name, getattr(obj, name)))
            setattr(obj, name, val)
        def undo(self):
            for obj, name, val in reversed(self._orig):
                setattr(obj, name, val)

    passed = 0
    for nm, fn in sorted(globals().items()):
        if nm.startswith("test_") and callable(fn):
            mp = _MP()
            try:
                import inspect
                params = inspect.signature(fn).parameters
                args = {}
                if "monkeypatch" in params: args["monkeypatch"] = mp
                if "tmp_path" in params:
                    args["tmp_path"] = pathlib.Path(tempfile.mkdtemp())
                fn(**args)
                print(f"ok  {nm}"); passed += 1
            except Exception:
                traceback.print_exc(); print(f"FAIL {nm}")
            finally:
                mp.undo()
    print(f"{passed} passed")

"""
Regression: two precision bugs in taint_analyzer.

BUG A — substring sink/source matching. Log method patterns "e"/"i" are substrings
of "isLoggable", so android.util.Log.isLoggable was collected as a Logging sink;
a source method "get" would match "getClass". Matching is now EXACT for named
methods, plus an explicit non-sink exclusion set.

BUG B — library→library flows reported as app taint. A flow whose entire call chain
is library/framework-owned is framework-internal logging, not an app vuln, and is
dropped; a flow touching app code is kept and carries owner_type.

These assertions fail on the old behavior and pass on the new. They mock the tiny
androguard surface the collectors use, and exercise the real Ownership Engine.
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import taint_analyzer as ta  # noqa: E402


# ── minimal androguard mocks ─────────────────────────────────────────────────
class _M:
    def __init__(self, cls, name, callers=()):
        self._cls, self.name, self._callers = cls, name, list(callers)

    def get_class_name(self): return self._cls
    def get_name(self): return self.name
    def get_descriptor(self): return "()V"
    def get_xref_from(self): return [(None, c, None) for c in self._callers]


class _C:
    def __init__(self, name, methods): self.name, self._m = name, methods
    def get_methods(self): return self._m


class _Dx:
    def __init__(self, classes): self._c = classes
    def get_classes(self): return self._c


# ── BUG A: exact sink matching + non-sink exclusion ──────────────────────────

def test_isloggable_not_collected_as_sink():
    log = _C("Landroid/util/Log;", [
        _M("Landroid/util/Log;", "d"),
        _M("Landroid/util/Log;", "e"),
        _M("Landroid/util/Log;", "i"),
        _M("Landroid/util/Log;", "isLoggable"),        # boolean read — NOT a sink
        _M("Landroid/util/Log;", "getStackTraceString"),  # formatter — NOT a sink
    ])
    sinks = ta._collect_sink_refs(_Dx([log]), ta.SINKS)
    keys = list(sinks)
    assert any(k.endswith("->e()V") for k in keys), "Log.e must still be a sink"
    assert any(k.endswith("->d()V") for k in keys), "Log.d must still be a sink"
    assert not any("isLoggable" in k for k in keys), "isLoggable must NOT be a sink"
    assert not any("getStackTraceString" in k for k in keys)


def test_source_get_is_exact_not_substring():
    app_caller = _M("Lcom/app/Reader;", "readBundle")
    other_caller = _M("Lcom/app/Reflect;", "reflect")
    bundle = _C("Landroid/os/Bundle;", [
        _M("Landroid/os/Bundle;", "get", callers=[app_caller]),
        _M("Landroid/os/Bundle;", "getClass", callers=[other_caller]),  # must NOT match "get"
    ])
    refs = ta._collect_method_refs(_Dx([bundle]), ta.SOURCES)
    # The Bundle.get source key collects only get's caller, never getClass's.
    key = ("android/os/Bundle", "get", "Bundle.get", "User Input")
    assert key in refs
    callers = refs[key]
    assert app_caller in callers
    assert other_caller not in callers, "getClass must not be matched by source 'get'"


# ── BUG B: ownership filter ──────────────────────────────────────────────────

def _lookup(app_package="com.ibsplc.mobile"):
    results = {"app_info": {"package": app_package}, "platform": "android",
               "attack_surface": {}}
    return ta._OwnershipLookup(results)


def test_library_owner_predicate():
    assert ta._is_library_owner("ThirdPartySDK")
    assert ta._is_library_owner("AndroidFramework")
    assert not ta._is_library_owner("Application")
    assert not ta._is_library_owner("Unknown")


def test_all_library_chain_dropped():
    lk = _lookup()
    chain = ["androidx.fragment.app.FragmentManager", "android.util.Log"]
    owners = [lk.owner_type(c) for c in chain]
    assert all(ta._is_library_owner(o) for o in owners), \
        f"androidx→Log chain should be all-library, got {owners}"


def test_app_owned_source_kept_with_owner_type():
    lk = _lookup(app_package="com.ibsplc.mobile")
    chain = ["com.ibsplc.mobile.LocationLogger", "android.util.Log"]
    owners = [lk.owner_type(c) for c in chain]
    assert not all(ta._is_library_owner(o) for o in owners), "app-touching flow must be kept"
    assert owners[0] == "Application", f"source class owner should be Application, got {owners[0]}"


def test_obfuscated_app_class_survives():
    # Flutter/AOT-obfuscated app classes (Z.S.A0, M0.a.h0) classify Unknown — NOT
    # library — so a GPS→Log.e flow through them is kept, not dropped.
    lk = _lookup()
    for cls in ("Z.S.A0", "M0.a.h0"):
        assert not ta._is_library_owner(lk.owner_type(cls)), f"{cls} must survive the filter"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")

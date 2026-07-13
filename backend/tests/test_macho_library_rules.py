"""Rules that do not apply to a dynamic library must not fire on one (RUN 15).

These two rules produced 74 of this app's 87 findings:
  * macho_no_pie          — 39 rows, at INFO, whose own description said "expected and not a
                            hardening gap". A finding that says it is not a problem is noise.
  * macho_multiple_rpaths — 35 rows, one per vendor framework. @executable_path/@loader_path
                            RPATHs are exactly what Xcode emits for a bundled framework.

MH_PIE is meaningful only for the MAIN EXECUTABLE image; a dylib relocates regardless. The
dylib-hijacking surface is decided by the main executable's search path. So both rules now apply
to the main executable ONLY — decided from the Mach-O header's FILE TYPE (content), not the path.
"""
from analyzers.lief_analyzer import _is_library_macho


class _Hdr:
    def __init__(self, ft):
        self.file_type = ft


class _M:
    def __init__(self, ft):
        self.header = _Hdr(ft)


def test_dylib_is_a_library():
    assert _is_library_macho(_M("FILE_TYPES.DYLIB")) is True


def test_bundle_is_a_library():
    assert _is_library_macho(_M("MH_BUNDLE")) is True


def test_main_executable_is_not_a_library():
    assert _is_library_macho(_M("FILE_TYPES.EXECUTE")) is False


def test_file_type_beats_the_path():
    # A framework-shaped PATH holding an EXECUTE image is still the executable, and an
    # executable-shaped path holding a DYLIB is still a library. Content wins.
    assert _is_library_macho(_M("EXECUTE"), "Frameworks/X.framework/X") is False
    assert _is_library_macho(_M("DYLIB"), "Runner") is True


def test_path_fallback_when_the_header_is_unreadable():
    class _Broken:
        header = None
    assert _is_library_macho(_Broken(), "Frameworks/App.framework/App") is True
    assert _is_library_macho(_Broken(), "libfoo.dylib") is True
    assert _is_library_macho(_Broken(), "Runner") is False

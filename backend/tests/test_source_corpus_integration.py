"""Integration proof for the SourceCorpus wiring.

Two things must hold for the Priority-1 refactor to be safe AND worthwhile:

  1. **Identical detections.** Running the real analyzers with ONE shared corpus
     must produce the exact same output as running each with its own throwaway
     corpus (the pre-refactor behavior). This is the "no detection change" gate.

  2. **Real I/O reduction.** With a shared corpus the decompiled tree is walked
     ONCE and each file read ONCE, instead of once per analyzer. We assert the
     physical os.walk / open counts collapse.

The analyzers exercised here are the pure-Python text scanners the orchestrator
runs on every scan (secrets, IPs, JWTs, endpoints, strings, SAST). androguard is
not required.
"""
import os
import sys
import builtins

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzers.source_corpus import SourceCorpus  # noqa: E402
from analyzers import evidence_scanner, network_intel, cloud_config, endpoint_intel, string_analyzer, code_analyzer  # noqa: E402


def _build_tree(base):
    """A miniature jadx + apktool tree with real, detectable signals."""
    jadx = os.path.join(base, "jadx")
    apktool = os.path.join(base, "apktool")
    for d in (
        os.path.join(jadx, "com", "app"),
        os.path.join(apktool, "res", "values"),
        os.path.join(apktool, "smali", "com", "app"),
        os.path.join(apktool, "smali", "kotlin"),  # noise dir — must be skipped
    ):
        os.makedirs(d, exist_ok=True)
    with open(os.path.join(jadx, "com", "app", "Api.java"), "w") as f:
        f.write(
            'class Api {\n'
            '  String aws = "AKIAIOSFODNN7EXAMPLE";\n'
            '  String url = "https://api.acmecorp.io/v1/login";\n'
            '  String host = "10.11.12.13";\n'
            '  String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEFghiJKLmnoPQRstuv";\n'
            '  String fb = "https://myproj.firebaseio.com";\n'
            '  String bucket = "myproj.appspot.com";\n'
            '}\n'
        )
    with open(os.path.join(apktool, "res", "values", "strings.xml"), "w") as f:
        # Google API key = "AIza" + exactly 35 chars (mixed-case → passes entropy).
        f.write('<resources><string name="api_key">AIzaa1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R</string></resources>')
    with open(os.path.join(apktool, "smali", "com", "app", "A.smali"), "w") as f:
        f.write('const-string v0, "https://tracker.example.net/collect"\n')
    with open(os.path.join(apktool, "smali", "kotlin", "Noise.smali"), "w") as f:
        f.write('const-string v0, "AKIANOISENOISENOISE0"\n')  # in skip dir — must NOT surface
    return [jadx, apktool]


def _run_all(dirs, corpus):
    """Run every migrated consumer, returning a comparable result bundle."""
    secrets = evidence_scanner.scan_directory_for_secrets("", dirs, corpus=corpus)
    ips = evidence_scanner.scan_directory_for_ips("", dirs, corpus=corpus)
    jwts = evidence_scanner.scan_directory_for_jwts("", dirs, corpus=corpus)
    ni_ips = network_intel.extract_ips(dirs[0], dirs[1:], corpus=corpus)
    cc = cloud_config.scan(dirs[0], dirs[1:], corpus=corpus)
    eps = endpoint_intel.extract_endpoints(dirs[0], dirs[1:], corpus=corpus)
    strings = string_analyzer.analyze_strings(dirs[0], "android", corpus=corpus)
    sast_res = {"findings": []}
    code_analyzer.run_android_sast(dirs, sast_res, corpus=corpus)
    return {
        "secrets": secrets, "ips": ips, "jwts": jwts, "ni_ips": ni_ips,
        "cc": cc, "eps": eps, "strings": strings, "sast": sast_res["findings"],
    }


def test_shared_corpus_matches_per_consumer(tmp_path):
    dirs = _build_tree(str(tmp_path))

    # Legacy path: each analyzer gets its own throwaway corpus (== pre-refactor).
    legacy = _run_all(dirs, corpus=None)
    # New path: one shared corpus across every analyzer.
    shared = SourceCorpus()
    new = _run_all(dirs, corpus=shared)

    # Detections must be byte-for-byte identical.
    assert new == legacy

    # And the signals we planted are actually found (guards against "identical
    # because both are empty").
    assert any(s["name"] == "AWS Access Key ID" for s in new["secrets"])
    assert any(s["name"] == "Google API Key" for s in new["secrets"])
    assert new["jwts"] and new["jwts"][0]["value"].startswith("eyJ")
    assert any(i["ip"] == "10.11.12.13" for i in new["ni_ips"])
    assert any("api.acmecorp.io" in e for e in new["eps"])

    # The skip-dir secret must NOT appear (proves filtering is preserved).
    assert not any("NOISE" in s.get("value", "") for s in new["secrets"])


def test_shared_corpus_concurrent_matches_serial(tmp_path):
    """The android/iOS orchestrators run these analyzers on a thread pool over one
    shared corpus. The corpus is lock-free (path-keyed, idempotent reads), so a
    concurrent run must still equal the serial legacy result."""
    from concurrent.futures import ThreadPoolExecutor
    dirs = _build_tree(str(tmp_path))
    legacy = _run_all(dirs, corpus=None)

    shared = SourceCorpus()
    # Pre-warm the walk exactly like analyze_ipa does, then hammer every analyzer
    # concurrently sharing the one corpus.
    for d in dirs:
        for _ in shared.walk(d):
            pass
    tasks = {
        "secrets": lambda: evidence_scanner.scan_directory_for_secrets("", dirs, corpus=shared),
        "ips":     lambda: evidence_scanner.scan_directory_for_ips("", dirs, corpus=shared),
        "jwts":    lambda: evidence_scanner.scan_directory_for_jwts("", dirs, corpus=shared),
        "ni_ips":  lambda: network_intel.extract_ips(dirs[0], dirs[1:], corpus=shared),
        "cc":      lambda: cloud_config.scan(dirs[0], dirs[1:], corpus=shared),
        "eps":     lambda: endpoint_intel.extract_endpoints(dirs[0], dirs[1:], corpus=shared),
        "strings": lambda: string_analyzer.analyze_strings(dirs[0], "android", corpus=shared),
    }
    with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        futs = {k: pool.submit(fn) for k, fn in tasks.items()}
        concurrent = {k: f.result() for k, f in futs.items()}

    for key, val in concurrent.items():
        assert val == legacy[key], f"concurrent {key} diverged from serial"


def test_shared_corpus_walks_each_dir_once(tmp_path):
    dirs = _build_tree(str(tmp_path))
    shared = SourceCorpus()
    _run_all(dirs, corpus=shared)
    # Two source roots (jadx, apktool) → each walked exactly once despite 8
    # analyzer invocations that each traverse them.
    assert shared.stats()["dirs_walked"] == 2


def test_shared_corpus_reduces_physical_io(tmp_path):
    dirs = _build_tree(str(tmp_path))

    real_walk = os.walk
    real_open = builtins.open

    def counting_walk(*a, **k):
        counting_walk.n += 1
        return real_walk(*a, **k)

    def counting_open(*a, **k):
        # Count only reads of files under our tree (ignore unrelated opens).
        try:
            path = a[0]
            if isinstance(path, (str, bytes, os.PathLike)) and str(path).startswith(str(tmp_path)):
                counting_open.n += 1
        except Exception:
            pass
        return real_open(*a, **k)

    # ── Legacy: each analyzer walks + reads on its own ──────────────────────
    counting_walk.n = 0
    counting_open.n = 0
    os.walk = counting_walk
    builtins.open = counting_open
    try:
        _run_all(dirs, corpus=None)
    finally:
        os.walk = real_walk
        builtins.open = real_open
    legacy_walks, legacy_reads = counting_walk.n, counting_open.n

    # ── Shared: one corpus for all analyzers ────────────────────────────────
    counting_walk.n = 0
    counting_open.n = 0
    os.walk = counting_walk
    builtins.open = counting_open
    try:
        _run_all(dirs, corpus=SourceCorpus())
    finally:
        os.walk = real_walk
        builtins.open = real_open
    shared_walks, shared_reads = counting_walk.n, counting_open.n

    # The shared corpus must strictly cut both physical walks and reads.
    assert shared_walks < legacy_walks
    assert shared_reads < legacy_reads
    # Concretely: 2 dirs walked once each under the shared corpus.
    assert shared_walks == 2
    print(f"\nI/O: walks {legacy_walks}->{shared_walks}, "
          f"file reads {legacy_reads}->{shared_reads}")

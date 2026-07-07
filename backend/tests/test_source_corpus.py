"""Proof tests for SourceCorpus: it must reproduce os.walk / open exactly.

The whole safety argument for the Priority-1 refactor is "detections are
identical because the corpus returns byte-for-byte what os.walk / open returned,
just once." These tests lock that invariant.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzers.source_corpus import SourceCorpus  # noqa: E402


def _make_tree(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b").mkdir()
    (tmp_path / "empty").mkdir()
    (tmp_path / "root.java").write_text("class Root { String k = \"AKIAABCDEFGHIJKLMNOP\"; }")
    (tmp_path / "a" / "x.kt").write_text("val u = \"http://10.0.0.5/api\"\n")
    (tmp_path / "a" / "b" / "deep.xml").write_text("<x>token</x>")
    (tmp_path / "bin.dex").write_bytes(b"\x00\x01hello\x02world\xff")
    return tmp_path


def test_walk_matches_oswalk_exactly(tmp_path):
    _make_tree(tmp_path)
    corpus = SourceCorpus()
    got = [(r, subs, files) for r, subs, files in corpus.walk(str(tmp_path))]
    expected = [(r, subs, files) for r, subs, files in os.walk(str(tmp_path))]
    assert got == expected


def test_walk_is_cached_and_replayable(tmp_path):
    _make_tree(tmp_path)
    corpus = SourceCorpus()
    first = list(corpus.walk(str(tmp_path)))
    # Delete a file after the first walk; the cached replay must be unchanged.
    os.remove(os.path.join(str(tmp_path), "root.java"))
    second = list(corpus.walk(str(tmp_path)))
    assert first == second
    assert corpus.stats()["dirs_walked"] == 1


def test_walk_yields_mutable_copies(tmp_path):
    _make_tree(tmp_path)
    corpus = SourceCorpus()
    # Prune in-place like a consumer does; must not corrupt the cache.
    for _root, subdirs, _files in corpus.walk(str(tmp_path)):
        subdirs[:] = []
    again = list(corpus.walk(str(tmp_path)))
    expected = [(r, subs, files) for r, subs, files in os.walk(str(tmp_path))]
    assert again == expected


def test_read_text_matches_open(tmp_path):
    _make_tree(tmp_path)
    corpus = SourceCorpus()
    for name in ("root.java", os.path.join("a", "x.kt"), os.path.join("a", "b", "deep.xml")):
        p = os.path.join(str(tmp_path), name)
        with open(p, "r", errors="replace") as f:
            expected = f.read()
        assert corpus.read_text(p) == expected
        # Second call served from cache — still identical.
        assert corpus.read_text(p) == expected


def test_read_text_respects_max_bytes(tmp_path):
    _make_tree(tmp_path)
    corpus = SourceCorpus()
    big = os.path.join(str(tmp_path), "root.java")
    size = os.path.getsize(big)
    assert corpus.read_text(big, max_bytes=size - 1) is None   # over cap → None
    assert corpus.read_text(big, max_bytes=size) is not None   # exactly at cap → ok


def test_read_text_cap_after_uncapped_cache(tmp_path):
    _make_tree(tmp_path)
    corpus = SourceCorpus()
    big = os.path.join(str(tmp_path), "root.java")
    full = corpus.read_text(big)                # cache full content, no cap
    assert full is not None
    # A stricter later caller must still be denied by its own cap.
    assert corpus.read_text(big, max_bytes=1) is None


def test_read_text_missing_file(tmp_path):
    corpus = SourceCorpus()
    assert corpus.read_text(os.path.join(str(tmp_path), "nope.java")) is None


def test_read_bytes_matches_open(tmp_path):
    _make_tree(tmp_path)
    corpus = SourceCorpus()
    p = os.path.join(str(tmp_path), "bin.dex")
    with open(p, "rb") as f:
        expected = f.read()
    assert corpus.read_bytes(p) == expected
    assert corpus.read_bytes(p, max_bytes=4) == expected[:4]


def test_budget_stops_caching_but_still_serves(tmp_path):
    _make_tree(tmp_path)
    corpus = SourceCorpus(text_budget=1)   # tiny budget: nothing gets cached
    p = os.path.join(str(tmp_path), "root.java")
    with open(p, "r", errors="replace") as f:
        expected = f.read()
    assert corpus.read_text(p) == expected            # still correct
    assert corpus.stats()["text_files_cached"] == 0   # but not retained

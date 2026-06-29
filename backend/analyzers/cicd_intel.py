"""
CI/CD Security Intelligence (Beetle 2.6) — static, network-free.

A first-class detection engine with the same shape as the mobile analyzers: it
scans a repository tree for CI/CD pipeline + workflow configuration and emits
CANONICAL findings that flow through the EXISTING pipeline (Finding Fusion →
Ownership → Evidence → Confidence → Attack Chains → Reports). No separate
reporting system, no duplicated finding model.

Phase 1 platforms: GitHub Actions, GitLab CI, Azure DevOps, Jenkins, CircleCI,
Bitbucket Pipelines, Drone, Buildkite, Tekton, and generic YAML pipelines.

Architecture — deliberately extensible so future sources (Trivy / Grype / Syft /
SBOM, Terraform / CloudFormation / Kubernetes / Helm IaC, OPA policy) plug into
the SAME engine without redesign:

  * PLATFORMS   — (id, label, predicate(rel_path)) decide which platform owns a file.
  * LINE_RULES  — per-line regex detectors; each yields one canonical finding.
    A rule may gate on platform id(s) via ``platforms`` and refine via ``reject``.
  * REPO_RULES  — repository-level checks (e.g. "no secret scanning configured").
  * analyze_tree(root) — walk, classify, run rules, return findings + metadata.

Findings are intentionally low-false-positive: detectors target CI/CD-specific,
high-signal constructs (mutable action refs, ``curl | bash``, ``permissions:
write-all``, ``docker.sock`` mounts, …). Generic in-repo secrets are left to the
existing Secret Intelligence engine when this runs inside a full repository scan,
so there is no duplicate secret logic; the rules here only flag hardcoded
credentials in CI/CD-specific constructs (``env:`` blocks, inline ``with:`` inputs).
"""
from __future__ import annotations

import os
import re

CICD_INTEL_VERSION = "1.0.0"
SOURCE = "CI/CD"

# ── Platform detection ───────────────────────────────────────────────────────
# predicate receives a forward-slashed, lowercased repo-relative path.
PLATFORMS = [
    ("github_actions", "GitHub Actions",
     lambda p: p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))),
    ("gitlab_ci", "GitLab CI",
     lambda p: os.path.basename(p) == ".gitlab-ci.yml" or p.endswith("/.gitlab-ci.yml")),
    ("azure_pipelines", "Azure DevOps",
     lambda p: os.path.basename(p) in ("azure-pipelines.yml", "azure-pipelines.yaml")
     or os.path.basename(p).startswith("azure-pipelines")),
    ("jenkins", "Jenkins",
     lambda p: os.path.basename(p) == "jenkinsfile" or p.endswith("/jenkinsfile")
     or os.path.basename(p).startswith("jenkinsfile")),
    ("circleci", "CircleCI",
     lambda p: p.endswith(".circleci/config.yml") or "/.circleci/" in f"/{p}"),
    ("bitbucket", "Bitbucket Pipelines",
     lambda p: os.path.basename(p) == "bitbucket-pipelines.yml"),
    ("drone", "Drone",
     lambda p: os.path.basename(p) == ".drone.yml"),
    ("buildkite", "Buildkite",
     lambda p: os.path.basename(p) in ("buildkite.yml", "pipeline.yml")
     and "buildkite" in p),
    ("tekton", "Tekton",
     lambda p: "/tekton/" in f"/{p}" and p.endswith((".yml", ".yaml"))),
]

# Extensions / names that could be a generic pipeline YAML if nothing else matched.
_GENERIC_YAML = (".yml", ".yaml")
_PIPELINE_HINT = re.compile(
    r"^\s*(stages|jobs|steps|pipelines|workflows|pipeline|tasks)\s*:", re.M)

# Files big enough to be data dumps are skipped.
_MAX_BYTES = 1 * 1024 * 1024


def classify_platform(rel_path: str) -> str | None:
    p = rel_path.replace("\\", "/").lower()
    for pid, _label, pred in PLATFORMS:
        try:
            if pred(p):
                return pid
        except Exception:
            continue
    return None


def _is_generic_pipeline(rel_path: str, content: str) -> bool:
    p = rel_path.replace("\\", "/").lower()
    if not p.endswith(_GENERIC_YAML):
        return False
    return bool(_PIPELINE_HINT.search(content or ""))


PLATFORM_LABELS = {pid: label for pid, label, _ in PLATFORMS}
PLATFORM_LABELS["generic_yaml"] = "Generic Pipeline"


# ── Helpers ──────────────────────────────────────────────────────────────────
_SECRET_REF = re.compile(r"\$\{\{?\s*secrets\.|\$\{?[A-Z_][A-Z0-9_]*\}?|vault:|\bsecrets\.", re.I)
_SHA_RE = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
_FLOATING_REFS = {"main", "master", "head", "latest", "develop", "dev"}


def _looks_like_ref(value: str) -> bool:
    return bool(_SECRET_REF.search(value or ""))


# ── Per-line rules ───────────────────────────────────────────────────────────
# Each rule: id, title, severity, cwe, owasp, category, regex, description,
# recommendation, references, optional platforms (gate), optional handler.
def _r(rid, title, severity, cwe, owasp, pattern, description, recommendation,
       references, *, platforms=None, category="CI/CD Security", flags=re.I):
    return {
        "id": rid, "title": title, "severity": severity, "cwe": cwe, "owasp": owasp,
        "category": category, "re": re.compile(pattern, flags),
        "description": description, "recommendation": recommendation,
        "references": references, "platforms": platforms,
    }


LINE_RULES = [
    # ── Dangerous workflow permissions ──────────────────────────────────────
    _r("CICD_PERMISSIONS_WRITE_ALL", "Workflow grants write-all permissions", "high",
       "CWE-732", "CICD-SEC-1",
       r"permissions\s*:\s*write-all",
       "The workflow grants `write-all` token permissions, giving every job full "
       "read/write access to the repository (contents, packages, deployments, …).",
       "Apply least privilege: set top-level `permissions: {}` and grant only the "
       "specific scopes each job needs.",
       ["https://docs.github.com/actions/security-guides/automatic-token-authentication",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/"],
       platforms=["github_actions"]),
    _r("CICD_PERMISSIONS_CONTENTS_WRITE", "Workflow grants contents: write", "medium",
       "CWE-732", "CICD-SEC-1",
       r"^\s*contents\s*:\s*write\s*$",
       "A job/workflow grants `contents: write`, allowing it to push commits, tags "
       "or releases. Combined with untrusted input this enables repo tampering.",
       "Grant `contents: write` only to the specific job that needs it, and prefer "
       "read-only tokens elsewhere.",
       ["https://docs.github.com/actions/security-guides/automatic-token-authentication"],
       platforms=["github_actions"]),
    _r("CICD_OIDC_IDTOKEN_WRITE", "Workflow requests id-token: write (OIDC)", "low",
       "CWE-269", "CICD-SEC-7",
       r"^\s*id-token\s*:\s*write\s*$",
       "`id-token: write` lets the workflow mint an OIDC token for cloud auth. This "
       "is the recommended keyless pattern, but a too-broadly-scoped trust policy or "
       "use in a workflow that runs untrusted code can be abused for cloud access.",
       "Confirm the cloud trust policy is scoped to this repo/branch/environment, and "
       "only enable id-token in workflows that do not execute untrusted PR code.",
       ["https://docs.github.com/actions/deployment/security-hardening-your-deployments"],
       platforms=["github_actions"]),
    # ── Untrusted / floating action versions ────────────────────────────────
    # Handled specially (needs ref parsing) — see _scan_uses.
    # ── Remote script execution (curl|bash) ─────────────────────────────────
    _r("CICD_REMOTE_SCRIPT_EXEC", "Remote script piped to a shell (curl | bash)", "high",
       "CWE-494", "CICD-SEC-4",
       r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b",
       "A script is downloaded and piped straight into a shell. A compromised or "
       "MITM'd URL results in arbitrary code execution on the runner with full access "
       "to the pipeline's secrets and tokens.",
       "Pin and verify what you execute: download to a file, verify a checksum/signature, "
       "then run it. Prefer official, version-pinned package installs.",
       ["https://owasp.org/www-project-top-10-ci-cd-security-risks/"]),
    # ── Dangerous shell usage ───────────────────────────────────────────────
    _r("CICD_CHMOD_777", "World-writable permissions (chmod 777)", "medium",
       "CWE-732", "CICD-SEC-1",
       r"chmod\s+(-[a-zA-Z]+\s+)*0?777\b",
       "`chmod 777` makes files world-writable, allowing any process on the runner to "
       "tamper with build inputs or outputs.",
       "Grant the narrowest permissions required (e.g. 755 for executables, 644 for files).",
       ["https://cwe.mitre.org/data/definitions/732.html"]),
    _r("CICD_SUDO_USAGE", "Privilege escalation via sudo in pipeline", "low",
       "CWE-250", "CICD-SEC-1",
       r"(?<![\w.\-])sudo\s+\S",
       "The pipeline uses `sudo`, running steps with elevated privileges. On a "
       "self-hosted runner this widens the blast radius of a compromised step.",
       "Avoid `sudo` in CI; use rootless tooling or pre-provisioned images with the "
       "needed packages.",
       ["https://owasp.org/www-project-top-10-ci-cd-security-risks/"]),
    _r("CICD_PRIVILEGED_CONTAINER", "Privileged container in pipeline", "high",
       "CWE-250", "CICD-SEC-1",
       r"privileged\s*:\s*true",
       "A privileged container disables most isolation and can access host devices — a "
       "container escape gives full control of the runner host.",
       "Avoid privileged mode; grant only the specific capabilities required.",
       ["https://owasp.org/www-project-top-10-ci-cd-security-risks/"]),
    _r("CICD_DOCKER_SOCK_MOUNT", "Docker socket mounted into a job", "high",
       "CWE-250", "CICD-SEC-1",
       r"/var/run/docker\.sock",
       "Mounting `/var/run/docker.sock` gives the job root-equivalent control of the "
       "Docker daemon (and therefore the host).",
       "Use a rootless/isolated builder (e.g. BuildKit, Kaniko) instead of mounting "
       "the host Docker socket.",
       ["https://owasp.org/www-project-top-10-ci-cd-security-risks/"]),
    # ── Docker :latest images ───────────────────────────────────────────────
    _r("CICD_DOCKER_LATEST", "Container image uses mutable :latest tag", "low",
       "CWE-1357", "CICD-SEC-3",
       r"image\s*:\s*[\"']?[\w./\-]+:latest\b",
       "A `:latest` image tag is mutable — the build is not reproducible and a "
       "compromised upstream tag silently changes what runs.",
       "Pin images to an immutable digest (`image@sha256:…`) or a specific version tag.",
       ["https://owasp.org/www-project-top-10-ci-cd-security-risks/"]),
    # ── Secret exposure ─────────────────────────────────────────────────────
    _r("CICD_SECRET_ECHO", "Secret printed to the build log", "high",
       "CWE-532", "CICD-SEC-6",
       r"(echo|printf|print)\b[^\n]*\$\{\{?\s*secrets\.",
       "A secret is echoed/printed, which writes it to the (often world-readable) "
       "build log, leaking the credential.",
       "Never print secrets. Use masked environment variables and rely on the CI "
       "provider's secret masking.",
       ["https://owasp.org/www-project-top-10-ci-cd-security-risks/"]),
    # ── Self-hosted runner ──────────────────────────────────────────────────
    _r("CICD_SELF_HOSTED_RUNNER", "Self-hosted runner in use", "low",
       "CWE-693", "CICD-SEC-5",
       r"runs-on\s*:\s*\[?[\"']?self-hosted",
       "Self-hosted runners persist state between jobs and, on public repos, can "
       "execute untrusted PR code on your infrastructure.",
       "Use ephemeral/just-in-time runners, isolate them from production, and never run "
       "untrusted PR workflows on persistent self-hosted runners.",
       ["https://docs.github.com/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security"],
       platforms=["github_actions"]),
]


# Hardcoded credential in a CI/CD env/with construct (not a ${{ secrets.* }} / $VAR ref).
_HARDCODED_CRED = re.compile(
    r"""(?ix)
    (?P<key>password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|
        auth[_-]?token|private[_-]?key)
    \s*[:=]\s*
    (?P<q>["']?)(?P<val>[^\s"'#]{6,})(?P=q)
    """)
_AWS_AKIA = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GH_TOKEN = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")


def _scan_secrets(rel_path, line, lineno):
    out = []
    low = line.strip()
    if _AWS_AKIA.search(line):
        out.append(("CICD_HARDCODED_AWS_KEY", "Hardcoded AWS access key in pipeline",
                    "critical", "CWE-798", "CICD-SEC-6", line))
    if _GH_TOKEN.search(line):
        out.append(("CICD_HARDCODED_GH_TOKEN", "Hardcoded token in pipeline",
                    "critical", "CWE-798", "CICD-SEC-6", line))
    if _PRIVATE_KEY.search(line):
        out.append(("CICD_HARDCODED_PRIVATE_KEY", "Hardcoded private key in pipeline",
                    "critical", "CWE-798", "CICD-SEC-6", line))
    m = _HARDCODED_CRED.search(line)
    if m:
        val = m.group("val")
        # Skip provider secret refs / env-var indirection / obvious placeholders.
        if not _looks_like_ref(val) and not val.startswith(("$", "{{")) \
                and val.lower() not in ("true", "false", "null", "none", "changeme", "example"):
            out.append(("CICD_HARDCODED_CREDENTIAL",
                        f"Hardcoded credential in pipeline ({m.group('key').lower()})",
                        "high", "CWE-798", "CICD-SEC-6", line))
    return out


_SECRET_REFS_DOC = ["https://owasp.org/www-project-top-10-ci-cd-security-risks/"]


def _uses_finding(rel_path, action, ref, line, lineno):
    """Classify a GitHub Actions ``uses:`` reference by pinning quality."""
    if action.startswith(("./", "docker://")):
        return None  # local action / docker handled elsewhere
    ref_l = ref.lower()
    if ref_l in _FLOATING_REFS:
        return ("CICD_ACTION_FLOATING_REF",
                f"Action pinned to a mutable ref (@{ref})", "high",
                "CWE-829", "CICD-SEC-3",
                f"`{action}` is referenced at the mutable ref `@{ref}`. The owner (or an "
                f"attacker who compromises it) can change what runs at any time.",
                "Pin third-party actions to a full commit SHA (and optionally a comment "
                "with the version).")
    if not _SHA_RE.match(ref):
        return ("CICD_ACTION_UNPINNED",
                f"Action not pinned to a commit SHA (@{ref})", "low",
                "CWE-829", "CICD-SEC-3",
                f"`{action}@{ref}` is pinned to a tag, which is mutable — a retagged "
                f"release silently changes the executed code.",
                "For supply-chain integrity, pin third-party actions to a full commit SHA.")
    return None


_USES_RE = re.compile(r"^\s*-?\s*uses\s*:\s*[\"']?([^\s\"'@]+)@([^\s\"'#]+)", re.I)


def _make_finding(rid, title, severity, cwe, owasp, category, rel_path, lineno,
                  snippet, description, recommendation, references, platform):
    return {
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "recommendation": recommendation,
        "file_path": rel_path,
        "line": lineno,
        "snippet": snippet.strip()[:240],
        "file_evidence": [{"path": rel_path, "lines": [lineno], "snippet": snippet.strip()[:240]}],
        "confidence": 90,
        "exploitability": 60,
        "validation_status": "validated",
        "source": SOURCE,
        "cwe": cwe,
        "owasp": owasp,
        "references": references,
        "rule_id": rid,
        "cicd_platform": platform,
    }


# ── Repository-level (absence) checks ────────────────────────────────────────
_PRACTICE_SIGNALS = {
    "secret_scanning": re.compile(r"gitleaks|trufflehog|detect-secrets|secret[-_]?scan", re.I),
    "sast": re.compile(r"codeql|semgrep|sonarqube|sonarcloud|snyk\s+code|bandit|\bsast\b", re.I),
    "dependency_scanning": re.compile(r"dependabot|renovate|snyk|osv-scanner|trivy|grype|dependency[-_]?(scan|review)", re.I),
    "sbom": re.compile(r"\bsbom\b|syft|cyclonedx|spdx", re.I),
    "signing_provenance": re.compile(r"cosign|sigstore|slsa|provenance|attest", re.I),
}
_PRACTICE_META = {
    "secret_scanning": ("No secret scanning configured in CI/CD", "medium", "CWE-798",
                        "Add a secret-scanning step (e.g. Gitleaks/TruffleHog) so committed "
                        "credentials are caught before release."),
    "sast": ("No SAST configured in CI/CD", "low", "CWE-1395",
             "Add static analysis (e.g. CodeQL/Semgrep) to the pipeline to catch code-level "
             "vulnerabilities automatically."),
    "dependency_scanning": ("No dependency scanning configured in CI/CD", "medium", "CWE-1104",
                            "Enable dependency scanning (Dependabot/Renovate/OSV/Trivy) to detect "
                            "vulnerable and outdated dependencies."),
    "sbom": ("No SBOM generation in CI/CD", "low", "CWE-1357",
             "Generate an SBOM (Syft/CycloneDX) during the build for supply-chain transparency."),
    "signing_provenance": ("No artifact signing / provenance in CI/CD", "low", "CWE-345",
                           "Sign artifacts and emit build provenance (Cosign/Sigstore/SLSA) so "
                           "consumers can verify integrity."),
}


def analyze_tree(root: str) -> dict:
    """Scan a repository tree. Returns
    ``{"findings": [...], "platforms": [...], "files": [...]}``."""
    findings: list[dict] = []
    platforms_seen: set[str] = set()
    pipeline_files: list[str] = []
    practice_hits: set[str] = set()
    corpus_for_practices: list[str] = []

    if not root or not os.path.isdir(root):
        return {"findings": [], "platforms": [], "files": []}

    for dirpath, dirnames, filenames in os.walk(root):
        # Skip VCS / dependency dirs — never pipeline config, and huge.
        dirnames[:] = [d for d in dirnames if d not in (
            ".git", "node_modules", "vendor", ".venv", "venv", "dist", "build")]
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            rel = os.path.relpath(fpath, root).replace("\\", "/")
            platform = classify_platform(rel)
            try:
                if os.path.getsize(fpath) > _MAX_BYTES:
                    continue
                with open(fpath, "r", errors="replace") as f:
                    content = f.read()
            except OSError:
                continue

            if platform is None and _is_generic_pipeline(rel, content):
                platform = "generic_yaml"
            if platform is None:
                continue

            platforms_seen.add(platform)
            pipeline_files.append(rel)
            corpus_for_practices.append(content)
            for key, rx in _PRACTICE_SIGNALS.items():
                if rx.search(content):
                    practice_hits.add(key)

            lines = content.splitlines()
            for i, line in enumerate(lines, start=1):
                # Secrets / hardcoded creds (CI/CD constructs).
                for rid, title, sev, cwe, owasp, snip in _scan_secrets(rel, line, i):
                    findings.append(_make_finding(
                        rid, title, sev, cwe, owasp, "CI/CD Secret", rel, i, snip,
                        "A credential appears to be hardcoded in the pipeline configuration, "
                        "exposing it to anyone with repository or build-log access.",
                        "Move the value into the CI provider's secret store and reference it "
                        "indirectly; rotate the exposed credential.",
                        _SECRET_REFS_DOC, platform))
                # GitHub Actions uses: pinning.
                if platform == "github_actions":
                    mu = _USES_RE.match(line)
                    if mu:
                        uf = _uses_finding(rel, mu.group(1), mu.group(2), line, i)
                        if uf:
                            rid, title, sev, cwe, owasp, desc, rec = uf
                            findings.append(_make_finding(
                                rid, title, sev, cwe, owasp, "CI/CD Supply Chain", rel, i,
                                line, desc, rec,
                                ["https://docs.github.com/actions/security-guides/security-hardening-for-github-actions"],
                                platform))
                # Generic per-line rules.
                for rule in LINE_RULES:
                    if rule["platforms"] and platform not in rule["platforms"]:
                        continue
                    if rule["re"].search(line):
                        findings.append(_make_finding(
                            rule["id"], rule["title"], rule["severity"], rule["cwe"],
                            rule["owasp"], rule["category"], rel, i, line,
                            rule["description"], rule["recommendation"], rule["references"],
                            platform))

    # Repository-level missing-practice findings (only when CI/CD actually exists).
    if pipeline_files:
        anchor = pipeline_files[0]
        for key, meta in _PRACTICE_META.items():
            if key in practice_hits:
                continue
            title, sev, cwe, rec = meta
            findings.append(_make_finding(
                f"CICD_MISSING_{key.upper()}", title, sev, cwe, "CICD-SEC-2",
                "CI/CD Hardening", anchor, 1, pipeline_files[0],
                f"{title}: no signal of this control was found across {len(pipeline_files)} "
                f"detected pipeline file(s). Automated security gates reduce the chance of a "
                f"vulnerable or tampered release shipping.",
                rec, ["https://owasp.org/www-project-top-10-ci-cd-security-risks/"], None))

    return {
        "findings": findings,
        "platforms": sorted(platforms_seen),
        "files": sorted(pipeline_files),
    }

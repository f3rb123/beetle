"""GitHub PAT validator — Phase 9.3. Read-only: GET /user (no scope enumeration)."""
from __future__ import annotations

from . import base


class GitHubValidator(base.BaseValidator):
    provider = "GITHUB"

    def validate(self, secret: dict) -> str:
        token = secret.get("_raw") or ""
        if not token:
            return base.ERROR
        req = base.make_request(
            "https://api.github.com/user",
            headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json"},
        )
        # 200 = token accepted; 401 = bad credentials. No scopes are read.
        return self._simple_probe(req, ok=(200,), bad=(401, 403))

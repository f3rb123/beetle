"""
Secret validator base — Phase 9.3.

Common interface + a single read-only HTTP primitive shared by every provider
validator. Validators perform ONE minimal "are these credentials accepted?"
check. They NEVER enumerate scopes/privileges, write, or mutate.

Every validate() returns exactly one of: VALID | INVALID | ERROR.
  VALID   — issuer/API accepted the credential.
  INVALID — issuer/API rejected it (401/403/explicit invalid).
  ERROR   — network error, timeout, or an inconclusive response.

Tests monkeypatch `http_send` to return canned (status, body) tuples, so the
result-mapping (and any request signing) is exercised without real network or
real credentials.
"""
from __future__ import annotations

import urllib.request
import urllib.error

VALID = "valid"
INVALID = "invalid"
ERROR = "error"

DEFAULT_TIMEOUT = 5  # seconds — hard per-validator cap (Task 3)
USER_AGENT = "Beetle-Scanner/1.0"


def make_request(url: str, method: str = "GET", headers: dict | None = None,
                 data: bytes | None = None) -> urllib.request.Request:
    return urllib.request.Request(
        url, data=data, method=method,
        headers={"User-Agent": USER_AGENT, **(headers or {})},
    )


def http_send(req: urllib.request.Request, timeout: int = DEFAULT_TIMEOUT) -> tuple[int, str]:
    """One read-only HTTP send. Returns (status, body[:4096]). Raises on error.

    The single network primitive — monkeypatched in tests. Body is capped so a
    hostile endpoint cannot stream unbounded data into the scanner.
    """
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        status = getattr(resp, "status", None) or resp.getcode()
        body = resp.read(4096).decode("utf-8", errors="replace")
        return status, body


class BaseValidator:
    """One provider's minimal accept/reject check."""

    provider = ""
    timeout = DEFAULT_TIMEOUT

    def validate(self, secret: dict) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    # ── Shared helpers ────────────────────────────────────────────────────────
    def _send(self, req: urllib.request.Request) -> tuple[int, str]:
        return http_send(req, self.timeout)

    @staticmethod
    def _classify_http_error(code: int, ok=(200,), bad=(401, 403)) -> str:
        if code in bad:
            return INVALID
        if code in ok:
            return VALID
        return ERROR

    def _simple_probe(self, req: urllib.request.Request,
                      ok=(200,), bad=(401, 403)) -> str:
        """GET/POST and map status → VALID/INVALID/ERROR. Exceptions → ERROR."""
        try:
            status, _ = self._send(req)
            if status in bad:
                return INVALID
            if status in ok:
                return VALID
            return ERROR
        except urllib.error.HTTPError as e:
            return self._classify_http_error(e.code, ok, bad)
        except Exception:
            return ERROR

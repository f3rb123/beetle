"""Azure storage validator — Phase 9.3.

Read-only: List Containers (GET ?comp=list), signed with SharedKey. This only
confirms the connection string / account key is accepted — it does not read blob
data or mutate anything. Parses AccountName + AccountKey from a connection
string (or pairs an account key with a connection string).

200 → VALID. 403 (AuthenticationFailed) → INVALID.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import urllib.error

from . import base

_API_VERSION = "2021-08-06"


def _parse_connection_string(conn: str) -> dict:
    out = {}
    for part in conn.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip().lower()] = v.strip()
    return out


class AzureValidator(base.BaseValidator):
    provider = "AZURE"

    def validate(self, secret: dict) -> str:
        account, key = self._account_and_key(secret)
        if not (account and key):
            return base.ERROR
        try:
            req = self._signed_request(account, key)
            status, _ = self._send(req)
            return base.VALID if status == 200 else base.ERROR
        except urllib.error.HTTPError as e:
            if e.code in (403, 401):
                return base.INVALID
            return base.ERROR
        except Exception:
            return base.ERROR

    @staticmethod
    def _account_and_key(secret: dict) -> tuple[str, str]:
        raw = secret.get("_raw") or ""
        members = secret.get("_raw_members") or {}
        conn = members.get("AZURE_CONNECTION_STRING") or (raw if "accountkey=" in raw.lower() else "")
        if conn:
            parsed = _parse_connection_string(conn)
            return parsed.get("accountname", ""), parsed.get("accountkey", "")
        return "", ""

    def _signed_request(self, account: str, key: str):
        now = datetime.datetime.now(datetime.timezone.utc)
        date = now.strftime("%a, %d %b %Y %H:%M:%S GMT")
        resource = f"/{account}/\ncomp:list"
        # VERB\n + 12 blank standard header lines, then the x-ms headers, then the
        # canonicalized resource (SharedKey StringToSign for List Containers).
        string_to_sign = (
            "GET\n"            # VERB
            "\n"               # Content-Encoding
            "\n"               # Content-Language
            "\n"               # Content-Length
            "\n"               # Content-MD5
            "\n"               # Content-Type
            "\n"               # Date
            "\n"               # If-Modified-Since
            "\n"               # If-Match
            "\n"               # If-None-Match
            "\n"               # If-Unmodified-Since
            "\n"               # Range
            f"x-ms-date:{date}\nx-ms-version:{_API_VERSION}\n"
            f"{resource}"
        )
        signature = base64.b64encode(
            hmac.new(base64.b64decode(key), string_to_sign.encode("utf-8"), hashlib.sha256).digest()
        ).decode()
        return base.make_request(
            f"https://{account}.blob.core.windows.net/?comp=list",
            headers={
                "x-ms-date": date,
                "x-ms-version": _API_VERSION,
                "Authorization": f"SharedKey {account}:{signature}",
            },
        )

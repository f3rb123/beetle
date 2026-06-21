"""Firebase validator — Phase 9.3.

Read-only reachability check: GET <db>/.json (shallow). We only decide whether
the database EXISTS / is reachable — we do NOT enumerate collections here (that
is the cloud-intelligence phase). 200 or 401 → reachable (VALID); 404 → INVALID.
"""
from __future__ import annotations

import urllib.error

from . import base


class FirebaseValidator(base.BaseValidator):
    provider = "FIREBASE"

    def validate(self, secret: dict) -> str:
        url = self._db_url(secret)
        if not url:
            return base.ERROR
        test = url.rstrip("/") + "/.json?shallow=true"
        try:
            status, _ = self._send(base.make_request(test))
            return base.VALID if status == 200 else base.ERROR
        except urllib.error.HTTPError as e:
            if e.code == 401:
                return base.VALID      # exists but rules require auth → reachable
            if e.code == 404:
                return base.INVALID    # no such database
            return base.ERROR
        except Exception:
            return base.ERROR

    @staticmethod
    def _db_url(secret: dict) -> str:
        members = secret.get("_raw_members") or {}
        if members:
            return members.get("FIREBASE_URL") or ""
        return secret.get("_raw") or ""

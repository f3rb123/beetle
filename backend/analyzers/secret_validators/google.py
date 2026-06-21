"""Google API-key validator — Phase 9.3.

Read-only: a single Geocoding request. We only decide accepted vs rejected from
the response `status` — we do NOT enumerate which APIs/scopes the key allows.
A restricted-but-valid key (referer/IP restriction) is treated as VALID.
"""
from __future__ import annotations

import urllib.error

from . import base


class GoogleValidator(base.BaseValidator):
    provider = "GOOGLE"

    def validate(self, secret: dict) -> str:
        key = secret.get("_raw") or ""
        if not key:
            return base.ERROR
        url = ("https://maps.googleapis.com/maps/api/geocode/json"
               f"?address=Mountain+View&key={key}")
        try:
            status, body = self._send(base.make_request(url))
        except urllib.error.HTTPError as e:
            if e.code in (400, 403):
                return base.INVALID
            return base.ERROR
        except Exception:
            return base.ERROR

        if status != 200:
            return base.ERROR
        low = body.lower()
        if '"status"' not in low:
            return base.ERROR
        # A REQUEST_DENIED that complains the key is invalid/unauthorized/expired
        # means the key is rejected. A REQUEST_DENIED about *restrictions* (referer
        # /IP) means the key is valid but scoped — treat as VALID (accepted).
        if "request_denied" in low and "restrict" not in low:
            if any(w in low for w in ("invalid", "not authorized", "unauthorized", "expired")):
                return base.INVALID
        return base.VALID

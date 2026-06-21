"""Twilio pair validator — Phase 9.3. Read-only: GET Accounts/<SID>.json."""
from __future__ import annotations

import base64

from . import base


class TwilioValidator(base.BaseValidator):
    provider = "TWILIO"

    def validate(self, secret: dict) -> str:
        members = secret.get("_raw_members") or {}
        sid = members.get("TWILIO_ACCOUNT_SID") or ""
        token = members.get("TWILIO_AUTH_TOKEN") or ""
        if not (sid and token):
            return base.ERROR  # need both halves; a lone SID is not validatable
        auth = base64.b64encode(f"{sid}:{token}".encode()).decode()
        req = base.make_request(
            f"https://api.twilio.com/2010-04-01/Accounts/{sid}.json",
            headers={"Authorization": f"Basic {auth}"},
        )
        return self._simple_probe(req, ok=(200,), bad=(401, 403, 404))

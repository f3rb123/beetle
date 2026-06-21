"""Stripe secret-key validator — Phase 9.3. Read-only: GET /v1/balance."""
from __future__ import annotations

import base64

from . import base


class StripeValidator(base.BaseValidator):
    provider = "STRIPE"

    def validate(self, secret: dict) -> str:
        key = self._secret_key(secret)
        if not key:
            return base.ERROR
        token = base64.b64encode(f"{key}:".encode()).decode()
        req = base.make_request(
            "https://api.stripe.com/v1/balance",
            headers={"Authorization": f"Basic {token}"},
        )
        return self._simple_probe(req, ok=(200,), bad=(401, 403))

    @staticmethod
    def _secret_key(secret: dict) -> str:
        # Pair: the secret half carries the validatable key. Single: _raw.
        members = secret.get("_raw_members") or {}
        if members:
            return members.get("STRIPE_SECRET") or ""
        return secret.get("_raw") or ""

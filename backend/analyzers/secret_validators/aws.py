"""AWS credential-pair validator — Phase 9.3.

Read-only: STS GetCallerIdentity, signed with SigV4. This is the *only* call —
it returns the caller's identity and grants nothing. We do NOT enumerate IAM
permissions or list any resource (that is a later phase). Needs BOTH halves of
the pair (access key id + secret key); a lone half cannot be signed.

200 → VALID. 403 (InvalidClientTokenId / SignatureDoesNotMatch) → INVALID.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import urllib.error

from . import base

_REGION = "us-east-1"
_SERVICE = "sts"
_HOST = "sts.amazonaws.com"
_BODY = "Action=GetCallerIdentity&Version=2011-06-15"


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret_key: str, datestamp: str) -> bytes:
    k_date = _sign(("AWS4" + secret_key).encode("utf-8"), datestamp)
    k_region = _sign(k_date, _REGION)
    k_service = _sign(k_region, _SERVICE)
    return _sign(k_service, "aws4_request")


class AWSValidator(base.BaseValidator):
    provider = "AWS"

    def validate(self, secret: dict) -> str:
        members = secret.get("_raw_members") or {}
        access_key = members.get("AWS_ACCESS_KEY") or ""
        secret_key = members.get("AWS_SECRET_KEY") or ""
        if not (access_key and secret_key):
            return base.ERROR
        try:
            req = self._signed_request(access_key, secret_key)
            status, _ = self._send(req)
            return base.VALID if status == 200 else base.ERROR
        except urllib.error.HTTPError as e:
            if e.code in (403, 401):
                return base.INVALID
            return base.ERROR
        except Exception:
            return base.ERROR

    def _signed_request(self, access_key: str, secret_key: str):
        now = datetime.datetime.now(datetime.timezone.utc)
        amzdate = now.strftime("%Y%m%dT%H%M%SZ")
        datestamp = now.strftime("%Y%m%d")

        content_type = "application/x-www-form-urlencoded; charset=utf-8"
        payload_hash = hashlib.sha256(_BODY.encode("utf-8")).hexdigest()

        canonical_headers = (
            f"content-type:{content_type}\n"
            f"host:{_HOST}\n"
            f"x-amz-date:{amzdate}\n"
        )
        signed_headers = "content-type;host;x-amz-date"
        canonical_request = (
            f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        )

        scope = f"{datestamp}/{_REGION}/{_SERVICE}/aws4_request"
        string_to_sign = (
            "AWS4-HMAC-SHA256\n"
            f"{amzdate}\n{scope}\n"
            f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        )
        signature = hmac.new(
            _signing_key(secret_key, datestamp),
            string_to_sign.encode("utf-8"), hashlib.sha256,
        ).hexdigest()

        authorization = (
            f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        return base.make_request(
            f"https://{_HOST}/",
            method="POST",
            headers={
                "Content-Type": content_type,
                "X-Amz-Date": amzdate,
                "Authorization": authorization,
            },
            data=_BODY.encode("utf-8"),
        )

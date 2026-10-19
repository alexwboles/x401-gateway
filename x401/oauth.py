"""Optional OAuth 2.0 token-exchange leg (x401 v0.2.0 profile).

The agent POSTs the result artifact as a token-exchange subject token; on
success the verifier issues a short-lived Bearer JWT carrying the spec's
``x401`` metadata block.
"""

from __future__ import annotations

import json
import secrets
import time
from datetime import datetime, timezone

from .jws import JWSError, sign_raw, verify

__all__ = [
    "OAuthError",
    "TOKEN_EXCHANGE_GRANT",
    "RESULT_ARTIFACT_TYPE",
    "build_token_request",
    "issue_access_token",
    "verify_access_token",
]

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
RESULT_ARTIFACT_TYPE = "urn:x401:params:oauth:token-type:result_artifact"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


class OAuthError(ValueError):
    """Raised on token validation failure; carries a machine-readable ``.code``."""

    def __init__(self, code: str, message: str | None = None):
        self.code = code
        super().__init__(message or code)


def build_token_request(subject_token: str, resource: str | None = None) -> dict:
    """Form params for the token-exchange POST (application/x-www-form-urlencoded)."""
    params = {
        "grant_type": TOKEN_EXCHANGE_GRANT,
        "subject_token_type": RESULT_ARTIFACT_TYPE,
        "subject_token": subject_token,
    }
    if resource is not None:
        params["resource"] = resource
    return params


def _iso8601(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def issue_access_token(
    *,
    agent_id: str,
    verifier_id: str,
    request_id: str | None,
    satisfied_requirements: list[str] | None,
    resource: str | None,
    method: str,
    signing_key,
    key_id: str,
    ttl: int = 300,
    alg: str = "EdDSA",
) -> str:
    """Issue a short-lived Bearer JWT with the spec's x401 metadata block."""
    now = int(time.time())
    expires_at = now + ttl
    claims = {
        "iss": verifier_id,
        "sub": agent_id,
        "aud": resource,
        "iat": now,
        "exp": expires_at,
        "jti": secrets.token_urlsafe(16),
        "x401": {
            "agent_id": agent_id,
            "verifier_id": verifier_id,
            "request_id": request_id,
            "satisfied_requirements": list(satisfied_requirements) if satisfied_requirements else [],
            "resource": resource,
            "method": method,
            "expires_at": _iso8601(expires_at),
        },
    }
    canonical = json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return sign_raw(canonical, signing_key, alg, extra_header={"kid": key_id, "typ": "at+jwt"})


def verify_access_token(token: str, public_key, *, expected_audience: str | None = None) -> dict:
    """Verify signature, expiry, and audience of an x401 access token.

    Returns the claims dict. Raises OAuthError('token_expired') when expired,
    OAuthError('invalid_token') on signature failure, audience mismatch, or a
    missing x401 metadata block.
    """
    try:
        claims = verify(token, public_key)
    except JWSError as exc:
        raise OAuthError("invalid_token", f"signature verification failed: {exc}") from exc

    now = int(time.time())
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or now >= exp:
        raise OAuthError("token_expired", "access token has expired")

    if expected_audience is not None:
        aud = claims.get("aud")
        audiences = aud if isinstance(aud, list) else [aud]
        if expected_audience not in audiences:
            raise OAuthError("invalid_token", "audience mismatch")

    if not isinstance(claims.get("x401"), dict):
        raise OAuthError("invalid_token", "missing x401 metadata block")
    return claims

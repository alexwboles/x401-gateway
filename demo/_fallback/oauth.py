"""Fallback ``x401.oauth`` — the optional OAuth token-exchange leg.

Fixed params per the x401 OAuth profile: grant_type and subject_token_type are
constants and MUST NOT be repeated in the PROOF-REQUEST payload. On success the
endpoint issues a short-lived Bearer JWT carrying the spec's ``x401`` metadata block.
"""

import secrets
import time

from . import jws as _jws
from .codec import b64u_encode

__all__ = [
    "OAuthError",
    "TOKEN_EXCHANGE_GRANT",
    "RESULT_ARTIFACT_TYPE",
    "ACCESS_TOKEN_TYPE",
    "build_token_request",
    "issue_access_token",
    "verify_access_token",
]

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
RESULT_ARTIFACT_TYPE = "urn:x401:params:oauth:token-type:result_artifact"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


class OAuthError(Exception):
    """Token-exchange / access-token failure; carries an x401 error ``code``."""

    def __init__(self, code: str, description: str = ""):
        super().__init__(description or code)
        self.code = code


def build_token_request(*, subject_token: str, resource: str | None = None,
                        audience: str | None = None) -> dict:
    """Build the form fields for the token-exchange POST (grant params are fixed)."""
    body = {
        "grant_type": TOKEN_EXCHANGE_GRANT,
        "subject_token": subject_token,
        "subject_token_type": RESULT_ARTIFACT_TYPE,
    }
    if resource:
        body["resource"] = resource
    if audience:
        body["audience"] = audience
    return body


def issue_access_token(*, signing_key, key_id: str | None = None, issuer: str,
                       agent_id: str, request_id: str,
                       satisfied_requirements=(), resource: str | None = None,
                       method: str | None = None, audience: str | None = None,
                       scope: str = "purchase", ttl: int = 300,
                       alg: str = "EdDSA") -> str:
    """Issue a short-lived Bearer JWT with the x401 metadata block."""
    now = int(time.time())
    exp = now + int(ttl)
    claims = {
        "iss": issuer,
        "sub": agent_id,
        "aud": audience or issuer,
        "iat": now,
        "exp": exp,
        "jti": b64u_encode(secrets.token_bytes(12)),
        "scope": scope,
        "x401": {
            "agent_id": agent_id,
            "verifier_id": issuer,
            "request_id": request_id,
            "satisfied_requirements": list(satisfied_requirements),
            "resource": resource,
            "method": method,
            "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp)),
        },
    }
    return _jws.sign_compact(claims, signing_key, alg=alg, kid=key_id)


def verify_access_token(token: str, key, *, audience: str | None = None,
                        now=None) -> dict:
    """Verify signature, expiry, and audience of an access token."""
    try:
        claims = _jws.verify_compact(token, key)
    except _jws.JwsError as exc:
        raise OAuthError("invalid_token", str(exc))
    moment = float(now) if now is not None else time.time()
    if moment > float(claims.get("exp", 0)):
        raise OAuthError("token_expired", "access token expired")
    if audience is not None and claims.get("aud") != audience:
        raise OAuthError("invalid_token", "access token audience mismatch")
    return claims

"""Fallback ``x401.request`` — build/parse PROOF-REQUEST (x401 Payload)."""

import secrets
import time

from . import jws as _jws
from .codec import b64u_encode, parse_header

__all__ = ["RequestError", "build_proof_request", "parse_proof_request"]

X401_VERSION = "0.2.0"
SIGNED = "openid4vp-v1-signed"
UNSIGNED = "openid4vp-v1-unsigned"


class RequestError(Exception):
    """Raised for invalid/unsupported proof requests; carries an x401 error ``code``."""

    def __init__(self, code: str, description: str = ""):
        super().__init__(description or code)
        self.code = code


def build_proof_request(*, verifier_private_key, key_id, client_id, dcql,
                        protocol: str = SIGNED, expected_origins=None,
                        oauth_token_endpoint=None, request_id=None,
                        satisfied_requirements=None, ttl: int = 300,
                        nonce: str | None = None, alg: str = "EdDSA") -> dict:
    """Build the x401 Payload dict for a PROOF-REQUEST header.

    Signed mode wraps the OpenID4VP request as a JAR (RFC 9101) JWT signed by the
    verifier; unsigned mode carries the raw request params (weaker binding — see
    docs/SECURITY.md).
    """
    if protocol not in (SIGNED, UNSIGNED):
        raise RequestError("unsupported_protocol", f"unknown protocol {protocol!r}")
    now = int(time.time())
    nonce = nonce or b64u_encode(secrets.token_bytes(16))  # 128-bit fresh nonce
    jar_claims = {
        "response_type": "vp_token",
        "response_mode": "dc_api",
        "client_id": client_id,
        "nonce": nonce,
        "dcql_query": dcql,
        "client_metadata": {},
        "iat": now,
        "exp": now + int(ttl),
    }
    if expected_origins:
        jar_claims["expected_origins"] = list(expected_origins)
    if protocol == SIGNED:
        data = {"request": _jws.sign_compact(
            jar_claims, verifier_private_key, alg=alg, kid=key_id)}
    else:
        data = dict(jar_claims)  # unsigned: raw params, no signature

    payload = {
        "scheme": "x401",
        "version": X401_VERSION,
        "credential_requirements": {
            "digital": {"requests": [{"protocol": protocol, "data": data}]}
        },
    }
    if oauth_token_endpoint:
        payload["oauth"] = {"token_endpoint": oauth_token_endpoint}
    if request_id:
        payload["request_id"] = request_id
    if satisfied_requirements:
        payload["satisfied_requirements"] = list(satisfied_requirements)
    return payload


def parse_proof_request(obj) -> dict:
    """Validate and return an x401 Payload (accepts a dict or raw header value)."""
    if isinstance(obj, str):
        obj = parse_header(obj)
    if not isinstance(obj, dict):
        raise RequestError("invalid_request", "PROOF-REQUEST must decode to a JSON object")
    if obj.get("scheme") != "x401":
        raise RequestError("invalid_request", "payload scheme must be 'x401'")
    if obj.get("version") != X401_VERSION:
        raise RequestError("unsupported_version",
                           f"unsupported x401 version {obj.get('version')!r}")
    try:
        requests = obj["credential_requirements"]["digital"]["requests"]
    except (KeyError, TypeError):
        raise RequestError("invalid_request", "missing credential_requirements.digital.requests")
    if not isinstance(requests, list) or not requests:
        raise RequestError("invalid_request", "digital.requests must be a non-empty list")
    return obj

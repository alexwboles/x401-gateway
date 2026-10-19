"""PROOF-REQUEST construction and parsing for x401 v0.2.0.

Signed mode (``openid4vp-v1-signed``, RECOMMENDED) embeds a JAR JWT (RFC 9101)
authored and signed by the verifier. Unsigned mode (``openid4vp-v1-unsigned``)
carries the raw request parameters in ``data`` (no ``request`` member).
"""

from __future__ import annotations

import base64
import secrets
import time

from .jws import sign_raw

__all__ = ["RequestError", "build_proof_request", "parse_proof_request"]

SCHEME = "x401"
VERSION = "0.2.0"
SIGNED_PROTOCOL = "openid4vp-v1-signed"
UNSIGNED_PROTOCOL = "openid4vp-v1-unsigned"


class RequestError(ValueError):
    """Raised when a PROOF-REQUEST payload is malformed or unsupported."""


def _fresh_nonce() -> str:
    # 128-bit nonce, base64url, no padding (22 chars).
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")


def build_proof_request(
    *,
    verifier_private_key,
    key_id: str,
    client_id: str,
    dcql: dict,
    protocol: str = SIGNED_PROTOCOL,
    expected_origins: list[str] | None = None,
    oauth_token_endpoint: str | None = None,
    request_id: str | None = None,
    satisfied_requirements: list[str] | None = None,
    ttl: int = 300,
    nonce: str | None = None,
    alg: str = "EdDSA",
) -> dict:
    """Build a full v0.2.0 PROOF-REQUEST payload.

    In signed mode the OpenID4VP claims are signed by the verifier's key into a
    JAR JWT with a fresh 128-bit ``nonce`` (unless ``nonce`` is passed) and a
    short ``exp``. In unsigned mode the raw params go into ``data`` directly.
    """
    if protocol not in (SIGNED_PROTOCOL, UNSIGNED_PROTOCOL):
        raise RequestError(f"unsupported protocol {protocol!r}")
    if not isinstance(dcql, dict) or not dcql.get("credentials"):
        raise RequestError("dcql must be a DCQL query dict with a non-empty 'credentials' list")

    nonce = nonce or _fresh_nonce()
    now = int(time.time())
    claims = {
        "response_type": "vp_token",
        "response_mode": "dc_api",
        "client_id": client_id,
        "nonce": nonce,
        "dcql_query": dcql,
        "client_metadata": {},
        "exp": now + ttl,
    }
    if expected_origins is not None:
        claims["expected_origins"] = list(expected_origins)

    if protocol == SIGNED_PROTOCOL:
        if verifier_private_key is None:
            raise RequestError("signed mode requires a verifier private key")
        import json as _json

        canonical = _json.dumps(
            claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        # kid lets the agent resolve the verifier's signing key.
        jar = sign_raw(canonical, verifier_private_key, alg, extra_header={"kid": key_id})
        data = {"request": jar}
    else:
        data = dict(claims)  # raw params; no 'request' member

    payload: dict = {
        "scheme": SCHEME,
        "version": VERSION,
        "credential_requirements": {
            "digital": {"requests": [{"protocol": protocol, "data": data}]}
        },
    }
    if oauth_token_endpoint is not None:
        payload["oauth"] = {"token_endpoint": oauth_token_endpoint}
    if request_id is not None:
        payload["request_id"] = request_id
    if satisfied_requirements is not None:
        payload["satisfied_requirements"] = list(satisfied_requirements)
    return payload


def parse_proof_request(obj: dict) -> dict:
    """Validate a decoded PROOF-REQUEST payload; return it unchanged on success."""
    if not isinstance(obj, dict):
        raise RequestError("PROOF-REQUEST must decode to a JSON object")
    if obj.get("scheme") != SCHEME:
        raise RequestError(f"scheme must be {SCHEME!r}")
    if obj.get("version") != VERSION:
        raise RequestError(f"unsupported version {obj.get('version')!r}")
    try:
        requests = obj["credential_requirements"]["digital"]["requests"]
    except (KeyError, TypeError) as exc:
        raise RequestError("missing credential_requirements.digital.requests") from exc
    if not isinstance(requests, list) or not requests:
        raise RequestError("credential_requirements.digital.requests must be non-empty")
    for req in requests:
        if not isinstance(req, dict) or not req.get("protocol") or not isinstance(req.get("data"), dict):
            raise RequestError("each request needs a 'protocol' and a 'data' object")
        if req["protocol"] not in (SIGNED_PROTOCOL, UNSIGNED_PROTOCOL):
            raise RequestError(f"unsupported protocol {req['protocol']!r}")
    return obj

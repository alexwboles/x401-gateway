"""Fallback ``x401.mandate`` — scoped-mandate extension (``x-x401ext-mandate/v1``).

x401 v0.2.0 standardizes the proof wire protocol but NOT the delegation/mandate
credential schema (it is an explicit open question in the spec). This module defines
the gateway's own mandate profile and marks it an extension: a JWS-signed canonical
JSON object recording which agent may act at which merchant, for what action, up to
what amount ceiling, inside what time window, bound to the verifier's challenge nonce.
Any alteration of the signed terms invalidates the signature.
"""

import time
from decimal import Decimal, InvalidOperation

from . import jws as _jws

__all__ = ["MandateError", "MANDATE_TYPE", "build_mandate", "sign_mandate",
           "verify_mandate"]

MANDATE_TYPE = "x-x401ext-mandate/v1"


class MandateError(Exception):
    """Mandate validation failure; ``code`` is one of the x401 error tokens."""

    def __init__(self, code: str, description: str = ""):
        super().__init__(description or code)
        self.code = code


def _amount(value) -> dict:
    """Normalize ``{currency, value}``; value becomes a 2-decimal string."""
    if isinstance(value, dict):
        currency, amount = value.get("currency"), value.get("value")
    else:
        raise MandateError("invalid_request", "amount must be {currency, value}")
    try:
        quantized = Decimal(str(amount)).quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError, TypeError):
        raise MandateError("invalid_request", f"bad amount value {amount!r}")
    if quantized < 0:
        raise MandateError("invalid_request", "negative amount")
    return {"currency": str(currency), "value": format(quantized, "f")}


def build_mandate(*, agent_id: str, merchant: str, action: str,
                  amount_ceiling, not_before=None, not_after=None,
                  nonce: str | None = None, request_id: str | None = None,
                  issuer: str | None = None) -> dict:
    """Build the unsigned mandate claims (sign with :func:`sign_mandate`)."""
    now = int(time.time())
    claims = {
        "type": MANDATE_TYPE,
        "iat": now,
        "agent_id": agent_id,
        "merchant": merchant,
        "action": action,
        "ceiling": _amount(amount_ceiling),
    }
    if issuer:
        claims["iss"] = issuer
    claims["nbf"] = int(not_before) if not_before is not None else now
    claims["exp"] = int(not_after) if not_after is not None else now + 600
    if nonce:
        claims["nonce"] = nonce
    if request_id:
        claims["request_id"] = request_id
    return claims


def sign_mandate(mandate: dict, private_key, *, key_id: str | None = None,
                 alg: str = "EdDSA") -> str:
    """JWS-sign mandate claims; returns the compact serialization."""
    return _jws.sign_compact(mandate, private_key, alg=alg, kid=key_id)


def verify_mandate(token: str, key, *, now=None, expected_merchant: str | None = None,
                   tx_amount=None) -> dict:
    """Verify a signed mandate against its key and the transaction context.

    Checks, in order: JWS integrity -> type -> time window -> merchant binding ->
    amount ceiling. Raises :class:`MandateError` with a precise ``code``.
    """
    try:
        claims = _jws.verify_compact(token, key)
    except _jws.JwsError as exc:
        message = str(exc)
        code = ("invalid_signature"
                if ("malformed" in message or "unsupported alg" in message)
                else "tampered_mandate")
        raise MandateError(code, message)
    if claims.get("type") != MANDATE_TYPE:
        raise MandateError("invalid_request",
                           f"not a {MANDATE_TYPE} mandate")
    moment = float(now) if now is not None else time.time()
    if moment < float(claims.get("nbf", 0)):
        raise MandateError("expired_mandate", "mandate not yet valid")
    if moment > float(claims.get("exp", 0)):
        raise MandateError("expired_mandate", "mandate expired")
    if expected_merchant is not None and claims.get("merchant") != expected_merchant:
        raise MandateError("wrong_binding",
                           "mandate merchant does not match this verifier")
    if tx_amount is not None:
        want = _amount(tx_amount)
        ceiling = claims.get("ceiling", {})
        if want["currency"] != ceiling.get("currency"):
            raise MandateError("mandate_exceeded",
                               "transaction currency not covered by mandate")
        if Decimal(want["value"]) > Decimal(ceiling.get("value", "0")):
            raise MandateError(
                "mandate_exceeded",
                f"{want['value']} {want['currency']} exceeds ceiling "
                f"{ceiling.get('value')} {ceiling.get('currency')}",
            )
    return claims

"""Scoped mandate credential -- GATEWAY EXTENSION, not part of x401 v0.2.0.

The v0.2.0 spec does not standardize a mandate/delegation schema (its
"Fully Autonomous Delegation" section is an open question). This module defines
the gateway's own profile, clearly marked as an extension:

    type: "x-x401ext-mandate/v1"

A mandate is a signed statement of *which agent, which merchant, what action
category, what amount ceiling, what time window*. It is signed with JWS compact
serialization over the canonical JSON bytes; ANY alteration of the signed terms
invalidates the signature. Never present this type as spec-defined.
"""

from __future__ import annotations

import json
import time
from decimal import Decimal, InvalidOperation

from .jws import JWSError, sign_raw, verify

__all__ = [
    "MandateError",
    "MANDATE_TYPE",
    "canonical",
    "build_mandate",
    "sign_mandate",
    "verify_mandate",
]

MANDATE_TYPE = "x-x401ext-mandate/v1"

_REQUIRED_TERMS = (
    "type",
    "agent",
    "merchant",
    "action_category",
    "amount_ceiling",
    "not_before",
    "not_after",
    "nonce",
)


class MandateError(ValueError):
    """Raised on mandate validation failure; carries a machine-readable ``.code``."""

    def __init__(self, code: str, message: str | None = None):
        self.code = code
        super().__init__(message or code)


def canonical(m: dict) -> bytes:
    """Canonical JSON bytes of a mandate: sorted keys, compact separators, UTF-8."""
    if not isinstance(m, dict):
        raise MandateError("tampered_mandate", "mandate must be a JSON object")
    return json.dumps(m, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def build_mandate(
    *,
    agent: str,
    merchant: str,
    action_category: str,
    amount_ceiling: dict,
    not_before: int,
    not_after: int,
    nonce: str,
    request_id: str | None = None,
) -> dict:
    """Build an unsigned mandate dict (sign with :func:`sign_mandate`)."""
    if not isinstance(amount_ceiling, dict) or "currency" not in amount_ceiling or "value" not in amount_ceiling:
        raise MandateError("tampered_mandate", "amount_ceiling needs {currency, value}")
    mandate = {
        "type": MANDATE_TYPE,
        "agent": agent,
        "merchant": merchant,
        "action_category": action_category,
        "amount_ceiling": {"currency": amount_ceiling["currency"], "value": amount_ceiling["value"]},
        "not_before": int(not_before),
        "not_after": int(not_after),
        "nonce": nonce,
    }
    if request_id is not None:
        mandate["request_id"] = request_id
    return mandate


def sign_mandate(mandate: dict, private_key, alg: str = "EdDSA") -> str:
    """JWS-compact-sign the canonical bytes of a mandate."""
    return sign_raw(canonical(mandate), private_key, alg)


def _amount(value: str) -> Decimal:
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise MandateError("tampered_mandate", f"bad amount value: {exc}") from exc


def verify_mandate(
    token: str,
    public_key,
    *,
    now: float | None = None,
    expected_merchant: str | None = None,
    tx_amount: dict | None = None,
) -> dict:
    """Verify a signed mandate and enforce its terms.

    Checks, in order: JWS signature (``invalid_signature``), structural terms
    (``tampered_mandate``), time window (``expired_mandate``), merchant binding
    (``wrong_binding``), and amount ceiling (``mandate_exceeded``). Returns the
    mandate dict on success.
    """
    now = time.time() if now is None else now

    if not isinstance(token, str):
        raise MandateError("invalid_signature", "mandate token must be a string")
    try:
        header_b64 = token.split(".")[0]
        import base64 as _b64

        padded = header_b64 + ("=" * ((4 - len(header_b64) % 4) % 4))
        header = json.loads(_b64.urlsafe_b64decode(padded).decode("utf-8"))
        alg = header.get("alg") if isinstance(header, dict) else None
    except Exception:
        alg = None
    if alg not in ("EdDSA", "ES256"):
        raise MandateError("invalid_signature", f"unsupported or missing alg: {alg!r}")

    try:
        mandate = verify(token, public_key, expected_alg=alg)
    except JWSError as exc:
        raise MandateError("invalid_signature", f"mandate signature invalid: {exc}") from exc

    if not isinstance(mandate, dict) or mandate.get("type") != MANDATE_TYPE:
        raise MandateError("tampered_mandate", "mandate type mismatch or malformed")
    missing = [t for t in _REQUIRED_TERMS if t not in mandate]
    if missing:
        raise MandateError("tampered_mandate", f"mandate missing terms: {missing}")

    if now < mandate["not_before"] or now > mandate["not_after"]:
        raise MandateError("expired_mandate", "mandate is outside its validity window")

    if expected_merchant is not None and mandate["merchant"] != expected_merchant:
        raise MandateError("wrong_binding", "mandate merchant binding mismatch")

    if tx_amount is not None:
        ceiling = mandate["amount_ceiling"]
        if not isinstance(tx_amount, dict) or tx_amount.get("currency") != ceiling.get("currency"):
            raise MandateError("mandate_exceeded", "transaction currency does not match ceiling")
        if _amount(tx_amount.get("value")) > _amount(ceiling.get("value")):
            raise MandateError("mandate_exceeded", "transaction amount exceeds mandate ceiling")

    return mandate

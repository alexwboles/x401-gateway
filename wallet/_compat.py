"""Defensive interop with the sibling ``x401`` package.

The ``x401`` verifier library is built in a parallel track and may not be
importable yet.  This module prefers its documented public API when present::

    x401.codec:   encode_payload / decode_payload / CodecError
    x401.jws:     generate_ed25519_keypair / jwk_public / key_from_jwk_public
    x401.mandate: build_mandate / sign_mandate / canonical
    x401.request: parse_proof_request

and otherwise falls back to minimal local implementations of the same
operations, so the wallet works standalone.  The local fallback uses
standard JWS compact serialization (EdDSA) over canonical JSON
(``sort_keys=True``, compact separators), so tokens remain interoperable
with any conformant implementation of the same profile.

``X401_FALLBACKS`` lists every operation currently served by a local
fallback -- useful for diagnostics and for the final build report.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time as _time

log = logging.getLogger("x401.wallet.compat")

MANDATE_TYPE = "x-x401ext-mandate/v1"
"""Scoped-mandate extension type.  NOT standardized by x401 v0.2.0."""

X401_FALLBACKS: list[str] = []

_x401_codec = None
_x401_jws = None
_x401_mandate = None
_x401_request = None

try:  # pragma: no cover - depends on the parallel track
    from x401 import codec as _x401_codec  # noqa: F401
    from x401 import jws as _x401_jws  # noqa: F401
    from x401 import mandate as _x401_mandate  # noqa: F401
    from x401 import request as _x401_request  # noqa: F401
except Exception as exc:  # x401 not built yet -- local fallbacks below
    log.info("sibling x401 package not importable (%s); using local fallbacks", exc)

HAVE_X401 = _x401_mandate is not None


def _fallback(name: str) -> None:
    if name not in X401_FALLBACKS:
        X401_FALLBACKS.append(name)


# ---------------------------------------------------------------------------
# base64url helpers (RFC 4648 section 5, no padding -- as x401 mandates)
# ---------------------------------------------------------------------------

def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    if isinstance(text, bytes):
        text = text.decode("ascii")
    text = text.strip()
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ---------------------------------------------------------------------------
# Canonical JSON (the SIWE property: the person signs exactly what they see)
# ---------------------------------------------------------------------------

def canonical(obj: dict) -> bytes:
    """Canonical byte form of a mandate/terms object."""
    if _x401_mandate is not None:
        fn = getattr(_x401_mandate, "canonical", None)
        if callable(fn):
            try:
                out = fn(obj)
                return out if isinstance(out, bytes) else str(out).encode("utf-8")
            except Exception:
                pass
    _fallback("mandate.canonical")
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# Ed25519 keys
# ---------------------------------------------------------------------------

def _ed_private_key_class():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    return Ed25519PrivateKey


def normalize_private_key(key):
    """Accept a private key in any supported shape -> Ed25519PrivateKey."""
    Ed25519PrivateKey = _ed_private_key_class()
    if isinstance(key, Ed25519PrivateKey):
        return key
    if isinstance(key, (bytes, bytearray)) and len(key) == 32:
        return Ed25519PrivateKey.from_private_bytes(bytes(key))
    if isinstance(key, str):  # base64url seed
        raw = b64u_decode(key)
        if len(raw) == 32:
            return Ed25519PrivateKey.from_private_bytes(raw)
    if isinstance(key, dict):
        for field in ("seed", "private_bytes", "private", "d"):
            if field in key:
                return normalize_private_key(key[field])
    if isinstance(key, (tuple, list)) and key:
        return normalize_private_key(key[0])
    raise TypeError(f"unsupported private key shape: {type(key).__name__}")


def normalize_public_key(key):
    """Accept a public key in any supported shape -> Ed25519PublicKey."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )
    if isinstance(key, Ed25519PublicKey):
        return key
    if isinstance(key, dict):  # JWK
        if key.get("kty") == "OKP" and key.get("crv") == "Ed25519" and "x" in key:
            raw = b64u_decode(key["x"])
            if len(raw) == 32:
                return Ed25519PublicKey.from_public_bytes(raw)
        raise TypeError(f"unsupported public JWK: {key!r}")
    if isinstance(key, (bytes, bytearray)) and len(key) == 32:
        return Ed25519PublicKey.from_public_bytes(bytes(key))
    if isinstance(key, str):
        raw = b64u_decode(key)
        if len(raw) == 32:
            return Ed25519PublicKey.from_public_bytes(raw)
    raise TypeError(f"unsupported public key shape: {type(key).__name__}")


def generate_keypair():
    """Return ``(private_key, public_jwk)`` for a fresh Ed25519 device key."""
    if _x401_jws is not None:
        gen = getattr(_x401_jws, "generate_ed25519_keypair", None)
        if callable(gen):
            try:
                # x401 returns a (private, public) tuple
                priv = normalize_private_key(gen())
                return priv, public_jwk_from_private(priv)
            except Exception:
                pass
    _fallback("jws.generate_ed25519_keypair")
    priv = _ed_private_key_class().generate()
    return priv, public_jwk_from_private(priv)


def public_jwk_from_private(private_key) -> dict:
    """Public JWK (OKP/Ed25519) for a private key."""
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )
    priv = normalize_private_key(private_key)
    if _x401_jws is not None:
        # x401.jws.jwk_public expects the PUBLIC key object
        fn = getattr(_x401_jws, "jwk_public", None)
        if callable(fn):
            for candidate in (priv.public_key(), priv):
                try:
                    jwk = fn(candidate)
                except Exception:
                    continue
                if isinstance(jwk, dict) and jwk.get("kty"):
                    return jwk
    _fallback("jws.jwk_public")
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u_encode(raw)}


def key_id(public_jwk: dict) -> str:
    """Stable key id: first 96 bits of SHA-256 over the raw public key."""
    raw = b64u_decode(public_jwk["x"])
    return b64u_encode(hashlib.sha256(raw).digest()[:12])


# ---------------------------------------------------------------------------
# Scoped mandate (x- extension -- NOT standardized by x401 v0.2.0)
# ---------------------------------------------------------------------------

class MandateError(ValueError):
    """Raised when a mandate token fails verification or schema checks."""


def build_mandate(*, agent: str, merchant: str, action_category: str,
                  amount_ceiling: dict, not_before: int, not_after: int,
                  nonce: str, issuer: str | None = None,
                  request_id: str | None = None) -> dict:
    """Build the scoped-mandate claims object (type ``x-x401ext-mandate/v1``)."""
    claims = {
        "type": MANDATE_TYPE,
        "agent": agent,
        "merchant": merchant,
        "action_category": action_category,
        "amount_ceiling": {
            "currency": str(amount_ceiling.get("currency", "USD")),
            "value": str(amount_ceiling.get("value", "0")),
        },
        "not_before": int(not_before),
        "not_after": int(not_after),
        "nonce": nonce,
    }
    if issuer:
        claims["iss"] = issuer
    if request_id:
        claims["request_id"] = request_id
    if _x401_mandate is not None:
        fn = getattr(_x401_mandate, "build_mandate", None)
        if callable(fn):
            try:
                # Their builder is schema-strict (no "iss" yet); add our
                # extension field afterwards.
                kwargs = {k: v for k, v in claims.items() if k != "iss"}
                built = fn(**kwargs)
                if isinstance(built, dict):
                    if issuer:
                        built.setdefault("iss", issuer)
                    return built
            except Exception:
                pass
    _fallback("mandate.build_mandate")
    return claims


def sign_mandate(mandate: dict, private_key, kid: str | None = None) -> str:
    """Sign a mandate -> JWS compact serialization (EdDSA).

    Prefers the sibling ``x401`` signer; the device ``kid`` is carried in
    the JWS header (via ``x401.jws.sign_raw``'s ``extra_header``) so verifiers
    can match the signature to a known device key.
    """
    priv = normalize_private_key(private_key)
    if _x401_mandate is not None:
        sign_raw = getattr(_x401_jws, "sign_raw", None) if _x401_jws else None
        x_canonical = getattr(_x401_mandate, "canonical", None)
        if kid and callable(sign_raw) and callable(x_canonical):
            try:
                return sign_raw(x_canonical(mandate), priv, alg="EdDSA",
                                extra_header={"kid": kid})
            except Exception:
                pass
        fn = getattr(_x401_mandate, "sign_mandate", None)
        if callable(fn):
            try:
                token = fn(mandate, priv)
                if isinstance(token, str) and token.count(".") == 2:
                    return token
            except Exception:
                pass
    _fallback("mandate.sign_mandate")
    header = {"alg": "EdDSA", "typ": "JWT"}
    if kid:
        header["kid"] = kid
    h = b64u_encode(json.dumps(header, separators=(",", ":")).encode("ascii"))
    p = b64u_encode(canonical(mandate))
    sig = priv.sign(f"{h}.{p}".encode("ascii"))
    return f"{h}.{p}.{b64u_encode(sig)}"


def verify_mandate(token: str, public_key, check_time: bool = True,
                   now: float | None = None) -> dict:
    """Verify a mandate JWS -> claims dict.  Raises :class:`MandateError`.

    Verification order: the sibling ``x401.mandate`` verifier first when
    available, then the local verifier.  Tampering with any signed byte
    (including a single character of the amount) fails verification.

    Note: the sibling verifier always enforces the validity window, so
    ``check_time=False`` bypasses it and uses the local verifier.
    """
    # The sibling verifier always enforces the time window.
    if _x401_mandate is not None and check_time:
        fn = getattr(_x401_mandate, "verify_mandate", None)
        if callable(fn):
            try:
                kwargs = {"now": now} if now is not None else {}
                claims = fn(token, public_key, **kwargs)
                if isinstance(claims, dict):
                    return claims
            except Exception:
                pass  # fall through to local verifier
    elif _x401_mandate is None:
        _fallback("mandate.verify_mandate")
    else:
        _fallback("mandate.verify_mandate/check_time=False")
    try:
        h_b64, p_b64, s_b64 = token.split(".")
    except ValueError:
        raise MandateError("not a JWS compact serialization (want 3 parts)")
    try:
        header = json.loads(b64u_decode(h_b64))
        payload_bytes = b64u_decode(p_b64)
        signature = b64u_decode(s_b64)
    except Exception as exc:
        raise MandateError(f"malformed JWS encoding: {exc}")
    if header.get("alg") not in ("EdDSA", "Ed25519"):
        raise MandateError(f"unsupported JWS alg: {header.get('alg')!r}")
    pub = normalize_public_key(public_key)
    try:
        pub.verify(signature, f"{h_b64}.{p_b64}".encode("ascii"))
    except Exception:
        raise MandateError("signature verification failed -- "
                           "mandate was altered or signed by another key")
    try:
        claims = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        raise MandateError(f"mandate payload is not JSON: {exc}")
    if not isinstance(claims, dict) or claims.get("type") != MANDATE_TYPE:
        raise MandateError(
            f"wrong mandate type: {claims.get('type')!r} (want {MANDATE_TYPE!r})")
    for field in ("agent", "merchant", "action_category", "amount_ceiling",
                  "not_before", "not_after", "nonce"):
        if field not in claims:
            raise MandateError(f"mandate missing required field: {field}")
    if check_time:
        ts = now if now is not None else _time.time()
        if not (claims["not_before"] <= ts <= claims["not_after"]):
            raise MandateError("mandate is outside its validity window")
    return claims


# ---------------------------------------------------------------------------
# Proof-request parsing (holder side is lenient: display, don't enforce)
# ---------------------------------------------------------------------------

def parse_proof_request(payload) -> dict:
    """Parse/validate a submitted x401 PROOF-REQUEST payload (lenient).

    The wallet is holder-side: it displays what was asked, it does not
    enforce verifier policy.  Malformed payloads are rejected, but unknown
    extension members are preserved for display.
    """
    if _x401_request is not None:
        fn = getattr(_x401_request, "parse_proof_request", None)
        if callable(fn):
            try:
                parsed = fn(payload)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                # Their parser is strict (spec-conformant); the wallet is
                # intentionally lenient holder-side, so fall through.
                _fallback("request.parse_proof_request/strict")
    else:
        _fallback("request.parse_proof_request")
    if not isinstance(payload, dict):
        raise ValueError("proof_request must be a JSON object")
    scheme = payload.get("scheme", "x401")
    if scheme != "x401":
        raise ValueError(f"unsupported scheme: {scheme!r}")
    return dict(payload)

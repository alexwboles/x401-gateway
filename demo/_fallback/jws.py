"""Fallback ``x401.jws`` — compact JWS with EdDSA (Ed25519) and ES256.

Covers the documented surface (``generate_ed25519_keypair``, ``jwk_public``) plus the
sign/verify primitives the fallback ``request``/``mandate``/``oauth`` modules need.
``public_key_from_jwk`` is a fallback-only extra used by ``demo/_compat.py``.
"""

import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .codec import b64u_decode, b64u_encode

__all__ = [
    "JwsError",
    "generate_ed25519_keypair",
    "generate_p256_keypair",
    "jwk_public",
    "public_key_from_jwk",
    "sign_compact",
    "verify_compact",
]


class JwsError(Exception):
    """Raised for malformed JWS or failed signature verification."""


def generate_ed25519_keypair():
    """Return ``(private_key, public_key)`` Ed25519 keypair."""
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def generate_p256_keypair():
    """Return ``(private_key, public_key)`` NIST P-256 keypair (for ES256)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


def jwk_public(public_key) -> dict:
    """Public JWK for an Ed25519 or P-256 public key."""
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "x": b64u_encode(raw)}
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        nums = public_key.public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": b64u_encode(nums.x.to_bytes(32, "big")),
            "y": b64u_encode(nums.y.to_bytes(32, "big")),
        }
    raise JwsError(f"unsupported public key type: {type(public_key).__name__}")


def public_key_from_jwk(jwk: dict):
    """Rebuild a public key from a JWK dict (fallback-only extra)."""
    kty = jwk.get("kty")
    if kty == "OKP" and jwk.get("crv") == "Ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(b64u_decode(jwk["x"]))
    if kty == "EC" and jwk.get("crv") == "P-256":
        point = (
            b"\x04" + b64u_decode(jwk["x"]) + b64u_decode(jwk["y"])
        )
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    raise JwsError(f"unsupported JWK: kty={kty} crv={jwk.get('crv')}")


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_compact(payload: dict, private_key, *, alg: str = "EdDSA",
                 kid: str | None = None, extra_header: dict | None = None) -> str:
    """Sign a claims dict, returning a JWS compact serialization."""
    header = {"alg": alg, "typ": "JWT"}
    if kid:
        header["kid"] = kid
    if extra_header:
        header.update(extra_header)
    h_b64 = b64u_encode(_canonical(header))
    p_b64 = b64u_encode(_canonical(payload))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    if alg == "EdDSA":
        sig = private_key.sign(signing_input)
    elif alg == "ES256":
        der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        raise JwsError(f"unsupported alg {alg!r} (fallback supports EdDSA, ES256)")
    return f"{h_b64}.{p_b64}.{b64u_encode(sig)}"


def verify_compact(token: str, public_key) -> dict:
    """Verify a compact JWS and return its payload; raises :class:`JwsError`."""
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        header = json.loads(b64u_decode(h_b64))
        payload = json.loads(b64u_decode(p_b64))
        sig = b64u_decode(s_b64)
    except Exception as exc:
        raise JwsError(f"malformed compact JWS: {exc}")
    alg = header.get("alg")
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    try:
        if alg == "EdDSA":
            if len(sig) != 64:
                raise JwsError("malformed EdDSA signature")
            public_key.verify(sig, signing_input)
        elif alg == "ES256":
            if len(sig) != 64:
                raise JwsError("malformed ES256 signature")
            r = int.from_bytes(sig[:32], "big")
            s = int.from_bytes(sig[32:], "big")
            public_key.verify(
                encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256())
            )
        else:
            raise JwsError(f"unsupported alg {alg!r} (fallback supports EdDSA, ES256)")
    except InvalidSignature:
        raise JwsError("JWS signature does not verify")
    return payload

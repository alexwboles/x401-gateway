"""JWS compact serialization (RFC 7515) for x401 v0.2.0.

Supported algorithms: EdDSA (Ed25519) and ES256 (P-256). Per JOSE, the ES256
signature is the raw R||S 64-byte concatenation -- NOT ASN.1 DER. This module
converts DER<->raw in both directions. Real crypto via the `cryptography`
package; no home-grown primitives.
"""

from __future__ import annotations

import base64
import binascii
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography import x509

__all__ = [
    "JWSError",
    "sign",
    "verify",
    "generate_ed25519_keypair",
    "generate_p256_keypair",
    "jwk_public",
    "key_from_jwk_public",
    "parse_x5c",
]

SUPPORTED_ALGS = ("EdDSA", "ES256")


class JWSError(ValueError):
    """Raised on any JWS verification or key-handling failure."""


def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64u_decode(s: str) -> bytes:
    if not isinstance(s, str):
        raise JWSError("base64url input must be a string")
    rem = len(s) % 4
    if rem == 1:
        raise JWSError("invalid base64url length")
    try:
        return base64.b64decode(s + ("=" * ((4 - rem) % 4)), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise JWSError(f"invalid base64url: {exc}") from exc


def _check_alg(alg: str) -> None:
    if alg not in SUPPORTED_ALGS:
        raise JWSError(f"unsupported alg {alg!r}; expected one of {SUPPORTED_ALGS}")


def sign_raw(payload_bytes: bytes, private_key, alg: str, extra_header: dict | None = None) -> str:
    """Sign raw payload bytes; returns a JWS compact serialization."""
    _check_alg(alg)
    header = {"alg": alg, "typ": "JWT"}
    if extra_header:
        header.update(extra_header)
    protected = _b64u_encode(json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    body = _b64u_encode(payload_bytes)
    signing_input = f"{protected}.{body}".encode("ascii")
    if alg == "EdDSA":
        if not isinstance(private_key, Ed25519PrivateKey):
            raise JWSError("EdDSA requires an Ed25519 private key")
        signature = private_key.sign(signing_input)
    else:  # ES256
        if not isinstance(private_key, EllipticCurvePrivateKey) or not isinstance(
            private_key.curve, SECP256R1
        ):
            raise JWSError("ES256 requires a P-256 (SECP256R1) private key")
        der = private_key.sign(signing_input, ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")  # JOSE raw R||S
    return f"{protected}.{body}.{_b64u_encode(signature)}"


def sign(payload: dict, private_key, alg: str) -> str:
    """Sign a dict payload (canonical JSON) with EdDSA or ES256. Returns JWS compact."""
    if not isinstance(payload, dict):
        raise JWSError("payload must be a dict")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    return sign_raw(canonical, private_key, alg)


def _split_compact(compact: str) -> tuple[dict, bytes, bytes, bytes]:
    parts = compact.split(".")
    if len(parts) != 3:
        raise JWSError("JWS compact serialization must have 3 parts")
    try:
        header = json.loads(_b64u_decode(parts[0]).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise JWSError(f"invalid JWS protected header: {exc}") from exc
    if not isinstance(header, dict):
        raise JWSError("JWS protected header must be a JSON object")
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    return header, signing_input, _b64u_decode(parts[1]), _b64u_decode(parts[2])


def verify(compact: str, public_key, expected_alg: str | None = None) -> dict:
    """Verify a JWS compact serialization; return the payload dict.

    Raises JWSError on malformed input, algorithm mismatch, unsupported alg,
    or bad signature.
    """
    if not isinstance(compact, str):
        raise JWSError("compact JWS must be a string")
    header, signing_input, payload_bytes, signature = _split_compact(compact)
    alg = header.get("alg")
    _check_alg(alg)
    if expected_alg is not None and alg != expected_alg:
        raise JWSError(f"algorithm mismatch: token is {alg!r}, expected {expected_alg!r}")
    try:
        if alg == "EdDSA":
            if not isinstance(public_key, Ed25519PublicKey):
                raise JWSError("EdDSA verification requires an Ed25519 public key")
            public_key.verify(signature, signing_input)
        else:  # ES256
            if not isinstance(public_key, EllipticCurvePublicKey) or not isinstance(
                public_key.curve, SECP256R1
            ):
                raise JWSError("ES256 verification requires a P-256 public key")
            if len(signature) != 64:
                raise JWSError("ES256 signature must be 64 raw bytes (R||S)")
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            public_key.verify(encode_dss_signature(r, s), signing_input, ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise JWSError("signature verification failed") from exc
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise JWSError(f"invalid JWS payload: {exc}") from exc
    if not isinstance(payload, dict):
        raise JWSError("JWS payload must be a JSON object")
    return payload


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private = Ed25519PrivateKey.generate()
    return private, private.public_key()


def generate_p256_keypair() -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    private = ec.generate_private_key(SECP256R1())
    return private, private.public_key()


def jwk_public(key) -> dict:
    """Public key -> JWK dict (OKP/Ed25519 or EC/P-256)."""
    if isinstance(key, Ed25519PublicKey):
        raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "x": _b64u_encode(raw)}
    if isinstance(key, EllipticCurvePublicKey) and isinstance(key.curve, SECP256R1):
        numbers = key.public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64u_encode(numbers.x.to_bytes(32, "big")),
            "y": _b64u_encode(numbers.y.to_bytes(32, "big")),
        }
    raise JWSError("unsupported public key type for JWK export")


def key_from_jwk_public(jwk: dict):
    """JWK dict -> public key object (OKP/Ed25519 or EC/P-256)."""
    if not isinstance(jwk, dict):
        raise JWSError("JWK must be a dict")
    kty = jwk.get("kty")
    try:
        if kty == "OKP" and jwk.get("crv") == "Ed25519":
            raw = _b64u_decode(jwk["x"])
            if len(raw) != 32:
                raise JWSError("Ed25519 JWK 'x' must be 32 bytes")
            return Ed25519PublicKey.from_public_bytes(raw)
        if kty == "EC" and jwk.get("crv") == "P-256":
            x = int.from_bytes(_b64u_decode(jwk["x"]), "big")
            y = int.from_bytes(_b64u_decode(jwk["y"]), "big")
            return EllipticCurvePublicKey.from_encoded_point(SECP256R1(), b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big"))
    except KeyError as exc:
        raise JWSError(f"JWK missing required member: {exc}") from exc
    raise JWSError(f"unsupported JWK: kty={kty!r} crv={jwk.get('crv')!r}")


def parse_x5c(header: dict) -> list[bytes]:
    """Extract DER certificate bytes from a JWS `x5c` header member (best-effort).

    Returns a list of DER-encoded certificates; entries that fail to decode or
    parse are skipped.
    """
    chain = header.get("x5c") if isinstance(header, dict) else None
    if not isinstance(chain, list):
        return []
    certs: list[bytes] = []
    for entry in chain:
        if not isinstance(entry, str):
            continue
        try:
            # x5c uses standard base64 (RFC 7515 section 4.1.6), padding allowed.
            der = base64.b64decode(entry, validate=True)
            x509.load_der_x509_certificate(der)  # validate it parses as a cert
        except Exception:
            continue
        certs.append(der)
    return certs

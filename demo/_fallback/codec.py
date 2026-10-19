"""Fallback ``x401.codec`` — strict base64url/JSON header codec.

Wire rules (x401 v0.2.0): each header value is exactly one base64url-encoded
(RFC 4648 section 5, URL-safe alphabet, NO padding) UTF-8 JSON object; header names
are case-insensitive; at most one field line per name; comma-joined lists invalid.
"""

import base64
import binascii
import json

__all__ = [
    "CodecError",
    "b64u_encode",
    "b64u_decode",
    "encode_payload",
    "decode_payload",
    "parse_header",
    "emit_header",
]


class CodecError(Exception):
    """Raised when a header value or payload is not strict x401 wire format."""


_B64U_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def b64u_encode(data: bytes) -> str:
    """Base64url-encode bytes, no padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    """Strict base64url decode: rejects padding, whitespace, and bad alphabet."""
    if not isinstance(s, str) or not s:
        raise CodecError("base64url value must be a non-empty string")
    if any(ch not in _B64U_ALPHABET for ch in s):
        raise CodecError(
            "base64url value contains illegal characters "
            "(strict: URL-safe alphabet, no padding, no whitespace)"
        )
    if len(s) % 4 == 1:
        raise CodecError("invalid base64url length")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError) as exc:
        raise CodecError(f"base64url decode failed: {exc}")


def encode_payload(obj: dict) -> str:
    """Canonical-JSON-encode a payload dict, then strict base64url (no padding)."""
    try:
        raw = json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CodecError(f"payload is not JSON-serializable: {exc}")
    return b64u_encode(raw)


def decode_payload(s: str) -> dict:
    """Strict-decode a base64url payload into a dict."""
    raw = b64u_decode(s)
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise CodecError(f"payload is not UTF-8 JSON: {exc}")
    if not isinstance(obj, dict):
        raise CodecError("x401 payload must be a JSON object")
    return obj


def parse_header(value: str) -> dict:
    """Parse one x401 header field value; rejects multi-line / comma-joined values."""
    if not isinstance(value, str):
        raise CodecError("header value must be a string")
    if "\r" in value or "\n" in value:
        raise CodecError("header value must be a single field line")
    if "," in value:
        raise CodecError("comma-joined header lists are invalid in x401")
    return decode_payload(value.strip())


def emit_header(obj: dict) -> str:
    """Encode a payload dict as an x401 header field value."""
    return encode_payload(obj)

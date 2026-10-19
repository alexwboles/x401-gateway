"""Strict base64url(JSON) header codec for x401 v0.2.0.

Every PROOF-* header value is exactly one base64url-encoded (RFC 4648 section 5,
URL-safe alphabet, NO padding) UTF-8 JSON object. This module enforces that
strictly: padding, whitespace, multi-line values, and comma-joined lists are all
rejected with CodecError.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Mapping

__all__ = ["CodecError", "encode_payload", "decode_payload", "parse_header", "emit_header"]

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_WS_RE = re.compile(r"\s")


class CodecError(ValueError):
    """Raised when a header value or payload violates the strict wire encoding."""


def _canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def encode_payload(obj: dict) -> str:
    """Canonical JSON (sorted keys, compact separators) -> base64url, no padding."""
    if not isinstance(obj, dict):
        raise CodecError("payload must be a JSON object (dict)")
    raw = _canonical_json(obj)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_payload(s: str) -> dict:
    """Strictly decode one base64url(JSON object) header value.

    Rejects: non-str input, any '=' padding, any whitespace (covers multi-line),
    characters outside the base64url alphabet, bad padding length, non-UTF8,
    non-JSON, and JSON that is not an object.
    """
    if not isinstance(s, str) or not s:
        raise CodecError("header value must be a non-empty string")
    if "=" in s:
        raise CodecError("base64url padding '=' is forbidden")
    if _WS_RE.search(s):
        raise CodecError("header value must be a single line with no whitespace")
    if not _B64URL_RE.match(s):
        raise CodecError("header value contains characters outside the base64url alphabet")
    # Restore padding for decoding; length mod 4 == 1 is impossible for valid input.
    rem = len(s) % 4
    if rem == 1:
        raise CodecError("invalid base64url length")
    padded = s + ("=" * ((4 - rem) % 4))
    try:
        raw = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CodecError(f"invalid base64url encoding: {exc}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CodecError("header value is not UTF-8") from exc
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CodecError(f"header value is not JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise CodecError("header value must decode to a JSON object")
    return obj


def parse_header(headers: Mapping, name: str) -> dict:
    """Find header `name` case-insensitively and strictly decode its value.

    The value must be a single line with no commas (comma-joined lists and
    multi-line values are invalid per the x401 v0.2.0 wire model).
    """
    found = None
    try:
        items = headers.items()
    except AttributeError as exc:
        raise CodecError("headers must be a mapping") from exc
    for key, value in items:
        if isinstance(key, str) and key.lower() == name.lower():
            found = value
            break
    if found is None:
        raise CodecError(f"missing required header: {name}")
    if isinstance(found, (list, tuple)):
        raise CodecError(f"header {name}: multiple values are not allowed")
    if not isinstance(found, str):
        raise CodecError(f"header {name}: value must be a string")
    if "," in found:
        raise CodecError(f"header {name}: comma-joined lists are not allowed")
    if "\n" in found or "\r" in found:
        raise CodecError(f"header {name}: multi-line values are not allowed")
    return decode_payload(found)


def emit_header(name: str, obj: dict) -> tuple[str, str]:
    """Return (header-name, encoded-value) ready to set on an HTTP message."""
    return (name, encode_payload(obj))

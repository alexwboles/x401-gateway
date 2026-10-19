"""PROOF-RESULT error object construction and parsing (x401 v0.2.0)."""

from __future__ import annotations

__all__ = ["ResultError", "ERROR_TOKENS", "make_result", "parse_result"]

SCHEME = "x401"
VERSION = "0.2.0"

# Standard error tokens used across the gateway. The spec leaves `error` as a
# verifier-defined short ASCII token; we standardize on these.
ERROR_TOKENS = frozenset(
    {
        "invalid_request",
        "invalid_response",
        "unsupported_version",
        "unknown_nonce",
        "replayed_nonce",
        "expired_challenge",
        "invalid_signature",
        "untrusted_issuer",
        "unsatisfied_requirements",
        "wrong_binding",
        "expired_mandate",
        "tampered_mandate",
        "mandate_exceeded",
        "invalid_token",
        "token_expired",
        "ssrf_blocked",
        "unsupported_protocol",
    }
)


class ResultError(ValueError):
    """Raised when a PROOF-RESULT payload is malformed."""


def make_result(
    error: str,
    description: str | None = None,
    error_uri: str | None = None,
    request_id: str | None = None,
) -> dict:
    """Build a v0.2.0 x401 Error Object payload."""
    result: dict = {"scheme": SCHEME, "version": VERSION, "error": error}
    if description is not None:
        result["error_description"] = description
    if error_uri is not None:
        result["error_uri"] = error_uri
    if request_id is not None:
        result["request_id"] = request_id
    return result


def parse_result(obj: dict) -> dict:
    """Validate a decoded PROOF-RESULT payload; return it unchanged on success."""
    if not isinstance(obj, dict):
        raise ResultError("PROOF-RESULT must decode to a JSON object")
    if obj.get("scheme") != SCHEME:
        raise ResultError(f"scheme must be {SCHEME!r}")
    if obj.get("version") != VERSION:
        raise ResultError(f"unsupported version {obj.get('version')!r}")
    error = obj.get("error")
    if not isinstance(error, str) or not error:
        raise ResultError("PROOF-RESULT requires a non-empty 'error' token")
    return obj

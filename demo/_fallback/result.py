"""Fallback ``x401.result`` — build/parse PROOF-RESULT (x401 response info)."""

from .codec import parse_header

__all__ = ["ResultError", "make_result", "parse_result"]

X401_VERSION = "0.2.0"


class ResultError(Exception):
    """Raised when a PROOF-RESULT value is not a valid x401 result object."""

    def __init__(self, code: str, description: str = ""):
        super().__init__(description or code)
        self.code = code


def make_result(*, error=None, error_description=None, error_uri=None,
                request_id=None, **extra) -> dict:
    """Build the x401 response-info object carried by PROOF-RESULT."""
    res = {"scheme": "x401", "version": X401_VERSION}
    if error:
        res["error"] = error
    if error_description:
        res["error_description"] = error_description
    if error_uri:
        res["error_uri"] = error_uri
    if request_id:
        res["request_id"] = request_id
    res.update(extra)
    return res


def parse_result(obj) -> dict:
    """Validate and return a PROOF-RESULT object (dict or raw header value)."""
    if isinstance(obj, str):
        obj = parse_header(obj)
    if (not isinstance(obj, dict) or obj.get("scheme") != "x401"
            or obj.get("version") != X401_VERSION):
        raise ResultError("invalid_response", "not an x401 v0.2.0 result object")
    return obj

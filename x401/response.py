"""PROOF-RESPONSE parsing and SSRF-guarded by-reference dereferencing.

Three mutually exclusive forms (exactly one required):
  inline        {credential_result: {protocol, data}}
  by_reference  {credential_result_uri: https://...}
  token_object  {scheme, version, token_type, access_token}
"""

from __future__ import annotations

import ipaddress
import json
import socket
import urllib.parse
import urllib.request

__all__ = ["ResponseError", "parse_proof_response", "dereference"]

SCHEME = "x401"
VERSION = "0.2.0"


class ResponseError(ValueError):
    """Raised on malformed PROOF-RESPONSE values or blocked/failing dereference.

    Carries a machine-readable ``.code`` (e.g. 'ssrf_blocked', 'too_large').
    """

    def __init__(self, code: str, message: str | None = None):
        self.code = code
        super().__init__(message or code)


def parse_proof_response(obj: dict) -> dict:
    """Parse a decoded PROOF-RESPONSE value into a normalized form dict.

    Returns {'form': 'inline'|'by_reference'|'token_object', ...}. Raises
    ResponseError unless exactly one of the three forms is present.
    """
    if not isinstance(obj, dict):
        raise ResponseError("invalid_response", "PROOF-RESPONSE must decode to a JSON object")

    has_inline = "credential_result" in obj
    has_ref = "credential_result_uri" in obj
    looks_like_token = all(k in obj for k in ("scheme", "version", "token_type", "access_token"))
    # A token object must not ride alongside result-artifact members: any
    # mixture is invalid, not "the other form wins".
    count = sum((has_inline, has_ref, looks_like_token))
    if count != 1:
        raise ResponseError(
            "invalid_response",
            "PROOF-RESPONSE must contain exactly one of credential_result, "
            "credential_result_uri, or an x401 Token Object",
        )
    has_token = looks_like_token

    request_id = obj.get("request_id")
    if has_inline:
        cr = obj["credential_result"]
        if not isinstance(cr, dict) or "protocol" not in cr or "data" not in cr:
            raise ResponseError("invalid_response", "credential_result needs {protocol, data}")
        return {
            "form": "inline",
            "request_id": request_id,
            "agent_id": obj.get("agent_id"),
            "credential_result": {"protocol": cr["protocol"], "data": cr["data"]},
        }
    if has_ref:
        uri = obj["credential_result_uri"]
        if not isinstance(uri, str) or not uri.startswith("https://"):
            raise ResponseError("invalid_response", "credential_result_uri must be an https URL")
        return {
            "form": "by_reference",
            "request_id": request_id,
            "agent_id": obj.get("agent_id"),
            "credential_result_uri": uri,
            "expires_at": obj.get("expires_at"),
        }
    if obj.get("scheme") != SCHEME or obj.get("version") != VERSION:
        raise ResponseError("invalid_response", "Token Object must carry scheme x401 / version 0.2.0")
    return {
        "form": "token_object",
        "token_type": obj["token_type"],
        "access_token": obj["access_token"],
    }


# ---------------------------------------------------------------------------
# SSRF-guarded dereference
# ---------------------------------------------------------------------------

def _check_uri(uri: str, allowed_prefix: str, allow_http: bool = False) -> urllib.parse.ParseResult:
    """Validate scheme + verifier-issued prefix. Raises ResponseError."""
    try:
        parsed = urllib.parse.urlparse(uri)
    except Exception as exc:
        raise ResponseError("invalid_uri", f"unparseable URI: {exc}") from exc
    if parsed.scheme not in ("https", "http") or (parsed.scheme == "http" and not allow_http):
        raise ResponseError("ssrf_blocked", "credential_result_uri must use https")
    if not parsed.hostname:
        raise ResponseError("invalid_uri", "URI has no host")
    if not uri.startswith(allowed_prefix):
        raise ResponseError("ssrf_blocked", "URI is outside the verifier-issued prefix")
    return parsed


def _check_host_ips(hostname: str) -> None:
    """Resolve the host and reject non-public IPs. Raises ResponseError('ssrf_blocked')."""
    try:
        infos = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ResponseError("ssrf_blocked", f"DNS resolution failed: {exc}") from exc
    if not infos:
        raise ResponseError("ssrf_blocked", "DNS resolution returned no addresses")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise ResponseError("ssrf_blocked", f"resolved IP {ip} is not publicly routable")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        raise ResponseError("redirect_blocked", "redirects are not followed for result dereference")


def dereference(
    uri: str,
    *,
    allowed_prefix: str,
    timeout: float = 5,
    max_bytes: int = 65536,
    _allow_http: bool = False,
) -> dict:
    """GET a by-reference result artifact with SSRF guards.

    Guards: https-only (``_allow_http`` is a testing hook only), the URI must
    start with the verifier-issued ``allowed_prefix``, every resolved IP must be
    publicly routable, no redirects are followed, and the response is bounded
    by ``timeout`` seconds and ``max_bytes``.

    Single-use of the capability URL is enforced by the caller (mark the URI
    consumed after the first successful dereference).

    Returns the decoded JSON object. Raises ResponseError.
    """
    parsed = _check_uri(uri, allowed_prefix, allow_http=_allow_http)
    if parsed.scheme not in ("https", "http") or (parsed.scheme == "http" and not _allow_http):
        raise ResponseError("ssrf_blocked", "credential_result_uri must use https")
    _check_host_ips(parsed.hostname)

    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(uri, headers={"Accept": "application/json", "User-Agent": "x401-gateway/0.1"})
    try:
        with opener.open(request, timeout=timeout) as resp:
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = resp.read(16384)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ResponseError("too_large", f"response exceeds {max_bytes} bytes")
                chunks.append(chunk)
            body = b"".join(chunks)
    except ResponseError:
        raise
    except Exception as exc:  # timeouts, refused connections, redirect blocks raised above pass through
        raise ResponseError("fetch_failed", f"GET failed: {exc}") from exc

    try:
        obj = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ResponseError("invalid_response", f"dereferenced body is not JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ResponseError("invalid_response", "dereferenced body must be a JSON object")
    return obj

"""Fallback ``x401.response`` — parse PROOF-RESPONSE, dereference by-ref artifacts.

By-reference dereference carries the spec's SSRF guards: https-only (or explicitly
allowed local http), verifier-issued prefix allowlist, DNS resolution with
non-public-address rejection, and fetch size/time bounds.
"""

import ipaddress
import json
import socket
import urllib.parse
import urllib.request

from .codec import decode_payload, parse_header

__all__ = ["ResponseError", "DereferenceError", "parse_proof_response", "dereference"]


class ResponseError(Exception):
    """Invalid result artifact; carries an x401 error ``code``."""

    def __init__(self, code: str, description: str = ""):
        super().__init__(description or code)
        self.code = code


class DereferenceError(ResponseError):
    """By-reference fetch refused or failed (usually ``ssrf_blocked``)."""


def parse_proof_response(obj) -> dict:
    """Validate a Result Artifact: exactly one of credential_result / credential_result_uri."""
    if isinstance(obj, str):
        obj = parse_header(obj)
    if not isinstance(obj, dict):
        raise ResponseError("invalid_response", "PROOF-RESPONSE must decode to a JSON object")
    has_result = "credential_result" in obj
    has_uri = "credential_result_uri" in obj
    if has_result == has_uri:
        raise ResponseError(
            "invalid_response",
            "exactly one of 'credential_result' / 'credential_result_uri' is required",
        )
    if has_result:
        cred = obj["credential_result"]
        if not isinstance(cred, dict) or "protocol" not in cred or "data" not in cred:
            raise ResponseError(
                "invalid_response", "credential_result must be {protocol, data}")
    else:
        uri = obj["credential_result_uri"]
        if not isinstance(uri, str) or not uri.startswith("https://"):
            raise ResponseError(
                "invalid_response", "credential_result_uri must be an https URL")
    return obj


def dereference(uri: str, *, allowed_prefixes=(), timeout: int = 5,
                max_bytes: int = 65536, allow_local_http: bool = False) -> dict:
    """Fetch a by-reference artifact with SSRF guards; returns the artifact dict."""
    parts = urllib.parse.urlparse(uri)
    local_host = parts.hostname in ("127.0.0.1", "localhost", "::1")
    if parts.scheme == "http" and allow_local_http and local_host:
        pass  # demo-local exception, explicitly opted in
    elif parts.scheme != "https":
        raise DereferenceError("ssrf_blocked", "by-reference artifact must use https")
    if allowed_prefixes and not any(uri.startswith(p) for p in allowed_prefixes):
        raise DereferenceError(
            "ssrf_blocked", "URI is not within a verifier-issued prefix")
    # Address-level guard: resolve and reject non-public addresses (TOCTOU noted in docs).
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or 443,
                                   type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise DereferenceError("ssrf_blocked", f"DNS resolution failed: {exc}")
    for info in {i[4][0] for i in infos}:
        ip = ipaddress.ip_address(info)
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified):
            raise DereferenceError(
                "ssrf_blocked", f"artifact host resolves to non-public address {info}")
    req = urllib.request.Request(uri, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                raise DereferenceError(
                    "ssrf_blocked", f"artifact fetch returned HTTP {resp.status}")
            raw = resp.read(max_bytes + 1)
    except DereferenceError:
        raise
    except Exception as exc:
        raise DereferenceError("ssrf_blocked", f"artifact fetch failed: {exc}")
    if len(raw) > max_bytes:
        raise DereferenceError("ssrf_blocked", "artifact exceeds size bound")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise DereferenceError("invalid_response", f"artifact is not JSON: {exc}")
    if not isinstance(obj, dict):
        raise DereferenceError("invalid_response", "artifact must be a JSON object")
    return obj

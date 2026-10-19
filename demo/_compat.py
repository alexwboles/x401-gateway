"""Guarded imports: prefer the real ``x401`` / ``wallet`` packages, else the
``demo/_fallback`` reference implementations.

``_compat`` resolves each module to the real package when importable, and to the
fallback otherwise — per module, so a partial delivery still uses whatever is
real. As of 2026-10-19 the real ``wallet`` track AND the real ``x401`` track
(10/10 modules) are delivered; the adapters below smooth over the remaining
shape differences between the brief's documented API and the delivered code:

* ``codec.parse_header`` takes a headers mapping in real x401 (not a raw
  value); ``emit_header`` returns a ``(name, value)`` tuple. Use
  ``codec.decode_payload`` / ``codec.encode_payload`` directly instead.
* ``nonce.NonceCache(ttl=...)`` / ``issue()`` (no per-issue ttl).
* ``trust.TrustList.add_issuer(issuer_id, public_key_jwk)`` — JWK dicts, no
  key-id lookup; the merchant keeps a parallel key map for signature keys.
* ``oauth.issue_access_token`` / ``verify_access_token`` keyword differences.
* ``result.make_result`` keyword differences (``description`` vs
  ``error_description``).
* ``response.dereference`` takes a single ``allowed_prefix``.
* ``mandate`` uses the wallet-track claim shape
  (agent/merchant/action_category/amount_ceiling/not_before/not_after).

Introspection: REAL_MODULES / FALLBACK_MODULES / backend_summary().
"""

import base64
import binascii
import importlib
import inspect
import json

IMPORT_ERRORS: list[str] = []
REAL_MODULES: list[str] = []
FALLBACK_MODULES: list[str] = []


def _load(real_name: str, fallback_name: str):
    try:
        mod = importlib.import_module(real_name)
        REAL_MODULES.append(real_name)
        return mod
    except ImportError as exc:  # includes ModuleNotFoundError
        IMPORT_ERRORS.append(f"{real_name}: {exc}")
    mod = importlib.import_module(fallback_name)
    FALLBACK_MODULES.append(real_name)
    return mod


codec = _load("x401.codec", "demo._fallback.codec")
jws = _load("x401.jws", "demo._fallback.jws")
request = _load("x401.request", "demo._fallback.request")
response = _load("x401.response", "demo._fallback.response")
result = _load("x401.result", "demo._fallback.result")
nonce = _load("x401.nonce", "demo._fallback.nonce")
mandate = _load("x401.mandate", "demo._fallback.mandate")
oauth = _load("x401.oauth", "demo._fallback.oauth")
trust = _load("x401.trust", "demo._fallback.trust")
html = _load("x401.html", "demo._fallback.html")
wallet_service = _load("wallet.service", "demo._fallback.wallet_service")

WalletServer = wallet_service.WalletServer

MANDATE_TYPE = "x-x401ext-mandate/v1"
"""Scoped-mandate extension type (NOT standardized by x401 v0.2.0)."""


def using_fallback() -> bool:
    return bool(FALLBACK_MODULES)


def wallet_is_real() -> bool:
    """True when the delivered wallet track's service is in use."""
    return "wallet.service" not in FALLBACK_MODULES


def x401_is_real() -> bool:
    """True when the delivered x401 track's modules are in use."""
    return not any(m.startswith("x401.") for m in FALLBACK_MODULES)


def backend_summary() -> str:
    bits = []
    bits.append("real wallet" if wallet_is_real() else "fallback wallet")
    x401_real = [m for m in REAL_MODULES if m.startswith("x401.")]
    bits.append(f"real x401 ({len(x401_real)}/10 modules)"
                if x401_real else "fallback x401 (x401/ not delivered yet)")
    if FALLBACK_MODULES:
        bits.append("fallbacks: " + ", ".join(FALLBACK_MODULES))
    return "backend: " + "; ".join(bits)


# -- small crypto-agnostic helpers (no dependency on x401.*) -----------------

_B64U_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    if not isinstance(s, str) or not s or any(c not in _B64U_ALPHABET for c in s):
        raise ValueError("invalid strict base64url value")
    if len(s) % 4 == 1:
        raise ValueError("invalid base64url length")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"base64url decode failed: {exc}")


def decode_compact_unverified(token: str) -> tuple[dict, dict]:
    """Split a compact JWS and return (header, payload) WITHOUT verifying.

    Used only to read ``kid``/``iss`` for key lookup — the trust decision
    always uses the key resolved from the local trust list, never the claim.
    """
    try:
        h_b64, p_b64, _sig = token.split(".")
        header = json.loads(b64u_decode(h_b64))
        payload = json.loads(b64u_decode(p_b64))
    except Exception as exc:
        raise ValueError(f"malformed compact JWS: {exc}")
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("malformed compact JWS: header/payload must be objects")
    return header, payload


def mandate_error_code(exc: BaseException) -> str:
    """Normalize any mandate-verification exception to an x401 error token."""
    return getattr(exc, "code", "invalid_signature") or "invalid_signature"


def verify_mandate(token: str, key, *, now=None, expected_merchant=None,
                   tx_amount=None) -> dict:
    """Verify a mandate: signature, terms, time window, merchant, ceiling.

    Adapts to the real ``x401.mandate.verify_mandate`` signature
    ``(token, public_key, *, now, expected_merchant, tx_amount)``.
    """
    fn = mandate.verify_mandate
    params = inspect.signature(fn).parameters
    kwargs = {"now": now, "expected_merchant": expected_merchant,
              "tx_amount": tx_amount}
    kwargs = {k: v for k, v in kwargs.items() if k in params}
    try:
        return fn(token, key, **kwargs)
    except TypeError:
        pass
    for name in ("key", "public_key", "verifying_key", "trusted_keys"):
        if name in params:
            return fn(token, **{**kwargs, name: key})
    # Last resort: let Python raise the real, descriptive TypeError.
    return fn(token, key, **kwargs)


def key_from_jwk(jwk: dict):
    """Rebuild a public-key object from a JWK dict."""
    for attr in ("key_from_jwk_public", "public_key_from_jwk"):
        fn = getattr(jws, attr, None)
        if callable(fn):
            return fn(jwk)
    # Fallback-only path using cryptography directly.
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    kty = jwk.get("kty")
    if kty == "OKP" and jwk.get("crv") == "Ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(b64u_decode(jwk["x"]))
    if kty == "EC" and jwk.get("crv") == "P-256":
        point = b"\x04" + b64u_decode(jwk["x"]) + b64u_decode(jwk["y"])
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    raise ValueError(f"unsupported JWK kty={kty} crv={jwk.get('crv')}")


# -- mandate shape normalization -------------------------------------------
# Real x401.mandate uses {agent, merchant, action_category, amount_ceiling,
# not_before, not_after}; the brief documented {agent_id, merchant, action,
# ceiling, nbf, exp}. Normalize to one internal form.

def normalize_mandate_claims(claims: dict) -> dict:
    """Map either mandate claim shape to the internal canonical form."""
    ceiling = claims.get("amount_ceiling") or claims.get("ceiling") or {}
    value = ceiling.get("value")
    return {
        "type": claims.get("type"),
        "iss": claims.get("iss") or claims.get("issuer"),
        "agent_id": claims.get("agent") or claims.get("agent_id"),
        "merchant": claims.get("merchant"),
        "action": claims.get("action_category") or claims.get("action"),
        "ceiling": {
            "currency": ceiling.get("currency"),
            "value": str(value) if value is not None else None,
        },
        "not_before": claims.get("not_before", claims.get("nbf")),
        "not_after": claims.get("not_after", claims.get("exp")),
        "nonce": claims.get("nonce"),
        "request_id": claims.get("request_id"),
    }


def build_mandate(*, agent: str, merchant: str, action_category: str,
                  amount_ceiling: dict, not_before: int, not_after: int,
                  nonce: str, request_id: str | None = None,
                  issuer: str | None = None) -> dict:
    """Build unsigned mandate claims (real x401.mandate shape preferred)."""
    params = set(inspect.signature(mandate.build_mandate).parameters)
    if "action_category" in params:
        claims = mandate.build_mandate(
            agent=agent, merchant=merchant, action_category=action_category,
            amount_ceiling=amount_ceiling, not_before=not_before,
            not_after=not_after, nonce=nonce, request_id=request_id)
        if issuer:
            claims["iss"] = issuer
        return claims
    # Fallback (brief shape).
    return mandate.build_mandate(
        agent_id=agent, merchant=merchant, action=action_category,
        amount_ceiling=amount_ceiling, not_before=not_before,
        not_after=not_after, nonce=nonce, request_id=request_id,
        issuer=issuer)


def sign_mandate(claims: dict, private_key, kid: str | None = None) -> str:
    """JWS-sign mandate claims (real x401.mandate.sign_mandate preferred)."""
    params = set(inspect.signature(mandate.sign_mandate).parameters)
    if "kid" in params:
        return mandate.sign_mandate(claims, private_key, kid=kid)
    # Real x401.mandate.sign_mandate(mandate, private_key, alg="EdDSA"):
    # no kid support; the merchant resolves the key via the iss claim.
    return mandate.sign_mandate(claims, private_key)


# -- result / oauth / response adapters --------------------------------------

_RESULT_PARAMS = set(inspect.signature(result.make_result).parameters)


def make_result(error: str, description: str | None = None,
                request_id: str | None = None,
                error_uri: str | None = None) -> dict:
    """Build an x401 Error Object across real/fallback result signatures."""
    if "error_description" in _RESULT_PARAMS:  # fallback (brief shape)
        return result.make_result(error=error, error_description=description,
                                  error_uri=error_uri, request_id=request_id)
    return result.make_result(error, description=description,
                              error_uri=error_uri, request_id=request_id)


_OAUTH_ISSUE_PARAMS = set(inspect.signature(oauth.issue_access_token).parameters)
_OAUTH_VERIFY_PARAMS = set(inspect.signature(oauth.verify_access_token).parameters)


def issue_access_token(*, agent_id: str, verifier_id: str,
                       request_id: str | None, satisfied_requirements,
                       resource: str | None, method: str, signing_key,
                       key_id: str, ttl: int = 300) -> str:
    """Issue a Bearer JWT across real/fallback oauth signatures."""
    if "verifier_id" in _OAUTH_ISSUE_PARAMS:  # real x401.oauth
        return oauth.issue_access_token(
            agent_id=agent_id, verifier_id=verifier_id, request_id=request_id,
            satisfied_requirements=satisfied_requirements, resource=resource,
            method=method, signing_key=signing_key, key_id=key_id, ttl=ttl)
    return oauth.issue_access_token(  # fallback (brief shape)
        signing_key=signing_key, key_id=key_id, issuer=verifier_id,
        agent_id=agent_id, request_id=request_id,
        satisfied_requirements=satisfied_requirements, resource=resource,
        method=method, audience=verifier_id, scope="purchase", ttl=ttl)


def verify_access_token(token: str, key, *, audience: str | None = None) -> dict:
    """Verify a Bearer JWT across real/fallback oauth signatures."""
    if "expected_audience" in _OAUTH_VERIFY_PARAMS:  # real x401.oauth
        return oauth.verify_access_token(token, key,
                                         expected_audience=audience)
    return oauth.verify_access_token(token, key, audience=audience)


_DEREF_PARAMS = set(inspect.signature(response.dereference).parameters)


def dereference(uri: str, *, allowed_prefix: str, timeout: float = 5,
                max_bytes: int = 65536) -> dict:
    """SSRF-guarded by-reference fetch across real/fallback signatures."""
    if "allowed_prefix" in _DEREF_PARAMS:  # real x401.response
        return response.dereference(uri, allowed_prefix=allowed_prefix,
                                    timeout=timeout, max_bytes=max_bytes)
    return response.dereference(uri, allowed_prefixes=(allowed_prefix,),
                                timeout=timeout, max_bytes=max_bytes)


def add_trust_issuer(trust_list, *, issuer_id: str, public_key=None,
                     public_jwk: dict | None = None, key_id: str | None = None):
    """Add an issuer to a trust list across real/fallback trust signatures."""
    params = set(inspect.signature(trust_list.add_issuer).parameters)
    if "public_key_jwk" in params:  # real x401.trust: JWK dicts
        jwk = public_jwk or jws.jwk_public(public_key)
        trust_list.add_issuer(issuer_id, jwk)
    else:  # fallback (brief shape): key objects + key ids
        trust_list.add_issuer(issuer_id, public_key, key_id=key_id)


# -- uniform wallet handle ---------------------------------------------------
# The delivered wallet: WalletServer((host, port), data_dir) — an HTTPServer
# subclass; approve via POST /api/approve/<id> {"decision": "approve"}.
# The fallback wallet:  WalletServer(host, port).start(); bare POST approves.
# WalletHandle hides the difference.

class WalletHandle:
    def __init__(self, *, server, url, issuer_id, key_id, public_key,
                 public_jwk, close):
        self.server = server
        self.url = url
        self.issuer_id = issuer_id
        self.key_id = key_id
        self.public_key = public_key      # cryptography public key object
        self.public_jwk = public_jwk
        self._close = close

    def close(self):
        self._close()


def open_wallet(host: str = "127.0.0.1", port: int = 0,
                data_dir=None) -> WalletHandle:
    """Start a wallet server in a daemon thread; return a uniform handle."""
    if wallet_is_real():
        import threading
        server = wallet_service.WalletServer((host, port), data_dir=data_dir)
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval": 0.1}, daemon=True)
        thread.start()
        device = server.device
        actual_port = server.server_address[1]
        return WalletHandle(
            server=server,
            url=f"http://{host}:{actual_port}",
            issuer_id=f"x401-wallet:{device.kid}",
            key_id=device.kid,
            public_key=device.private_key.public_key(),
            public_jwk=device.public_jwk,
            close=lambda: (server.shutdown(), server.server_close()),
        )
    server = wallet_service.WalletServer(host=host, port=port).start()
    return WalletHandle(
        server=server,
        url=server.url,
        issuer_id=server.device_issuer_id,
        key_id=server.device_key_id,
        public_key=server.device_public_key,
        public_jwk=server.device_public_jwk,
        close=server.stop,
    )


def wallet_approve(handle: WalletHandle, approval_id: str) -> int:
    """Approve a wallet session; returns the HTTP status.

    Sends {"decision": "approve"} (required by the delivered wallet; the
    fallback wallet also accepts it).
    """
    import urllib.error
    import urllib.request
    data = json.dumps({"decision": "approve"}).encode("utf-8")
    req = urllib.request.Request(
        f"{handle.url}/api/approve/{approval_id}", data=data, method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


def wallet_status(handle: WalletHandle, approval_id: str) -> dict:
    """GET /api/status/<id> and return the decoded JSON."""
    import urllib.request
    with urllib.request.urlopen(f"{handle.url}/api/status/{approval_id}",
                                timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))

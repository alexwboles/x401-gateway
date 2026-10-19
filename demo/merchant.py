#!/usr/bin/env python3
"""Demo x401 merchant / verifier (stdlib http.server, x401 v0.2.0).

Routes:
    GET  /resource            no proof -> 401 + PROOF-REQUEST (signed JAR, fresh
                             nonce, short exp) + Cache-Control: no-store, with the
                             x401 HTML <data> embed mirror in the body.
    GET  /resource            with PROOF-RESPONSE -> mandate validation; 200
                             {"granted": true, ...} or 401 + PROOF-RESULT error.
    GET  /resource            with Authorization: Bearer -> access-token check.
    POST /oauth/token         token-exchange leg (fixed grant params); the subject
                             artifact is validated with the SAME proof-validation
                             rules as the direct retry, then a short-lived Bearer
                             JWT with the x401 metadata block is issued.
    GET  /.well-known/jwks.json  verifier public key (for JAR verifiability).

Trust: operator-owned local TrustList. The demo wires the wallet's device key as a
self-issued issuer — the differentiator vs. inheriting a curated registry.
"""

import argparse
import json
import secrets
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from demo import _compat as C

CLIENT_ID = "https://merchant.demo"
REQUEST_ID_BASE = "demo-purchase-v1"  # stable template; each challenge appends entropy
SATISFIED_REQUIREMENTS = ["urn:demo:x401:satisfaction:purchase:v1"]

DCQL = {
    "credentials": [
        {
            "id": "purchase_mandate",
            "format": "jwt_vc_json",
            "meta": {"type_values": ["x-x401ext-mandate/v1"]},
            "claims": [
                {"path": ["merchant"], "values": [CLIENT_ID]},
                {"path": ["action"], "values": ["purchase"]},
            ],
        }
    ]
}

ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


class MerchantConfig:
    """Runtime configuration for the demo merchant."""

    def __init__(self, *, trust, charge_amount: dict, token_ttl: int = 300,
                 challenge_ttl: int = 120, result_uri_prefix: str | None = None,
                 key_id: str = "merchant-key-1"):
        # Verifier keypair generated at startup (Ed25519; JARs use EdDSA).
        self.verifier_private_key, self.verifier_public_key = (
            C.jws.generate_ed25519_keypair())
        self.key_id = key_id
        self.trust = trust                      # x401.trust.TrustList
        # Parallel key-resolution map: issuer_id -> (kid, public key object).
        # (Delivered x401.trust stores JWK dicts and answers trust decisions;
        # the merchant keeps the live key objects for signature verification.)
        self.key_map: dict[str, tuple] = {}
        self.nonces = C.nonce.NonceCache(ttl=challenge_ttl)
        self.charge_amount = charge_amount      # {"currency","value"}
        self.token_ttl = token_ttl
        self.challenge_ttl = challenge_ttl
        self.result_uri_prefix = result_uri_prefix
        # Challenge binding for wallets that mint their own mandate nonce
        # (the delivered wallet does): single-use request ids.
        self.issued_request_ids: dict[str, float] = {}   # request_id -> expiry
        self.consumed_request_ids: set[str] = set()


def create_server(host: str, port: int, config: MerchantConfig) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), _Handler)
    server.config = config
    server.daemon_threads = True
    return server


class _Handler(BaseHTTPRequestHandler):
    server_version = "x401-demo-merchant/0.1"

    def log_message(self, *args):  # keep demo output clean
        pass

    @property
    def config(self) -> MerchantConfig:
        return self.server.config

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    # -- small send helpers ------------------------------------------------
    def _send_json(self, status: int, obj: dict, extra_headers: dict | None = None):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, status: int, html: str, extra_headers: dict | None = None):
        raw = html.encode("utf-8")
        self.send_response(status)
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    # -- routing -----------------------------------------------------------
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/resource":
            self._handle_resource()
        elif path == "/.well-known/jwks.json":
            self._send_json(200, {"keys": [
                {"kid": self.config.key_id,
                 **C.jws.jwk_public(self.config.verifier_public_key)}]})
        else:
            self._send_json(404, {"error": "not_found"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/oauth/token":
            self._handle_token_exchange()
        else:
            self._send_json(404, {"error": "not_found"})

    # -- /resource ---------------------------------------------------------
    def _handle_resource(self):
        authz = self.headers.get("Authorization", "")
        if authz.startswith("Bearer "):
            status, body, result_obj = self._validate_bearer(authz[7:].strip())
            self._finish(status, body, result_obj)
            return
        proof_response = self.headers.get("PROOF-RESPONSE")
        if proof_response:
            status, body, result_obj = self._validate_proof_response_header(
                proof_response)
            self._finish(status, body, result_obj)
            return
        self._send_challenge()

    def _finish(self, status: int, body: dict, result_obj: dict | None):
        if status == 200 or result_obj is None:
            self._send_json(status, body)
        else:
            self._send_json(status, body, extra_headers={
                "PROOF-RESULT": C.codec.encode_payload(result_obj),
                "Cache-Control": "no-store",
            })

    # -- challenge (401 + PROOF-REQUEST) -----------------------------------
    def _send_challenge(self):
        cfg = self.config
        now = time.time()
        nonce = cfg.nonces.issue()
        # Unique per-challenge request id: the delivered wallet echoes it into
        # the mandate and mints its own mandate nonce, so this is our replay
        # binding for that path (see _consume_binding).
        request_id = f"{REQUEST_ID_BASE}-{C.b64u_encode(secrets.token_bytes(6))}"
        cfg.issued_request_ids[request_id] = now + cfg.challenge_ttl
        for rid, exp in [i for i in cfg.issued_request_ids.items()
                         if i[1] <= now]:
            del cfg.issued_request_ids[rid]
        payload = C.request.build_proof_request(
            verifier_private_key=cfg.verifier_private_key,
            key_id=cfg.key_id,
            client_id=CLIENT_ID,
            dcql=DCQL,
            protocol="openid4vp-v1-signed",
            expected_origins=["https://merchant.demo"],
            oauth_token_endpoint=self.base_url + "/oauth/token",
            request_id=request_id,
            satisfied_requirements=SATISFIED_REQUIREMENTS,
            ttl=cfg.challenge_ttl,
            nonce=nonce,
            alg="EdDSA",
        )
        body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Proof required</title></head>
<body style="font-family:system-ui,sans-serif;max-width:640px;margin:2em auto">
<h1>Proof required (x401 v0.2.0)</h1>
<p>This demo merchant needs an identity proof before granting the resource.</p>
{C.html.embed_html(payload)}
<p>Agents: retry with a <code>PROOF-RESPONSE</code> header carrying the Result
Artifact. Header-blind clients: the challenge is mirrored in the
<code>&lt;data&gt;</code> element above (informational only — the header is
authoritative).</p>
</body></html>"""
        self._send_html(401, body, extra_headers={
            "PROOF-REQUEST": C.codec.encode_payload(payload),
            "Cache-Control": "no-store",
        })

    # -- proof validation (shared by direct retry + token exchange) ---------
    def _proof_error(self, code: str, description: str,
                     request_id: str = REQUEST_ID_BASE):
        result_obj = C.make_result(error=code, description=description,
                                   request_id=request_id)
        body = {"granted": False, "error": code,
                "error_description": description, "request_id": request_id}
        return 401, body, result_obj

    def _validate_proof_response_header(self, header_value: str):
        # Strict wire check first (comma-joined / multi-line values invalid).
        if "," in header_value or "\n" in header_value or "\r" in header_value:
            return self._proof_error("invalid_response",
                                     "PROOF-RESPONSE is not strict x401 wire format")
        try:
            obj = C.codec.decode_payload(header_value)
        except Exception:
            return self._proof_error("invalid_response",
                                     "PROOF-RESPONSE is not strict x401 wire format")
        request_id = obj.get("request_id") or REQUEST_ID_BASE
        try:
            parsed = C.response.parse_proof_response(obj)
        except Exception as exc:
            code = getattr(exc, "code", "invalid_response")
            return self._proof_error(code, str(exc), request_id)
        # Delivered x401.response returns a normalized {'form': ...} envelope;
        # the fallback returns the raw artifact — detect the form either way.
        form = parsed.get("form")
        if form is None:
            if "credential_result_uri" in parsed:
                form = "by_reference"
            elif (parsed.get("scheme") == "x401" and "access_token" in parsed):
                form = "token_object"
            else:
                form = "inline"
        # x401 Token Object alternative placement (Bearer inside PROOF-RESPONSE).
        if form == "token_object":
            return self._validate_bearer(parsed["access_token"])
        return self._validate_artifact(parsed, form)

    def _validate_artifact(self, parsed: dict, form: str):
        request_id = parsed.get("request_id") or REQUEST_ID_BASE
        if form == "by_reference":
            prefix = self.config.result_uri_prefix
            if not prefix:
                return self._proof_error(
                    "ssrf_blocked",
                    "by-reference artifacts are not enabled on this verifier",
                    request_id)
            try:
                fetched = C.dereference(parsed["credential_result_uri"],
                                        allowed_prefix=prefix)
                parsed = C.response.parse_proof_response(fetched)
                form = parsed.get("form") or "inline"
            except Exception as exc:
                code = getattr(exc, "code", "ssrf_blocked")
                return self._proof_error(code, str(exc), request_id)
            if form != "inline":
                return self._proof_error(
                    "invalid_response",
                    "dereferenced artifact must be an inline result artifact",
                    request_id)
        cred = parsed["credential_result"]
        # The delivered wallet sets credential_result.protocol to the mandate
        # type itself; accept it alongside the OpenID4VP protocol labels.
        if cred.get("protocol") not in ("openid4vp-v1-signed",
                                        "openid4vp-v1-unsigned",
                                        C.MANDATE_TYPE):
            return self._proof_error(
                "unsupported_protocol",
                f"unsupported credential protocol {cred.get('protocol')!r}",
                request_id)
        token = cred.get("data")
        if not isinstance(token, str):
            return self._proof_error("invalid_response",
                                     "credential_result.data must be a string",
                                     request_id)
        claims, code = self._validate_mandate(token)
        if code:
            return self._proof_error(code, _ERROR_DESCRIPTIONS.get(code, code),
                                     request_id)
        body = {
            "granted": True,
            "scheme": "x401",
            "version": "0.2.0",
            "request_id": request_id,
            "mandate": {
                "issuer": claims.get("iss"),
                "agent_id": claims.get("agent_id"),
                "merchant": claims.get("merchant"),
                "action": claims.get("action"),
                "ceiling": claims.get("ceiling"),
            },
            "charge": self.config.charge_amount,
        }
        return 200, body, None

    def _validate_mandate(self, token: str):
        """Returns (normalized_claims, None) on success or (None, error_code).

        Trust check against the operator-owned trust list, then
        ``x401.mandate.verify_mandate`` (signature, type, time window, merchant
        binding, amount ceiling), then single-use challenge binding (JAR nonce
        via NonceCache, or echoed request_id for wallets that mint their own
        mandate nonce).
        """
        try:
            header, unverified = C.decode_compact_unverified(token)
        except ValueError:
            return None, "invalid_signature"
        kid = header.get("kid")
        iss = unverified.get("iss")
        # Operator-owned trust first: unknown issuer -> untrusted_issuer.
        if not iss or not self.config.trust.is_trusted(iss):
            return None, "untrusted_issuer"
        entry = self.config.key_map.get(iss)
        key = None
        if entry is not None:
            entry_kid, candidate = entry
            if not kid or not entry_kid or kid == entry_kid:
                key = candidate
        if key is None:
            return None, "untrusted_issuer"
        try:
            mandate = C.verify_mandate(
                token, key,
                now=time.time(),
                expected_merchant=CLIENT_ID,
                tx_amount=self.config.charge_amount,
            )
        except Exception as exc:
            return None, C.mandate_error_code(exc)
        norm = C.normalize_mandate_claims(mandate)
        # Single-use binding: only a fully-validated proof burns it.
        binding_code = self._consume_binding(norm, time.time())
        if binding_code:
            return None, binding_code
        return norm, None

    def _consume_binding(self, norm: dict, now: float) -> str | None:
        """Consume the challenge binding; returns an error code or None."""
        nonce = norm.get("nonce")
        if nonce:
            try:
                self.config.nonces.consume(nonce)
                return None
            except Exception as exc:
                code = getattr(exc, "code", "unknown_nonce")
                if code != "unknown_nonce":
                    return code  # replayed_nonce / expired_challenge
                # else: wallet-minted nonce — fall through to request_id binding
        request_id = norm.get("request_id")
        exp = self.config.issued_request_ids.get(request_id)
        if exp is None:
            if request_id in self.config.consumed_request_ids:
                return "replayed_nonce"
            return "unknown_nonce"
        if now > exp:
            del self.config.issued_request_ids[request_id]
            return "expired_challenge"
        del self.config.issued_request_ids[request_id]
        self.config.consumed_request_ids.add(request_id)
        return None

    # -- bearer access tokens ----------------------------------------------
    def _validate_bearer(self, token: str):
        # The token's aud is the resource it was issued for (x401 OAuth
        # profile); bind it to this route.
        try:
            claims = C.verify_access_token(
                token, self.config.verifier_public_key,
                audience=self.base_url + "/resource")
        except Exception as exc:
            code = getattr(exc, "code", "invalid_token")
            return self._proof_error(code, str(exc))
        x401 = claims.get("x401", {})
        body = {
            "granted": True,
            "via": "oauth_token",
            "scheme": "x401",
            "version": "0.2.0",
            "request_id": x401.get("request_id"),
            "scope": claims.get("scope"),
            "charge": self.config.charge_amount,
        }
        return 200, body, None

    # -- token exchange ------------------------------------------------------
    def _handle_token_exchange(self):
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            length = 0
        form = urllib.parse.parse_qs(
            self.rfile.read(length).decode("utf-8", "replace") if length else "")
        f = {k: v[0] for k, v in form.items()}

        def token_error(code: str, description: str):
            result_obj = C.make_result(error=code, description=description,
                                       request_id=REQUEST_ID_BASE)
            self._send_json(400, {"error": code, "error_description": description},
                            extra_headers={
                                "PROOF-RESULT": C.codec.encode_payload(result_obj),
                                "Cache-Control": "no-store",
                            })

        if f.get("grant_type") != C.oauth.TOKEN_EXCHANGE_GRANT:
            token_error("invalid_request",
                        "grant_type must be "
                        f"{C.oauth.TOKEN_EXCHANGE_GRANT}")
            return
        if f.get("subject_token_type") != C.oauth.RESULT_ARTIFACT_TYPE:
            token_error("invalid_request",
                        "subject_token_type must be "
                        f"{C.oauth.RESULT_ARTIFACT_TYPE}")
            return
        subject_token = f.get("subject_token")
        if not subject_token:
            token_error("invalid_request", "missing subject_token")
            return
        try:
            parsed = C.response.parse_proof_response(
                C.codec.decode_payload(subject_token))
        except Exception as exc:
            token_error(getattr(exc, "code", "invalid_request"), str(exc))
            return
        form = parsed.get("form") or "inline"
        if form != "inline":
            token_error("invalid_request",
                        "token exchange requires an inline result artifact")
            return
        # Same proof-validation rules as the direct retry (consumes the nonce).
        status, body, _result_obj = self._validate_artifact(parsed, form)
        if status != 200:
            token_error(body["error"], body["error_description"])
            return
        access_token = C.issue_access_token(
            agent_id=body["mandate"]["agent_id"],
            verifier_id=CLIENT_ID,
            request_id=body["request_id"],
            satisfied_requirements=SATISFIED_REQUIREMENTS,
            resource=f.get("resource"),
            method="GET",
            signing_key=self.config.verifier_private_key,
            key_id=self.config.key_id,
            ttl=self.config.token_ttl,
        )
        _header, token_claims = C.decode_compact_unverified(access_token)
        self._send_json(200, {
            "access_token": access_token,
            "issued_token_type": ACCESS_TOKEN_TYPE,
            "token_type": "Bearer",
            "expires_in": self.config.token_ttl,
            "scope": "purchase",
            "x401": token_claims.get("x401", {}),
        })


_ERROR_DESCRIPTIONS = {
    "invalid_request": "mandate is not a well-formed scoped mandate",
    "invalid_signature": "mandate JWS is malformed",
    "tampered_mandate": "mandate signature does not verify — signed terms were altered",
    "expired_mandate": "mandate is outside its validity window",
    "wrong_binding": "mandate was issued for a different merchant",
    "mandate_exceeded": "charge exceeds the mandate's authorized ceiling",
    "untrusted_issuer": "mandate signer is not in the verifier's trust list",
    "unknown_nonce": "challenge nonce was not issued by this verifier",
    "replayed_nonce": "challenge nonce has already been used",
    "expired_challenge": "challenge expired before the proof arrived",
}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Demo x401 merchant / verifier")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8072)
    ap.add_argument("--charge-amount", default="49.99",
                    help="demo charge, e.g. 49.99")
    ap.add_argument("--charge-currency", default="USD")
    ap.add_argument("--token-ttl", type=int, default=300)
    ap.add_argument("--challenge-ttl", type=int, default=120)
    ap.add_argument("--trust-issuer", default="did:web:localhost-wallet",
                    help="issuer id to trust (operator-owned local trust)")
    ap.add_argument("--trust-kid", default=None)
    ap.add_argument("--trust-jwk", default=None,
                    help="trusted device public key as JWK JSON "
                         "(operator adds the wallet's device key here)")
    args = ap.parse_args(argv)

    trust = C.trust.TrustList()
    key_map: dict[str, tuple] = {}
    if args.trust_jwk:
        jwk = json.loads(args.trust_jwk)
        issuer_id = args.trust_issuer or "did:web:localhost-wallet"
        kid = args.trust_kid or jwk.get("kid")
        C.add_trust_issuer(trust, issuer_id=issuer_id, public_jwk=jwk,
                           key_id=kid)
        key_map[issuer_id] = (kid, C.key_from_jwk(jwk))
        print(f"trust: {issuer_id} (kid={kid})")
    else:
        print("trust: WARNING — no --trust-jwk given; no issuer is trusted "
              "(all proofs will fail with untrusted_issuer)")

    config = MerchantConfig(
        trust=trust,
        charge_amount={"currency": args.charge_currency,
                       "value": args.charge_amount},
        token_ttl=args.token_ttl,
        challenge_ttl=args.challenge_ttl,
    )
    config.key_map.update(key_map)
    server = create_server(args.host, args.port, config)
    host, port = server.server_address
    print(f"x401 demo merchant on http://{host}:{port} "
          f"({C.backend_summary()})")
    print(f"  charge: {args.charge_currency} {args.charge_amount}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

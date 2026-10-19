"""Fallback ``wallet.service`` — self-hosted identity wallet (demo).

The differentiator: no commercial provider in the loop. The wallet holds the
holder's device key, shows the requested claims AND the transaction terms in plain
language, and — on the person's approval — signs a scoped mandate
(``x-x401ext-mandate/v1``) binding verified identity to the exact terms authorized.
The device key is the self-hosted stand-in for Proof's biometric + hardware key
(the production upgrade path is WebAuthn/passkey-bound signing).

HTTP surface (all on 127.0.0.1):
    POST /api/requests            {"proof_request", "terms"} -> approval session
    GET  /api/status/<id>         poll: pending | approved | denied | expired
    POST /api/approve/<id>        approve (human page + programmatic/auto-approve)
    POST /api/deny/<id>           deny
    GET  /approve/<id>            human approval page (terms in plain language)
    GET  /                       service info + device JWK (for trust wiring)
    GET  /.well-known/jwks.json   device key set
"""

import json
import secrets
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import jws as _jws
from . import mandate as _mandate
from .codec import b64u_decode, b64u_encode, parse_header

__all__ = ["WalletError", "WalletServer"]


class WalletError(Exception):
    """Wallet request failure; ``status`` is the HTTP status to return."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _utc(ts: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


class _Handler(BaseHTTPRequestHandler):
    server_version = "x401-demo-wallet/0.1"

    def log_message(self, *args):  # keep demo output clean
        pass

    @property
    def wallet(self) -> "WalletServer":
        return self.server.wallet

    # -- helpers ---------------------------------------------------------
    def _send_json(self, status: int, obj: dict):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, status: int, html: str):
        raw = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length else b""
        try:
            return json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            raise WalletError(400, "request body must be JSON")

    def _wants_json(self) -> bool:
        ctype = self.headers.get("Content-Type", "")
        accept = self.headers.get("Accept", "")
        return "application/json" in ctype or "application/json" in accept

    # -- routing ---------------------------------------------------------
    def do_GET(self):
        parts = urllib.parse.urlparse(self.path).path.strip("/").split("/")
        try:
            if parts == [""]:
                w = self.wallet
                self._send_json(200, {
                    "service": "x401-demo-wallet",
                    "x401": "0.2.0",
                    "device_issuer": w.device_issuer_id,
                    "device_key_id": w.device_key_id,
                    "device_jwk": w.device_public_jwk,
                    "note": "self-hosted identity wallet: no commercial provider involved",
                })
            elif parts == [".well-known", "jwks.json"]:
                self._send_json(200, {"keys": [self.wallet.device_public_jwk]})
            elif parts[0] == "approve" and len(parts) == 2:
                self._send_html(200, self.wallet.approval_page(parts[1]))
            elif parts[:2] == ["api", "status"] and len(parts) == 3:
                self._send_json(200, self.wallet.status(parts[2]))
            else:
                self._send_json(404, {"error": "not_found"})
        except WalletError as exc:
            self._send_json(exc.status, {"error": str(exc)})

    def do_POST(self):
        parts = urllib.parse.urlparse(self.path).path.strip("/").split("/")
        try:
            if parts == ["api", "requests"]:
                self._send_json(200, self.wallet.create_request(self._read_json()))
            elif parts[:2] == ["api", "approve"] and len(parts) == 3:
                # Accept {"decision": "approve"|"deny"} (delivered-wallet shape);
                # a bare POST to /api/approve/<id> approves, /api/deny/<id> denies.
                decision = self._posted_decision() or "approve"
                rec = self._apply_decision(parts[2], decision)
                self._approval_result(parts[2], rec,
                                      approved=(decision == "approve"))
            elif parts[:2] == ["api", "deny"] and len(parts) == 3:
                decision = self._posted_decision() or "deny"
                rec = self._apply_decision(parts[2], decision)
                self._approval_result(parts[2], rec,
                                      approved=(decision == "approve"))
            else:
                self._send_json(404, {"error": "not_found"})
        except WalletError as exc:
            self._send_json(exc.status, {"error": str(exc)})

    def _posted_decision(self) -> str | None:
        """Optional JSON body {"decision": "approve"|"deny"}; None if absent."""
        ctype = self.headers.get("Content-Type", "")
        if "application/json" not in ctype:
            return None
        try:
            body = self._read_json()
        except WalletError:
            return None
        decision = body.get("decision") if isinstance(body, dict) else None
        return decision if decision in ("approve", "deny") else None

    def _apply_decision(self, approval_id: str, decision: str) -> dict:
        if decision == "deny":
            return self.wallet.deny(approval_id)
        return self.wallet.approve(approval_id)

    def _approval_result(self, approval_id: str, rec: dict, *, approved: bool):
        if self._wants_json():
            self._send_json(200, {"approval_id": approval_id,
                                 "status": rec["status"]})
            return
        verb = "approved" if approved else "denied"
        self._send_html(200,
                        f"<!doctype html><html><head><meta charset='utf-8'>"
                        f"<title>Mandate {verb}</title></head><body>"
                        f"<h1>Mandate {verb}</h1>"
                        f"<p>Approval <code>{approval_id}</code> was {verb}."
                        f" You can close this page; the agent has been notified.</p>"
                        f"</body></html>")


class WalletServer:
    """Self-hosted identity wallet serving on 127.0.0.1."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 approval_ttl: int = 600, mandate_ttl: int = 600):
        self.host = host
        self._port = port
        self.approval_ttl = approval_ttl
        self.mandate_ttl = mandate_ttl
        # Device key: the self-hosted stand-in for biometric + hardware-backed key.
        self.device_private_key, self.device_public_key = (
            _jws.generate_ed25519_keypair())
        self.device_key_id = "device-1"
        self.device_issuer_id = "did:web:localhost-wallet"  # self-issued issuer
        self.device_public_jwk = {"kid": self.device_key_id,
                                  **_jws.jwk_public(self.device_public_key)}
        self._approvals: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- lifecycle -------------------------------------------------------
    def start(self) -> "WalletServer":
        self._server = ThreadingHTTPServer((self.host, self._port), _Handler)
        self._server.wallet = self
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.1},
            daemon=True,
        )
        self._thread.start()
        return self

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def __enter__(self) -> "WalletServer":
        return self.start()

    def __exit__(self, *args):
        self.stop()

    @property
    def port(self) -> int:
        if self._server:
            return self._server.server_address[1]
        return self._port

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    # -- approval sessions -----------------------------------------------
    @staticmethod
    def _summarize_request(proof_request) -> tuple[dict, dict]:
        """Return (payload dict, {request_id, client_id, nonce})."""
        try:
            if isinstance(proof_request, str):
                payload = parse_header(proof_request)
            else:
                payload = dict(proof_request)
            data = payload["credential_requirements"]["digital"]["requests"][0]["data"]
            if "request" in data:  # signed mode: JAR JWT
                _h, p_b64, _s = data["request"].split(".")
                jar = json.loads(b64u_decode(p_b64))
            else:  # unsigned mode: raw params
                jar = data
            summary = {
                "request_id": payload.get("request_id"),
                "client_id": jar.get("client_id"),
                "nonce": jar.get("nonce"),
            }
        except Exception as exc:
            raise WalletError(400, f"unreadable proof_request: {exc}")
        if not summary["nonce"]:
            raise WalletError(400, "proof_request carries no challenge nonce")
        return payload, summary

    @staticmethod
    def _check_terms(terms) -> dict:
        if not isinstance(terms, dict):
            raise WalletError(400, "terms must be an object")
        for field in ("merchant", "amount", "ceiling"):
            if field not in terms:
                raise WalletError(400, f"terms.{field} is required")
        for field in ("amount", "ceiling"):
            amt = terms[field]
            if (not isinstance(amt, dict) or "currency" not in amt
                    or "value" not in amt):
                raise WalletError(400, f"terms.{field} must be {{currency, value}}")
        terms.setdefault("action", "purchase")
        terms.setdefault("agent_id", "unknown-agent")
        return terms

    def create_request(self, body: dict) -> dict:
        proof_request = body.get("proof_request")
        if proof_request is None:
            raise WalletError(400, "proof_request is required")
        terms = self._check_terms(body.get("terms"))
        payload, summary = self._summarize_request(proof_request)
        approval_id = b64u_encode(secrets.token_bytes(12))
        now = int(time.time())
        with self._lock:
            self._approvals[approval_id] = {
                "approval_id": approval_id,
                "proof_request": payload,
                "terms": terms,
                "summary": summary,
                "status": "pending",
                "created_at": now,
                "expires_at": now + self.approval_ttl,
                "proof_response": None,
            }
        return {
            "approval_id": approval_id,
            "approval_url": f"{self.url}/approve/{approval_id}",
            "status": "pending",
            "expires_at": _utc(now + self.approval_ttl),
            "verifier": summary["client_id"],
        }

    def _get(self, approval_id: str) -> dict:
        with self._lock:
            rec = self._approvals.get(approval_id)
        if rec is None:
            raise WalletError(404, "unknown approval_id")
        if rec["status"] == "pending" and time.time() > rec["expires_at"]:
            with self._lock:
                rec["status"] = "expired"
        return rec

    def approve(self, approval_id: str) -> dict:
        rec = self._get(approval_id)
        with self._lock:
            if rec["status"] != "pending":
                raise WalletError(409, f"approval is {rec['status']}, not pending")
            terms = rec["terms"]
            summary = rec["summary"]
            now = int(time.time())
            # The person approves EXACTLY these terms; the device key signs them.
            # Any later alteration (amount, merchant, ...) invalidates the signature.
            claims = _mandate.build_mandate(
                agent_id=terms["agent_id"],
                merchant=terms["merchant"],
                action=terms["action"],
                amount_ceiling=terms["ceiling"],
                nonce=summary["nonce"],
                request_id=summary["request_id"],
                issuer=self.device_issuer_id,
                not_after=now + self.mandate_ttl,
            )
            token = _mandate.sign_mandate(
                claims, self.device_private_key, key_id=self.device_key_id)
            rec["proof_response"] = {
                "request_id": summary["request_id"],
                "credential_result": {
                    "protocol": "openid4vp-v1-signed",
                    "data": token,
                },
            }
            rec["status"] = "approved"
        return rec

    def deny(self, approval_id: str) -> dict:
        rec = self._get(approval_id)
        with self._lock:
            if rec["status"] != "pending":
                raise WalletError(409, f"approval is {rec['status']}, not pending")
            rec["status"] = "denied"
        return rec

    def status(self, approval_id: str) -> dict:
        rec = self._get(approval_id)
        out = {
            "approval_id": approval_id,
            "status": rec["status"],
            "expires_at": _utc(rec["expires_at"]),
        }
        if rec["status"] == "approved":
            out["proof_response"] = rec["proof_response"]
        return out

    def approval_page(self, approval_id: str) -> str:
        rec = self._get(approval_id)
        terms = rec["terms"]
        summary = rec["summary"]
        amount = terms["amount"]
        ceiling = terms["ceiling"]
        rows = (
            ("Merchant", terms["merchant"]),
            ("Action", terms["action"]),
            ("Charge amount", f"{amount['currency']} {amount['value']}"),
            ("Authorized ceiling", f"{ceiling['currency']} {ceiling['value']}"),
            ("Agent", terms["agent_id"]),
            ("Verifier", summary["client_id"] or "unknown"),
            ("Expires", _utc(rec["expires_at"])),
        )
        rows_html = "".join(
            f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows)
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Approve mandate — x401 demo wallet</title>
<style>body{{font-family:system-ui,sans-serif;max-width:640px;margin:2em auto;
padding:0 1em;color:#1a1a1a}}table{{border-collapse:collapse;width:100%;
margin:1em 0}}th,td{{text-align:left;padding:.5em;border-bottom:1px solid #ddd}}
th{{width:40%;color:#555}}.btn{{font-size:1.1em;padding:.6em 1.6em;margin-right:1em;
cursor:pointer;border:1px solid #222;background:#fff}}
.approve{{background:#1a1a1a;color:#fff}}.warn{{background:#fff8e1;border:1px solid
#e0c36a;padding:.8em;margin:1em 0}}</style></head>
<body>
<h1>Approve this mandate?</h1>
<p>Your agent asks you to authorize the following transaction. Approving signs
these <strong>exact terms</strong> with this device's key — if the agent later
alters the amount, merchant, or anything else, the signature will not verify.</p>
<table>{rows_html}</table>
<div class="warn">Status: <strong>{rec["status"]}</strong>. This demo wallet signs
with its device key, the self-hosted stand-in for a biometric + hardware key.</div>
<form method="post" action="/api/approve/{approval_id}" style="display:inline">
<button class="btn approve" type="submit">Approve &amp; sign</button></form>
<form method="post" action="/api/deny/{approval_id}" style="display:inline">
<button class="btn" type="submit">Deny</button></form>
</body></html>"""

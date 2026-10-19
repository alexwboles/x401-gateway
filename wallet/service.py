#!/usr/bin/env python3
"""x401 self-hosted wallet service (holder side).

Stdlib only (``http.server`` / ``urllib``) -- no web framework.

Run:
    cd ~/workspace/x401-gateway && python3 -m wallet.service

Environment:
    X401_WALLET_DIR   data directory (default: ./wallet-data)
    X401_WALLET_HOST  bind host (default: 127.0.0.1)
    X401_WALLET_PORT  port (default: 8765)

Flow (RFC 8628 device-grant shape):
    1. The agent POSTs the x401 PROOF-REQUEST payload + human-readable terms
       to /api/requests and gets an approval_id + approval_url (+ QR).
    2. The person opens the approval URL (or scans the QR) on their own
       device, reviews the exact terms, and approves/denies.
    3. On approval the wallet signs a scoped mandate
       (type "x-x401ext-mandate/v1") with the device key and stores the
       credential_result; the agent polls /api/status/<id> for it.
"""

from __future__ import annotations

import html
import json
import logging
import os
import secrets
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from wallet import _compat as x
from wallet.device import DeviceKey
from wallet.qr import HAVE_QR, qr_to_svg
from wallet.store import CredentialStore, seed_demo_credential

log = logging.getLogger("x401.wallet")

DATA_DIR = Path(os.environ.get("X401_WALLET_DIR", "wallet-data"))
HOST = os.environ.get("X401_WALLET_HOST", "127.0.0.1")
PORT = int(os.environ.get("X401_WALLET_PORT", "8765"))

DEFAULT_APPROVAL_TTL = 600      # seconds a pending approval stays valid
DEFAULT_MANDATE_WINDOW = 3600  # seconds the signed mandate stays valid


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _fmt_time(ts: float) -> str:
    dt = datetime.fromtimestamp(ts).astimezone()
    return dt.strftime("%b %d, %Y, %I:%M %p %Z").replace(" 0", " ")


def _fmt_amount(amount_ceiling: dict) -> str:
    cur = amount_ceiling.get("currency", "")
    val = amount_ceiling.get("value", "0")
    return f"{cur} {val}".strip()


def _client_id_hint(proof_request: dict) -> str:
    """Best-effort extraction of a verifier client_id for display."""
    try:
        reqs = (proof_request.get("credential_requirements", {})
                .get("digital", {}).get("requests", []))
        for r in reqs:
            data = r.get("data", {})
            if isinstance(data, dict):
                if data.get("client_id"):
                    return str(data["client_id"])
                # unsigned mode: raw params may carry client_id
                inner = data.get("request")
                if isinstance(inner, dict) and inner.get("client_id"):
                    return str(inner["client_id"])
    except Exception:
        pass
    for key in ("client_id", "verifier_id", "verifier"):
        if proof_request.get(key):
            return str(proof_request[key])
    return ""


def _normalize_terms(proof_request: dict, terms: dict | None) -> dict:
    """Merge explicit terms over defaults drawn from the proof request."""
    t = dict(terms or {})
    pr = proof_request or {}
    t.setdefault("merchant_display",
                 pr.get("merchant_display") or pr.get("verifier_display")
                 or _client_id_hint(pr) or "Unknown merchant")
    t.setdefault("action_category", pr.get("action_category") or "general")
    raw_ac = t.get("amount_ceiling") or pr.get("amount_ceiling") or {}
    if not isinstance(raw_ac, dict):
        raw_ac = {"value": raw_ac}
    t["amount_ceiling"] = {
        "currency": str(raw_ac.get("currency") or "USD"),
        "value": str(raw_ac.get("value") or "0"),
    }
    try:
        t["expires_in"] = max(1, int(t.get("expires_in") or DEFAULT_APPROVAL_TTL))
    except (TypeError, ValueError):
        t["expires_in"] = DEFAULT_APPROVAL_TTL
    try:
        t["window_seconds"] = max(60, int(t.get("window_seconds")
                                         or DEFAULT_MANDATE_WINDOW))
    except (TypeError, ValueError):
        t["window_seconds"] = DEFAULT_MANDATE_WINDOW
    t.setdefault("agent", pr.get("agent_id") or pr.get("agent") or "agent:unknown")
    t["client_id"] = t.get("client_id") or _client_id_hint(pr)
    return t


def _relay_return_uri(uri: str, credential_result: dict) -> None:
    """Best-effort POST of the credential result to the relay's return_uri."""
    try:
        body = json.dumps(credential_result).encode("utf-8")
        req = urllib.request.Request(
            uri, data=body,
            headers={"Content-Type": "application/json",
                     "User-Agent": "x401-wallet/0.1.0"},
            method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            log.info("return_uri relay -> %s (%s)", uri, resp.status)
    except Exception as exc:  # best-effort: never fail the approval
        log.warning("return_uri relay to %s failed (ignored): %s", uri, exc)


# ---------------------------------------------------------------------------
# server
# ---------------------------------------------------------------------------

class WalletServer(ThreadingHTTPServer):
    """Threading HTTP server holding the wallet state."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, data_dir: str | Path | None = None):
        self.data_dir = Path(data_dir) if data_dir else DATA_DIR
        self.lock = threading.RLock()
        self.store = CredentialStore(self.data_dir / "credentials.json")
        self.device = DeviceKey(self.data_dir)
        self.approvals: dict[str, dict] = {}
        self._qr_cache: dict[str, str] = {}
        super().__init__(server_address, WalletHandler)
        log.info("wallet data dir: %s (device kid=%s, x401 fallbacks=%s)",
                 self.data_dir, self.device.kid, x.X401_FALLBACKS or "none")

    # -- approvals ------------------------------------------------------
    def new_approval(self, proof_request: dict, terms: dict | None) -> dict:
        """Create a pending approval; returns the record (with mandate claims
        fully determined so the person sees exactly what gets signed)."""
        parsed = x.parse_proof_request(proof_request)
        norm = _normalize_terms(parsed, terms)
        now = time.time()
        aid = "appr-" + secrets.token_urlsafe(12)
        # The SIWE property: the mandate claims are fixed NOW, before the
        # person sees them.  Approval signs exactly these bytes -- nothing
        # is added or altered afterwards (not even the nonce).
        mandate_claims = x.build_mandate(
            agent=norm["agent"],
            merchant=norm["merchant_display"],
            action_category=norm["action_category"],
            amount_ceiling=norm["amount_ceiling"],
            not_before=int(now),
            not_after=int(now + norm["window_seconds"]),
            nonce=secrets.token_urlsafe(16),
            issuer=f"x401-wallet:{self.device.kid}",
            request_id=parsed.get("request_id"),
        )
        record = {
            "id": aid,
            "proof_request": parsed,
            "terms": norm,
            "request_id": parsed.get("request_id"),
            "mandate_claims": mandate_claims,
            "canonical_terms": x.canonical(mandate_claims).decode("utf-8"),
            "created_at": now,
            "expires_at": now + norm["expires_in"],
            "status": "pending",
            "decided_at": None,
            "credential_result": None,
        }
        with self.lock:
            self.approvals[aid] = record
        return record

    def get_approval(self, aid: str) -> dict | None:
        with self.lock:
            return self.approvals.get(aid)

    def _expire_if_needed(self, record: dict) -> None:
        if record["status"] == "pending" and time.time() > record["expires_at"]:
            record["status"] = "expired"

    def decide(self, aid: str, decision: str) -> tuple[int, dict]:
        """Apply an approve/deny decision.  Returns (http_status, payload)."""
        with self.lock:
            record = self.approvals.get(aid)
            if record is None:
                return 404, {"error": "unknown_approval"}
            self._expire_if_needed(record)
            if record["status"] == "expired":
                return 410, {"error": "approval_expired",
                             "error_description": "This approval request has expired."}
            if record["status"] != "pending":
                return 409, {"error": "already_decided",
                             "status": record["status"]}
            if decision not in ("approve", "deny"):
                return 400, {"error": "bad_decision",
                             "error_description": 'decision must be "approve" or "deny"'}
            now = time.time()
            if decision == "deny":
                record["status"] = "denied"
                record["decided_at"] = now
                log.info("approval %s denied", aid)
                return 200, {"status": "denied", "approval_id": aid}
            # approve: sign EXACTLY the mandate claims shown to the person
            if now > record["mandate_claims"]["not_after"]:
                record["status"] = "expired"
                return 410, {"error": "approval_expired",
                             "error_description": "The mandate window lapsed before approval."}
            token = x.sign_mandate(record["mandate_claims"],
                                   self.device.private_key,
                                   kid=self.device.kid)
            record["credential_result"] = {"protocol": x.MANDATE_TYPE,
                                          "data": token}
            record["status"] = "approved"
            record["decided_at"] = now
            log.info("approval %s approved; mandate signed (kid=%s)",
                     aid, self.device.kid)
            result = dict(record["credential_result"])
            # return_uri relay (x401 spec pattern): fire and forget
            uri = record["proof_request"].get("return_uri")
            if isinstance(uri, str) and uri.startswith("https://"):
                threading.Thread(target=_relay_return_uri,
                                 args=(uri, result), daemon=True).start()
            elif uri:
                log.warning("ignoring non-https return_uri: %r", uri)
            return 200, {"status": "approved", "approval_id": aid}

    def status_payload(self, record: dict) -> dict:
        with self.lock:
            self._expire_if_needed(record)
            payload = {
                "status": record["status"],
                "approval_id": record["id"],
                "merchant_display": record["terms"]["merchant_display"],
                "expires_at": record["expires_at"],
            }
            if record["status"] == "approved":
                payload["proof_response"] = {
                    "request_id": record.get("request_id") or record["id"],
                    "credential_result": record["credential_result"],
                }
            return payload

    def qr_svg_for_url(self, url: str) -> str | None:
        if not HAVE_QR:
            return None
        with self.lock:
            svg = self._qr_cache.get(url)
            if svg is None:
                svg = qr_to_svg(url)
                self._qr_cache[url] = svg
            return svg


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class WalletHandler(BaseHTTPRequestHandler):
    server_version = "x401-wallet/0.1.0"
    protocol_version = "HTTP/1.1"

    # -- plumbing -------------------------------------------------------
    def log_message(self, fmt, *args):  # keep stdlib chatter in logging
        log.info("%s %s", self.address_string(), fmt % args)

    def _path_parts(self) -> list[str]:
        path = urllib.parse.urlsplit(self.path).path
        return [p for p in path.strip("/").split("/") if p]

    def _base_url(self) -> str:
        scheme = self.headers.get("X-Forwarded-Proto", "http")
        host = self.headers.get("Host")
        if not host:
            host = f"127.0.0.1:{self.server.server_address[1]}"
        return f"{scheme}://{host}"

    def _approval_url(self, aid: str) -> str:
        return f"{self._base_url()}/approve/{urllib.parse.quote(aid)}"

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > 1_000_000:
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return "INVALID"

    def _send(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, obj: dict):
        self._send(status, json.dumps(obj, indent=2).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _send_html(self, status: int, doc: str):
        self._send(status, doc.encode("utf-8"), "text/html; charset=utf-8")

    def _send_svg(self, status: int, svg: str):
        self._send(status, svg.encode("utf-8"), "image/svg+xml")

    # -- routing --------------------------------------------------------
    def do_GET(self):
        parts = self._path_parts()
        srv: WalletServer = self.server
        if parts == []:
            return self._send_html(200, home_page(srv))
        if parts[0] == "approve" and len(parts) == 2:
            return self._approve_page(parts[1])
        if parts[0] == "qr" and len(parts) == 2:
            return self._qr(parts[1])
        if parts[:2] == ["api", "status"] and len(parts) == 3:
            record = srv.get_approval(urllib.parse.unquote(parts[2]))
            if record is None:
                return self._send_json(404, {"error": "unknown_approval"})
            return self._send_json(200, srv.status_payload(record))
        return self._send_html(404, error_page(404, "Not found",
                                              "This wallet has no such page."))

    def do_POST(self):
        parts = self._path_parts()
        srv: WalletServer = self.server
        if parts == ["api", "requests"]:
            return self._api_requests()
        if parts[:2] == ["api", "approve"] and len(parts) == 3:
            body = self._read_json()
            if body == "INVALID" or not isinstance(body, dict):
                return self._send_json(400, {"error": "bad_request",
                                             "error_description": "Expected a JSON object body."})
            decision = (body or {}).get("decision")
            status, payload = srv.decide(urllib.parse.unquote(parts[2]), decision)
            return self._send_json(status, payload)
        if parts == ["api", "credentials", "seed"]:
            with srv.lock:
                cred = seed_demo_credential(srv.store)
            self.send_response(303)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if parts[:2] == ["api", "credentials"] and len(parts) == 4 and parts[3] == "delete":
            ok = srv.store.delete_credential(urllib.parse.unquote(parts[2]))
            self.send_response(303 if ok else 404)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        return self._send_json(404, {"error": "unknown_endpoint"})

    # -- endpoint implementations ---------------------------------------
    def _api_requests(self):
        srv: WalletServer = self.server
        body = self._read_json()
        if body == "INVALID" or not isinstance(body, dict):
            return self._send_json(400, {"error": "bad_request",
                                        "error_description": "Expected a JSON object body."})
        if not isinstance(body.get("proof_request"), dict):
            return self._send_json(400, {"error": "bad_request",
                                        "error_description": '"proof_request" must be a JSON object.'})
        try:
            record = srv.new_approval(body["proof_request"], body.get("terms"))
        except ValueError as exc:
            return self._send_json(400, {"error": "bad_proof_request",
                                        "error_description": str(exc)})
        url = self._approval_url(record["id"])
        log.info("new approval %s for %s (%s)",
                 record["id"], record["terms"]["merchant_display"],
                 _fmt_amount(record["terms"]["amount_ceiling"]))
        return self._send_json(200, {
            "approval_id": record["id"],
            "approval_url": url,
            "qr_text": url,  # scan / encode as QR on the agent side
            "expires_at": record["expires_at"],
            "status": "pending",
        })

    def _approve_page(self, aid: str):
        srv: WalletServer = self.server
        record = srv.get_approval(urllib.parse.unquote(aid))
        if record is None:
            return self._send_html(404, error_page(404, "Unknown approval",
                                                  "No approval request with this id exists on this wallet."))
        url = self._approval_url(record["id"])
        svg = srv.qr_svg_for_url(url)
        return self._send_html(200, approve_page(srv, record, url, svg))

    def _qr(self, aid: str):
        srv: WalletServer = self.server
        record = srv.get_approval(urllib.parse.unquote(aid))
        if record is None:
            return self._send_json(404, {"error": "unknown_approval"})
        url = self._approval_url(record["id"])
        svg = srv.qr_svg_for_url(url)
        if svg is None:
            return self._send_json(501, {"error": "qr_unavailable",
                                        "approval_url": url,
                                        "hint": "QR library unavailable; use approval_url as text."})
        return self._send_svg(200, svg)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

CSS = """
:root{
  --paper:#F6F4EE; --card:#FFFFFF; --ink:#1A1915; --muted:#6F6A5D;
  --line:#E3DED0; --accent:#0B5B3E; --accent-deep:#073E2A;
  --danger:#A4261C; --warn:#8A5A00; --code:#F1EEE4;
}
*{box-sizing:border-box;border-radius:0 !important}
body{margin:0;background:var(--paper);color:var(--ink);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,"Helvetica Neue",Arial,sans-serif;
  -webkit-font-smoothing:antialiased;line-height:1.5}
.wrap{max-width:780px;margin:0 auto;padding:36px 20px 72px}
.topbar{display:flex;justify-content:space-between;align-items:baseline;
  border-bottom:2px solid var(--ink);padding-bottom:12px;margin-bottom:28px}
.brand{font-weight:800;letter-spacing:.14em;font-size:13px}
.brand .x{color:var(--accent)}
.device{font-size:12px;color:var(--muted);font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.card{background:var(--card);border:1px solid var(--line);
  box-shadow:0 1px 2px rgba(26,25,21,.05),0 10px 28px rgba(26,25,21,.07);
  padding:32px;margin-bottom:20px}
.eyebrow{font-size:11px;letter-spacing:.16em;color:var(--accent);font-weight:700;margin-bottom:10px}
h1{font-size:26px;line-height:1.25;margin:0 0 6px;font-weight:700;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:14px;margin:0 0 24px}
.rows{border-top:1px solid var(--line)}
.row{display:flex;justify-content:space-between;gap:16px;padding:13px 0;border-bottom:1px solid var(--line)}
.row .k{font-size:11px;letter-spacing:.1em;color:var(--muted);font-weight:700;padding-top:3px;white-space:nowrap}
.row .v{text-align:right;font-size:14px;overflow-wrap:anywhere}
.row .v.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
.amount{font-family:Georgia,"Times New Roman",serif;font-size:40px;font-weight:700;
  letter-spacing:-.01em;margin:6px 0 2px}
.amount small{font-size:16px;font-family:inherit;color:var(--muted);font-weight:400}
details.terms{margin-top:22px;border:1px solid var(--line);background:var(--code)}
details.terms summary{cursor:pointer;padding:12px 16px;font-size:13px;font-weight:700;list-style:none}
details.terms summary::-webkit-details-marker{display:none}
details.terms summary:before{content:"▸ ";color:var(--accent)}
details.terms[open] summary:before{content:"▾ "}
details.terms pre{margin:0;padding:16px;border-top:1px solid var(--line);
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
  white-space:pre-wrap;overflow-wrap:anywhere;max-height:320px;overflow:auto}
.note{font-size:12.5px;color:var(--muted);margin-top:12px}
.countdown{margin:24px 0 6px}
.countdown .t{font-size:12px;font-weight:700;letter-spacing:.08em;color:var(--warn)}
.bar{height:6px;background:var(--code);margin-top:8px}
.bar i{display:block;height:100%;background:var(--accent);width:100%}
.btns{display:flex;gap:12px;margin-top:22px}
button{font:inherit;cursor:pointer;border:1px solid var(--ink);padding:15px 20px;
  font-size:15px;font-weight:700;letter-spacing:.02em;flex:1}
button.approve{background:var(--accent);border-color:var(--accent-deep);color:#fff}
button.approve:hover{background:var(--accent-deep)}
button.deny{background:#fff;color:var(--ink)}
button.deny:hover{background:#F1EEE4}
button:disabled{opacity:.45;cursor:not-allowed}
.qrgrid{display:flex;gap:24px;align-items:flex-start}
.qrgrid img{width:168px;height:168px;border:1px solid var(--line);display:block;background:#fff}
.copyrow{display:flex;gap:8px;margin-top:12px}
.copyrow input{flex:1;font:inherit;font-size:12px;padding:9px 10px;border:1px solid var(--line);
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted);background:var(--paper)}
.copyrow button{flex:0 0 auto;padding:9px 14px;font-size:12px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{font-size:11px;letter-spacing:.1em;color:var(--muted);text-align:left;
  padding:10px 8px;border-bottom:2px solid var(--ink)}
td{padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:top}
td.mono,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.pill{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.08em;
  padding:4px 10px;border:1px solid}
.pill.pending{color:var(--warn);border-color:var(--warn);background:#FDF6E3}
.pill.approved{color:var(--accent);border-color:var(--accent);background:#E9F2EC}
.pill.denied{color:var(--danger);border-color:var(--danger);background:#F9E9E7}
.pill.expired{color:var(--muted);border-color:var(--muted);background:#EFEDE6}
a{color:var(--accent)}
.footer{margin-top:36px;padding-top:16px;border-top:1px solid var(--line);
  font-size:12px;color:var(--muted);display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
.receipt-hero{text-align:left;padding:8px 0 20px}
.receipt-hero .big{font-size:22px;font-weight:800;margin-bottom:6px}
pre.curl{background:#1A1915;color:#EDE9DC;padding:16px;font-size:12px;overflow:auto;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
h2{font-size:16px;letter-spacing:.04em;margin:28px 0 4px}
@media(max-width:640px){.btns{flex-direction:column}.qrgrid{flex-direction:column}.card{padding:22px}}
"""


def _shell(title: str, body: str, device: DeviceKey | None = None) -> str:
    dev = ""
    if device is not None:
        dev = (f'<span class="device">device {_esc(device.label)} · '
               f'key <span class="mono">{_esc(device.kid)}</span></span>')
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)} · x401 Wallet</title>
<style>{CSS}</style></head>
<body><div class="wrap">
<div class="topbar"><span class="brand"><span class="x">x401</span> WALLET</span>{dev}</div>
{body}
<div class="footer"><span>Self-hosted x401 v0.2.0 holder wallet — no commercial provider.</span>
<span>Approvals are signed on this device only.</span></div>
</div></body></html>"""


def home_page(srv: WalletServer) -> str:
    dev = srv.device
    creds = srv.store.list_credentials()
    with srv.lock:
        approvals = sorted(srv.approvals.values(),
                           key=lambda r: r["created_at"], reverse=True)

    cred_rows = ""
    for c in creds:
        claims = c.get("claims", {})
        given = claims.get("given_name", "")
        cred_rows += (
            f'<tr><td class="mono">{_esc(c.get("id",""))}</td>'
            f'<td>{_esc(c.get("type",""))}</td>'
            f'<td class="mono">{_esc(c.get("issuer",""))}</td>'
            f'<td>{_esc(given)} <span class="mono" style="color:var(--muted)">'
            f'{_esc(c.get("subject",""))}</span></td>'
            f'<td><form method="post" action="/api/credentials/{_esc(c.get("id",""))}/delete" '
            f'style="margin:0"><button type="submit" style="padding:6px 10px;font-size:12px;flex:0">'
            f'Delete</button></form></td></tr>')
    if not cred_rows:
        cred_rows = ('<tr><td colspan="5" style="color:var(--muted)">'
                     'No credentials yet. Seed the demo credential to try the flow.</td></tr>')

    appr_rows = ""
    for r in approvals[:20]:
        with srv.lock:
            srv._expire_if_needed(r)
            status = r["status"]
        appr_rows += (
            f'<tr><td class="mono">{_esc(r["id"][:14])}…</td>'
            f'<td>{_esc(r["terms"]["merchant_display"])}</td>'
            f'<td>{_esc(_fmt_amount(r["terms"]["amount_ceiling"]))}</td>'
            f'<td><span class="pill {status}">{status.upper()}</span></td>'
            f'<td><a href="/approve/{_esc(r["id"])}">open</a></td></tr>')
    if not appr_rows:
        appr_rows = ('<tr><td colspan="5" style="color:var(--muted)">'
                     'No approval requests yet. Agents POST to /api/requests.</td></tr>')

    body = f"""
<div class="card">
  <div class="eyebrow">HOLDER WALLET · THIS DEVICE</div>
  <h1>Your identity, your approvals.</h1>
  <p class="sub">Agents send x401 proof requests here. You see exactly what is
  asked — who, what, how much, for how long — and approve or deny on your own
  device. Approved mandates are signed with this device's key.</p>
  <div class="rows">
    <div class="row"><span class="k">DEVICE</span><span class="v">{_esc(dev.label)}</span></div>
    <div class="row"><span class="k">KEY ID</span><span class="v mono">{_esc(dev.kid)}</span></div>
    <div class="row"><span class="k">CREATED</span><span class="v">{_esc(_fmt_time(datetime.fromisoformat(dev.created_at).timestamp()))}</span></div>
    <div class="row"><span class="k">PUBLIC KEY</span><span class="v mono">Ed25519 · {_esc(dev.public_jwk["x"][:24])}…</span></div>
  </div>
  <details class="terms"><summary>Device public JWK</summary>
  <pre>{_esc(json.dumps(dev.public_jwk, indent=2))}</pre></details>
</div>

<div class="card">
  <div class="eyebrow">FOR AGENTS</div>
  <h1 style="font-size:19px">Send an approval request</h1>
  <p class="sub">POST the x401 proof request plus human-readable terms. Poll
  <span class="mono">GET /api/status/&lt;approval_id&gt;</span> until it is approved.</p>
  <pre class="curl">curl -s -X POST http://127.0.0.1:{srv.server_address[1]}/api/requests \\
  -H 'Content-Type: application/json' -d '{{
    "proof_request": {{"scheme": "x401", "version": "0.2.0",
                       "credential_requirements": {{"digital": {{"requests": []}}}}}},
    "terms": {{"merchant_display": "Acme Bank",
               "action_category": "purchase",
               "amount_ceiling": {{"currency": "USD", "value": "250.00"}},
               "expires_in": 600, "window_seconds": 3600}}
  }}'</pre>
</div>

<div class="card">
  <div class="eyebrow">APPROVAL QUEUE</div>
  <table><tr><th>ID</th><th>MERCHANT</th><th>CEILING</th><th>STATUS</th><th></th></tr>
  {appr_rows}</table>
</div>

<div class="card">
  <div class="eyebrow">CREDENTIALS</div>
  <table><tr><th>ID</th><th>TYPE</th><th>ISSUER</th><th>HOLDER</th><th></th></tr>
  {cred_rows}</table>
  <form method="post" action="/api/credentials/seed" style="margin-top:14px">
    <button type="submit" class="deny" style="flex:0">Seed demo credential</button>
  </form>
  <p class="note">Credentials live in <span class="mono">wallet-data/credentials.json</span>
  on this device. Nothing leaves the device except mandates you explicitly approve.</p>
</div>"""
    return _shell("Home", body, dev)


def approve_page(srv: WalletServer, record: dict, url: str, svg: str | None) -> str:
    dev = srv.device
    terms = record["terms"]
    claims = record["mandate_claims"]
    amount = _fmt_amount(terms["amount_ceiling"])
    with srv.lock:
        srv._expire_if_needed(record)
        status = record["status"]

    if status == "approved":
        return _shell("Approved", _receipt_approved(record), dev)
    if status == "denied":
        return _shell("Denied", _receipt_denied(record), dev)
    if status == "expired":
        return _shell("Expired", error_page(
            410, "This approval request expired",
            f'{_esc(terms["merchant_display"])} asked for approval, but the '
            'request lapsed before you decided. Ask the agent to send a fresh request.'), dev)

    # ---- pending: the person-facing approval screen ----
    client_id = terms.get("client_id") or ""
    who_line = (f'<div class="row"><span class="k">VERIFIER</span>'
                f'<span class="v mono">{_esc(client_id) if client_id else "not stated"}</span></div>')
    window = f'{_fmt_time(claims["not_before"])} → {_fmt_time(claims["not_after"])}'

    qr_block = ""
    if svg is not None:
        qr_block = f"""
<div class="card">
  <div class="eyebrow">SECOND DEVICE</div>
  <div class="qrgrid">
    <img src="/qr/{_esc(record["id"])}" alt="QR code for this approval">
    <div>
      <h1 style="font-size:17px;margin-bottom:6px">On your phone instead?</h1>
      <p class="sub" style="margin-bottom:0">Scan the code to open this exact
      approval on another device. Same terms, same signature.</p>
      <div class="copyrow">
        <input id="appr-url" readonly value="{_esc(url)}">
        <button type="button" class="deny" onclick="navigator.clipboard.writeText(document.getElementById('appr-url').value);this.textContent='Copied';">Copy link</button>
      </div>
    </div>
  </div>
</div>"""
    else:
        qr_block = f"""
<div class="card">
  <div class="eyebrow">SECOND DEVICE</div>
  <p class="sub">Open this approval on another device:</p>
  <div class="copyrow">
    <input id="appr-url" readonly value="{_esc(url)}">
    <button type="button" class="deny" onclick="navigator.clipboard.writeText(document.getElementById('appr-url').value);this.textContent='Copied';">Copy link</button>
  </div>
</div>"""

    body = f"""
<div class="card">
  <div class="eyebrow">APPROVAL REQUEST · <span id="countdown">--:--</span> LEFT</div>
  <h1>{_esc(terms["merchant_display"])} is asking your agent to act</h1>
  <p class="sub">Review the terms below. Approving signs a scoped mandate with
  this device's key — the agent cannot exceed what you sign.</p>

  <div class="amount">{_esc(terms["amount_ceiling"]["value"])} <small>{_esc(terms["amount_ceiling"]["currency"])}</small></div>
  <p class="sub" style="margin-top:0">maximum amount the agent may act within</p>

  <div class="rows">
    <div class="row"><span class="k">WHO IS ASKING</span><span class="v"><strong>{_esc(terms["merchant_display"])}</strong></span></div>
    {who_line}
    <div class="row"><span class="k">ACTION</span><span class="v">{_esc(terms["action_category"])}</span></div>
    <div class="row"><span class="k">AGENT</span><span class="v mono">{_esc(terms["agent"])}</span></div>
    <div class="row"><span class="k">TIME WINDOW</span><span class="v">{_esc(window)}</span></div>
    <div class="row"><span class="k">REQUEST EXPIRES</span><span class="v">{_esc(_fmt_time(record["expires_at"]))}</span></div>
  </div>

  <details class="terms">
    <summary>Exact signed terms — what you see is what you sign</summary>
    <pre>{_esc(record["canonical_terms"])}</pre>
  </details>
  <p class="note">On approval, the JSON above is signed as-is (canonical form)
  with this device's Ed25519 key as mandate type
  <span class="mono">{_esc(x.MANDATE_TYPE)}</span>. If the agent alters the amount,
  recipient, or any other term, the signature no longer validates.</p>

  <div class="countdown"><div class="t">EXPIRES IN <span id="countdown2">--:--</span></div>
  <div class="bar"><i id="bar"></i></div></div>

  <div class="btns">
    <button type="button" class="deny" id="btn-deny">Deny</button>
    <button type="button" class="approve" id="btn-approve">Approve {_esc(amount)}</button>
  </div>
  <p class="note" id="msg" style="min-height:1.2em"></p>
</div>
{qr_block}
<script>
(function(){{
  var expiresAt = {record["expires_at"]:.3f};
  var createdAt = {record["created_at"]:.3f};
  function tick(){{
    var now = Date.now()/1000, left = Math.max(0, expiresAt - now);
    var m = Math.floor(left/60), s = Math.floor(left%60);
    var txt = (m<10?"0":"")+m+":"+(s<10?"0":"")+s;
    document.getElementById("countdown").textContent = txt;
    document.getElementById("countdown2").textContent = txt;
    var total = Math.max(1, expiresAt - createdAt);
    document.getElementById("bar").style.width = (100*left/total)+"%";
    if (left <= 0) location.reload();
  }}
  tick(); setInterval(tick, 1000);
  function decide(d){{
    var b1=document.getElementById("btn-approve"), b2=document.getElementById("btn-deny");
    b1.disabled = b2.disabled = true;
    document.getElementById("msg").textContent = "Signing…";
    fetch("/api/approve/{_esc(record["id"])}", {{
      method:"POST", headers:{{"Content-Type":"application/json"}},
      body: JSON.stringify({{decision:d}})
    }}).then(function(r){{ return r.json().then(function(j){{ return {{s:r.status,j:j}}; }}); }})
    .then(function(x){{
      if (x.s === 200) location.reload();
      else {{
        document.getElementById("msg").textContent = "Error: " + (x.j.error_description || x.j.error || x.s);
        b1.disabled = b2.disabled = false;
      }}
    }}).catch(function(e){{
      document.getElementById("msg").textContent = "Network error: " + e;
      b1.disabled = b2.disabled = false;
    }});
  }}
  document.getElementById("btn-approve").addEventListener("click", function(){{ decide("approve"); }});
  document.getElementById("btn-deny").addEventListener("click", function(){{ decide("deny"); }});
}})();
</script>"""
    return _shell(f"Approve — {terms['merchant_display']}", body, dev)


def _receipt_approved(record: dict) -> str:
    cr = record["credential_result"]
    terms = record["terms"]
    return f"""
<div class="card">
  <div class="receipt-hero">
    <div class="eyebrow" style="color:var(--accent)">DECIDED</div>
    <div class="big">Approved — mandate signed.</div>
    <p class="sub">{_esc(terms["merchant_display"])} · {_esc(_fmt_amount(terms["amount_ceiling"]))} ·
    agent <span class="mono">{_esc(terms["agent"])}</span></p>
  </div>
  <div class="rows">
    <div class="row"><span class="k">PROTOCOL</span><span class="v mono">{_esc(cr["protocol"])}</span></div>
    <div class="row"><span class="k">DECIDED AT</span><span class="v">{_esc(_fmt_time(record["decided_at"]))}</span></div>
    <div class="row"><span class="k">VALID UNTIL</span><span class="v">{_esc(_fmt_time(record["mandate_claims"]["not_after"]))}</span></div>
  </div>
  <details class="terms"><summary>Signed mandate (JWS)</summary>
  <pre>{_esc(cr["data"])}</pre></details>
  <p class="note">The agent can fetch this via
  <span class="mono">GET /api/status/{_esc(record["id"])}</span>. The mandate is
  independently re-verifiable by the merchant at any time.</p>
</div>"""


def _receipt_denied(record: dict) -> str:
    terms = record["terms"]
    return f"""
<div class="card">
  <div class="receipt-hero">
    <div class="eyebrow" style="color:var(--danger)">DECIDED</div>
    <div class="big">Denied.</div>
    <p class="sub">No mandate was signed. The agent was told this request
    ({_esc(terms["merchant_display"])}, {_esc(_fmt_amount(terms["amount_ceiling"]))}) was denied.</p>
  </div>
</div>"""


def error_page(status: int, title: str, message: str) -> str:
    return _shell(title, f"""
<div class="card">
  <div class="eyebrow">{status}</div>
  <h1>{title}</h1>
  <p class="sub">{message}</p>
  <p><a href="/">Back to wallet home</a></p>
</div>""")


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    server = WalletServer((HOST, PORT), data_dir=DATA_DIR)
    host, port = server.server_address[:2]
    print(f"x401 wallet listening on http://{host}:{port}/")
    print(f"  data dir : {server.data_dir}")
    print(f"  device   : {server.device.label} (kid={server.device.kid})")
    if x.X401_FALLBACKS:
        print(f"  note     : x401 package API fallbacks in use: {', '.join(x.X401_FALLBACKS)}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

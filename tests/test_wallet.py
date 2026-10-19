#!/usr/bin/env python3
"""Tests for the x401 self-hosted wallet (holder side).

Stdlib only (unittest + urllib).  Starts WalletServer in-process on
127.0.0.1 with an ephemeral port -- no external network.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wallet import _compat as x
from wallet.device import DeviceKey
from wallet.qr import HAVE_QR
from wallet.service import WalletServer, _relay_return_uri
from wallet.store import CredentialStore, seed_demo_credential


def http(method, url, body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def submit(server_base, proof_request=None, terms=None):
    pr = {"scheme": "x401", "version": "0.2.0",
          "credential_requirements": {"digital": {"requests": []}}}
    if proof_request:
        pr.update(proof_request)
    body = {"proof_request": pr}
    if terms is not None:
        body["terms"] = terms
    return http("POST", server_base + "/api/requests", body)


class WalletServiceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="x401-wallet-test-")
        cls.server = WalletServer(("127.0.0.1", 0), data_dir=cls.tmpdir)
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        dev = json.loads(Path(cls.tmpdir, "device.json").read_text())
        cls.device_jwk = dev["public_jwk"]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    # -- submission -----------------------------------------------------
    def test_submit_returns_approval(self):
        status, body = submit(self.base, terms={
            "merchant_display": "Acme Bank", "action_category": "purchase",
            "amount_ceiling": {"currency": "USD", "value": "250.00"}})
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["approval_id"].startswith("appr-"))
        self.assertIn("/approve/" + payload["approval_id"], payload["approval_url"])
        self.assertTrue(payload["approval_url"].startswith("http://127.0.0.1:"))
        self.assertEqual(payload["qr_text"], payload["approval_url"])

        status, body = http("GET", f"{self.base}/api/status/{payload['approval_id']}")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "pending")

    def test_submit_bad_body(self):
        status, _ = http("POST", self.base + "/api/requests",
                         {"terms": {}})  # missing proof_request
        self.assertEqual(status, 400)
        status, _ = http("POST", self.base + "/api/requests",
                         {"proof_request": "not-a-dict"})
        self.assertEqual(status, 400)

    def test_terms_defaults(self):
        status, body = submit(self.base, terms=None)
        self.assertEqual(status, 200)
        aid = json.loads(body)["approval_id"]
        record = self.server.get_approval(aid)
        self.assertEqual(record["terms"]["merchant_display"], "Unknown merchant")
        self.assertEqual(record["terms"]["amount_ceiling"]["currency"], "USD")
        self.assertEqual(record["terms"]["agent"], "agent:unknown")

    # -- full approval flow ---------------------------------------------
    def test_full_approval_flow(self):
        status, body = submit(self.base, terms={
            "merchant_display": "Acme Bank", "action_category": "purchase",
            "amount_ceiling": {"currency": "USD", "value": "250.00"},
            "agent": "agent:shopping-assistant-7",
            "window_seconds": 3600})
        aid = json.loads(body)["approval_id"]

        status, body = http("POST", f"{self.base}/api/approve/{aid}",
                            {"decision": "approve"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "approved")

        status, body = http("GET", f"{self.base}/api/status/{aid}")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["status"], "approved")
        pr = payload["proof_response"]
        self.assertEqual(pr["credential_result"]["protocol"], x.MANDATE_TYPE)
        token = pr["credential_result"]["data"]

        # mandate verifies against the device public key
        claims = x.verify_mandate(token, self.device_jwk)
        self.assertEqual(claims["type"], x.MANDATE_TYPE)
        self.assertEqual(claims["merchant"], "Acme Bank")
        self.assertEqual(claims["action_category"], "purchase")
        self.assertEqual(claims["amount_ceiling"],
                         {"currency": "USD", "value": "250.00"})
        self.assertEqual(claims["agent"], "agent:shopping-assistant-7")
        self.assertLess(claims["not_before"], claims["not_after"])
        self.assertTrue(claims["nonce"])

        # SIWE property: the signed bytes are exactly the canonical terms
        h_b64, p_b64, _s_b64 = token.split(".")
        self.assertEqual(x.b64u_decode(p_b64), x.canonical(claims))

        # second decision is rejected
        status, _ = http("POST", f"{self.base}/api/approve/{aid}",
                         {"decision": "deny"})
        self.assertEqual(status, 409)

    def test_deny_flow(self):
        status, body = submit(self.base, terms={"merchant_display": "Acme Bank"})
        aid = json.loads(body)["approval_id"]
        status, body = http("POST", f"{self.base}/api/approve/{aid}",
                            {"decision": "deny"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "denied")
        status, body = http("GET", f"{self.base}/api/status/{aid}")
        payload = json.loads(body)
        self.assertEqual(payload["status"], "denied")
        self.assertNotIn("proof_response", payload)

    def test_bad_decision(self):
        status, body = submit(self.base, terms={"merchant_display": "Acme Bank"})
        aid = json.loads(body)["approval_id"]
        status, body = http("POST", f"{self.base}/api/approve/{aid}",
                            {"decision": "maybe"})
        self.assertEqual(status, 400)

    def test_unknown_approval(self):
        status, _ = http("GET", self.base + "/api/status/appr-nope")
        self.assertEqual(status, 404)
        status, _ = http("POST", self.base + "/api/approve/appr-nope",
                         {"decision": "approve"})
        self.assertEqual(status, 404)

    def test_expired_approval(self):
        status, body = submit(self.base, terms={"merchant_display": "Acme Bank",
                                                "expires_in": 1})
        aid = json.loads(body)["approval_id"]
        time.sleep(1.4)
        status, body = http("POST", f"{self.base}/api/approve/{aid}",
                            {"decision": "approve"})
        self.assertEqual(status, 410)
        self.assertEqual(json.loads(body)["error"], "approval_expired")
        status, body = http("GET", f"{self.base}/api/status/{aid}")
        self.assertEqual(json.loads(body)["status"], "expired")

    # -- tamper resistance ------------------------------------------------
    def _approved_token(self):
        status, body = submit(self.base, terms={
            "merchant_display": "Acme Bank",
            "amount_ceiling": {"currency": "USD", "value": "250.00"}})
        aid = json.loads(body)["approval_id"]
        http("POST", f"{self.base}/api/approve/{aid}", {"decision": "approve"})
        _s, b = http("GET", f"{self.base}/api/status/{aid}")
        return json.loads(b)["proof_response"]["credential_result"]["data"]

    @staticmethod
    def _flip(token, part=1, pos=10):
        parts = token.split(".")
        seg = parts[part]
        new_char = "A" if seg[pos] != "A" else "B"
        parts[part] = seg[:pos] + new_char + seg[pos + 1:]
        return ".".join(parts)

    def test_tampered_payload_fails(self):
        token = self._approved_token()
        with self.assertRaises(x.MandateError):
            x.verify_mandate(self._flip(token, part=1), self.device_jwk)

    def test_tampered_signature_fails(self):
        token = self._approved_token()
        with self.assertRaises(x.MandateError):
            x.verify_mandate(self._flip(token, part=2), self.device_jwk)

    def test_wrong_key_fails(self):
        token = self._approved_token()
        _priv, other_jwk = x.generate_keypair()
        with self.assertRaises(x.MandateError):
            x.verify_mandate(token, other_jwk)

    def test_expired_mandate_fails(self):
        token = self._approved_token()
        claims = x.verify_mandate(token, self.device_jwk, check_time=False)
        with self.assertRaises(x.MandateError):
            x.verify_mandate(token, self.device_jwk,
                             now=claims["not_after"] + 1)

    # -- pages ------------------------------------------------------------
    def test_home_page(self):
        status, body = http("GET", self.base + "/")
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertIn("x401", text)
        self.assertIn(self.server.device.kid, text)

    def test_approve_page_shows_terms(self):
        status, body = submit(self.base, terms={
            "merchant_display": "Acme Bank", "action_category": "purchase",
            "amount_ceiling": {"currency": "USD", "value": "250.00"}})
        aid = json.loads(body)["approval_id"]
        status, body = http("GET", f"{self.base}/approve/{aid}")
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertIn("Acme Bank", text)
        self.assertIn("250.00", text)
        self.assertIn("Exact signed terms", text)
        self.assertIn("border-radius:0", text.replace(" ", ""))
        # canonical terms block matches what the wallet will sign
        # (HTML-escaped in the page, as it must be)
        import html as _html
        record = self.server.get_approval(aid)
        self.assertIn(_html.escape(record["canonical_terms"])[:80], text)

    def test_approve_page_unknown(self):
        status, _ = http("GET", self.base + "/approve/appr-nope")
        self.assertEqual(status, 404)

    @unittest.skipUnless(HAVE_QR, "qrcodegen vendor library unavailable")
    def test_qr_endpoint(self):
        status, body = submit(self.base, terms={"merchant_display": "Acme Bank"})
        aid = json.loads(body)["approval_id"]
        status, body = http("GET", f"{self.base}/qr/{aid}")
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertIn("<svg", text)
        self.assertIn("</svg>", text)

    # -- return_uri relay ---------------------------------------------------
    def test_return_uri_non_https_ignored(self):
        status, body = submit(
            self.base,
            proof_request={"return_uri": "http://evil.example/hook"},
            terms={"merchant_display": "Acme Bank"})
        aid = json.loads(body)["approval_id"]
        status, body = http("POST", f"{self.base}/api/approve/{aid}",
                            {"decision": "approve"})
        self.assertEqual(status, 200)  # approval unaffected

    def test_relay_best_effort_never_raises(self):
        # https to a closed port must not raise (best-effort, 5s timeout)
        _relay_return_uri("https://127.0.0.1:1/x401/return",
                          {"protocol": x.MANDATE_TYPE, "data": "x"})


class CredentialStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="x401-store-test-")
        self.store = CredentialStore(Path(self.tmpdir) / "credentials.json")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_crud(self):
        cid = self.store.add_credential({
            "type": "IdentityCredential", "issuer": "did:example:bank",
            "subject": "did:example:alex", "claims": {"given_name": "Alex"}})
        self.assertTrue(cid.startswith("cred-"))
        self.assertEqual(len(self.store.list_credentials()), 1)
        got = self.store.get_credential(cid)
        self.assertEqual(got["claims"]["given_name"], "Alex")
        self.assertIn("added_at", got)
        self.assertTrue(self.store.delete_credential(cid))
        self.assertEqual(self.store.list_credentials(), [])
        self.assertFalse(self.store.delete_credential(cid))
        self.assertIsNone(self.store.get_credential(cid))

    def test_persistence(self):
        cid = self.store.add_credential({"type": "T", "issuer": "i",
                                         "subject": "s", "claims": {}})
        again = CredentialStore(Path(self.tmpdir) / "credentials.json")
        self.assertEqual(again.get_credential(cid)["type"], "T")

    def test_seed_demo_credential(self):
        cred = seed_demo_credential(self.store)
        self.assertEqual(cred["type"], "IdentityCredential")
        self.assertEqual(cred["subject"], "did:example:alex")
        self.assertEqual(cred["issuer"], "did:example:alex")  # self-issued


class DeviceKeyTest(unittest.TestCase):
    def test_create_and_reload(self):
        tmpdir = tempfile.mkdtemp(prefix="x401-device-test-")
        try:
            d1 = DeviceKey(tmpdir, label="Test device")
            self.assertEqual(d1.label, "Test device")
            self.assertTrue(d1.kid)
            self.assertEqual(d1.public_jwk["kty"], "OKP")
            sig = d1.sign(b"hello")
            d1.private_key.public_key().verify(sig, b"hello")

            d2 = DeviceKey(tmpdir)  # reload from disk
            self.assertEqual(d2.kid, d1.kid)
            self.assertEqual(d2.public_jwk, d1.public_jwk)
            sig2 = d2.sign(b"hello")
            d2.private_key.public_key().verify(sig2, b"hello")

            mode = Path(tmpdir, "device.json").stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class CompatTest(unittest.TestCase):
    def test_local_fallbacks_cover_mandate_api(self):
        # The sibling x401 package is built in parallel; these must work
        # with or without it.
        priv, jwk = x.generate_keypair()
        mandate = x.build_mandate(
            agent="agent:x", merchant="M", action_category="purchase",
            amount_ceiling={"currency": "USD", "value": "1.00"},
            not_before=1_700_000_000, not_after=1_700_003_600,
            nonce="n123", issuer="iss")
        token = x.sign_mandate(mandate, priv, kid="k1")
        self.assertEqual(token.count("."), 2)
        claims = x.verify_mandate(token, jwk, check_time=False)
        self.assertEqual(claims["merchant"], "M")
        canon1 = x.canonical(mandate)
        canon2 = x.canonical(dict(reversed(list(mandate.items()))))
        self.assertEqual(canon1, canon2)  # key order independent

    def test_parse_proof_request_lenient(self):
        pr = x.parse_proof_request({"scheme": "x401", "custom": 1})
        self.assertEqual(pr["custom"], 1)
        with self.assertRaises(ValueError):
            x.parse_proof_request({"scheme": "http"})
        with self.assertRaises(ValueError):
            x.parse_proof_request("nope")

    def test_cross_track_mandate_interop(self):
        """A wallet-signed mandate must verify with the sibling x401 package
        directly (and vice versa) -- the two tracks stay wire-compatible."""
        try:
            from x401 import mandate as xm
        except ImportError:
            self.skipTest("sibling x401 package not built yet")
        priv, jwk = x.generate_keypair()
        mandate = x.build_mandate(
            agent="agent:x", merchant="M", action_category="purchase",
            amount_ceiling={"currency": "USD", "value": "1.00"},
            not_before=1_700_000_000, not_after=1_900_000_000,
            nonce="n123", issuer="iss")
        token = x.sign_mandate(mandate, priv, kid="k1")

        # kid is conveyed in the JWS header
        header_b64 = token.split(".")[0]
        header = json.loads(x.b64u_decode(header_b64))
        self.assertEqual(header.get("kid"), "k1")
        self.assertEqual(header.get("alg"), "EdDSA")

        # sibling verifier accepts the wallet's token (key object form)
        pub = x.normalize_public_key(jwk)
        claims = xm.verify_mandate(token, pub)
        self.assertEqual(claims["type"], xm.MANDATE_TYPE)
        self.assertEqual(claims["merchant"], "M")

        # and a token built purely with the sibling API verifies via _compat
        sib_token = xm.sign_mandate(
            xm.build_mandate(agent="agent:y", merchant="M2",
                             action_category="refund",
                             amount_ceiling={"currency": "USD", "value": "5.00"},
                             not_before=1_700_000_000, not_after=1_900_000_000,
                             nonce="n456"),
            priv)
        claims2 = x.verify_mandate(sib_token, jwk)
        self.assertEqual(claims2["merchant"], "M2")


if __name__ == "__main__":
    unittest.main(verbosity=2)

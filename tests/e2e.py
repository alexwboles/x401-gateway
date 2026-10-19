#!/usr/bin/env python3
"""End-to-end tests for the x401-gateway demo.

unittest, stdlib HTTP only; the delivered wallet + demo merchant run in-process
on 127.0.0.1 with ephemeral ports; no external network. Each test drives the real
wire protocol: PROOF-REQUEST -> wallet approval -> PROOF-RESPONSE -> PROOF-RESULT,
and asserts the exact x401 error token on every negative path.

Run:  python3 tests/e2e.py        (from the repo root)
"""

import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from demo import _compat as C
from demo import merchant as merchant_mod
from demo.agent import build_terms

CLIENT_ID = merchant_mod.CLIENT_ID
REQUEST_ID_BASE = merchant_mod.REQUEST_ID_BASE


def http_request(method, url, headers=None, data=None, content_type=None):
    req = urllib.request.Request(url, data=data, headers=dict(headers or {}),
                                 method=method)
    if content_type:
        req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def proof_result_error(headers) -> str:
    value = headers.get("PROOF-RESULT") or headers.get("Proof-Result")
    assert value, "expected a PROOF-RESULT header on the failure response"
    return C.result.parse_result(C.codec.decode_payload(value))["error"]


class DemoHarness(unittest.TestCase):
    token_ttl = 300

    def start_merchant(self, charge_amount="49.99", token_ttl=None):
        config = merchant_mod.MerchantConfig(
            trust=self.trust,
            charge_amount={"currency": "USD", "value": charge_amount},
            token_ttl=self.token_ttl if token_ttl is None else token_ttl,
        )
        # Key resolution for the trusted device key (parallel to the TrustList).
        config.key_map[self.wallet.issuer_id] = (
            self.wallet.key_id, self.wallet.public_key)
        server = merchant_mod.create_server("127.0.0.1", 0, config)
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        self._servers.append((server, thread))
        host, port = server.server_address
        return f"http://{host}:{port}"

    def setUp(self):
        self._servers = []
        # Fresh wallet (and device key) per test; isolated data dir.
        self.wallet = C.open_wallet(port=0, data_dir=tempfile.mkdtemp(
            prefix="x401-wallet-e2e-"))
        # Operator-owned local trust: merchant trusts the wallet's device key
        # directly as a self-issued issuer.
        self.trust = C.trust.TrustList()
        C.add_trust_issuer(self.trust, issuer_id=self.wallet.issuer_id,
                           public_key=self.wallet.public_key,
                           public_jwk=self.wallet.public_jwk,
                           key_id=self.wallet.key_id)
        self.merchant_url = self.start_merchant()

    def tearDown(self):
        for server, _thread in self._servers:
            server.shutdown()
            server.server_close()
        self.wallet.close()

    # -- helpers ---------------------------------------------------------
    def device_private_key(self):
        """Wallet device private key — test-only (mints negative-test mandates)."""
        server = self.wallet.server
        if hasattr(server, "device"):  # delivered wallet
            return server.device.private_key
        return server.device_private_key  # fallback wallet

    def get_challenge(self, url=None):
        url = url or self.merchant_url
        status, headers, _body = http_request("GET", url + "/resource")
        self.assertEqual(status, 401, "expected 401 challenge")
        self.assertIn("PROOF-REQUEST", headers)
        self.assertIn("Cache-Control", headers)
        payload = C.request.parse_proof_request(
            C.codec.decode_payload(headers["PROOF-REQUEST"]))
        jar = payload["credential_requirements"]["digital"]["requests"][0]
        self.assertEqual(jar["protocol"], "openid4vp-v1-signed")
        _h, jar_claims = C.decode_compact_unverified(jar["data"]["request"])
        self.assertTrue(payload["request_id"].startswith(REQUEST_ID_BASE))
        return payload, jar_claims

    def wallet_approve(self, payload, terms_dict) -> dict:
        """Submit challenge+terms, approve programmatically, return proof_response."""
        status, _h, body = http_request(
            "POST", self.wallet.url + "/api/requests",
            data=json.dumps({"proof_request": payload,
                             "terms": terms_dict}).encode(),
            content_type="application/json")
        self.assertEqual(status, 200)
        session = json.loads(body)
        self.assertTrue(session["approval_url"].startswith(self.wallet.url))
        approval_id = session["approval_id"]
        self.assertEqual(C.wallet_approve(self.wallet, approval_id), 200)
        state = C.wallet_status(self.wallet, approval_id)
        self.assertEqual(state["status"], "approved")
        return state["proof_response"]

    def retry(self, proof_response, url=None):
        url = url or self.merchant_url
        return http_request(
            "GET", url + "/resource",
            headers={"PROOF-RESPONSE": C.codec.encode_payload(proof_response)})

    def mint_mandate(self, *, nonce, request_id, ceiling="100.00",
                     not_before=None, not_after=None, key=None, kid=None,
                     issuer=None, merchant_id=CLIENT_ID):
        """Mint a signed mandate (negative-test credential factory)."""
        now = int(time.time())
        claims = C.build_mandate(
            agent="e2e-agent/1",
            merchant=merchant_id,
            action_category="purchase",
            amount_ceiling={"currency": "USD", "value": ceiling},
            not_before=int(not_before) if not_before is not None else now,
            not_after=int(not_after) if not_after is not None else now + 600,
            nonce=nonce,
            request_id=request_id,
            issuer=issuer or self.wallet.issuer_id,
        )
        return C.sign_mandate(claims, key or self.device_private_key(),
                              kid=kid or self.wallet.key_id)

    @staticmethod
    def artifact_for(mandate_jws, request_id):
        return {"request_id": request_id,
                "credential_result": {"protocol": C.MANDATE_TYPE,
                                      "data": mandate_jws}}


class EndToEnd(DemoHarness):
    def test_full_loop(self):
        """challenge -> wallet submit -> approve -> PROOF-RESPONSE -> 200 granted."""
        payload, _jar = self.get_challenge()
        proof_response = self.wallet_approve(
            payload, build_terms(CLIENT_ID, amount="49.99", ceiling="100.00",
                                 agent_id="e2e-agent/1"))
        status, _headers, body = self.retry(proof_response)
        self.assertEqual(status, 200)
        granted = json.loads(body)
        self.assertTrue(granted["granted"])
        self.assertEqual(granted["mandate"]["merchant"], CLIENT_ID)
        self.assertEqual(granted["request_id"], payload["request_id"])

    def test_tampered_amount(self):
        """(a) charge above the mandate ceiling -> mandate_exceeded.
        (b) terms re-serialized under the original signature -> rejected."""
        # (a) merchant charges 150.00 against a 100.00 mandate ceiling.
        url2 = self.start_merchant(charge_amount="150.00")
        payload, _jar = self.get_challenge(url2)
        proof_response = self.wallet_approve(
            payload, build_terms(CLIENT_ID, amount="150.00", ceiling="100.00",
                                 agent_id="e2e-agent/1"))
        status, headers, _body = self.retry(proof_response, url=url2)
        self.assertEqual(status, 401)
        self.assertEqual(proof_result_error(headers), "mandate_exceeded")

        # (b) valid signature, tampered terms: flip the ceiling, keep signature.
        payload, jar = self.get_challenge()
        good = self.mint_mandate(nonce=jar["nonce"],
                                 request_id=payload["request_id"])
        h_b64, p_b64, s_b64 = good.split(".")
        claims = json.loads(C.b64u_decode(p_b64))
        claims["amount_ceiling"]["value"] = "1000000.00"
        tampered = (h_b64 + "."
                    + C.b64u_encode(json.dumps(
                        claims, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=False).encode("utf-8"))
                    + "." + s_b64)
        status, headers, _body = self.retry(
            self.artifact_for(tampered, payload["request_id"]))
        self.assertEqual(status, 401)
        self.assertIn(proof_result_error(headers),
                      {"tampered_mandate", "invalid_signature"})

    def test_expired_mandate(self):
        """Mandate with not_after in the past -> expired_mandate."""
        payload, jar = self.get_challenge()
        token = self.mint_mandate(nonce=jar["nonce"],
                                  request_id=payload["request_id"],
                                  not_after=time.time() - 60)
        status, headers, _body = self.retry(
            self.artifact_for(token, payload["request_id"]))
        self.assertEqual(status, 401)
        self.assertEqual(proof_result_error(headers), "expired_mandate")

    def test_replayed_nonce(self):
        """Replaying a consumed proof -> replayed_nonce."""
        payload, _jar = self.get_challenge()
        proof_response = self.wallet_approve(
            payload, build_terms(CLIENT_ID, amount="49.99", ceiling="100.00",
                                 agent_id="e2e-agent/1"))
        status, _h, body = self.retry(proof_response)
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["granted"])
        status, headers, _body = self.retry(proof_response)
        self.assertEqual(status, 401)
        self.assertEqual(proof_result_error(headers), "replayed_nonce")

    def test_untrusted_issuer(self):
        """Mandate signed by a key outside the trust list -> untrusted_issuer."""
        payload, jar = self.get_challenge()
        evil_priv, _evil_pub = C.jws.generate_ed25519_keypair()
        token = self.mint_mandate(nonce=jar["nonce"],
                                  request_id=payload["request_id"],
                                  key=evil_priv, kid="evil-key-1",
                                  issuer="did:web:evil.example")
        status, headers, _body = self.retry(
            self.artifact_for(token, payload["request_id"]))
        self.assertEqual(status, 401)
        self.assertEqual(proof_result_error(headers), "untrusted_issuer")

    def test_oauth_leg(self):
        """Token exchange with a valid artifact -> Bearer -> granted;
        garbage bearer -> invalid_token; expired bearer -> token_expired."""
        url = self.start_merchant(token_ttl=2)
        payload, _jar = self.get_challenge(url)
        proof_response = self.wallet_approve(
            payload, build_terms(CLIENT_ID, amount="49.99", ceiling="100.00",
                                 agent_id="e2e-agent/1"))

        token_endpoint = payload["oauth"]["token_endpoint"]
        form = C.oauth.build_token_request(
            subject_token=C.codec.encode_payload(proof_response),
            resource=url + "/resource")
        status, _h, body = http_request(
            "POST", token_endpoint,
            data=urllib.parse.urlencode(form).encode(),
            content_type="application/x-www-form-urlencoded")
        self.assertEqual(status, 200, body.decode()[:300])
        token_resp = json.loads(body)
        self.assertEqual(token_resp["token_type"], "Bearer")
        self.assertIn("access_token", token_resp)
        self.assertIn("x401", token_resp)
        self.assertEqual(token_resp["x401"]["request_id"], payload["request_id"])
        access_token = token_resp["access_token"]

        status, _h, body = http_request(
            "GET", url + "/resource",
            headers={"Authorization": "Bearer " + access_token})
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["granted"])

        status, headers, _b = http_request(
            "GET", url + "/resource",
            headers={"Authorization": "Bearer garbage"})
        self.assertEqual(status, 401)
        self.assertEqual(proof_result_error(headers), "invalid_token")

        time.sleep(2.5)  # let the 2-second token expire
        status, headers, _b = http_request(
            "GET", url + "/resource",
            headers={"Authorization": "Bearer " + access_token})
        self.assertEqual(status, 401)
        self.assertEqual(proof_result_error(headers), "token_expired")


if __name__ == "__main__":
    unittest.main(verbosity=2)

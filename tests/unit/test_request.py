"""Unit tests for x401/request.py -- PROOF-REQUEST build/parse."""

import base64
import json
import unittest

from x401.codec import encode_payload, parse_header
from x401.jws import (
    generate_ed25519_keypair,
    generate_p256_keypair,
    verify,
)
from x401.request import (
    RequestError,
    build_proof_request,
    parse_proof_request,
)


DCQL = {
    "credentials": [
        {
            "id": "financial_customer",
            "format": "jwt_vc_json",
            "meta": {"type_values": ["FinancialCustomerCredential"]},
            "claims": [
                {
                    "path": ["credentialSubject", "assurance_level"],
                    "values": ["VC-AL2", "VC-AL3"],
                }
            ],
        }
    ]
}


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + ("=" * ((4 - len(s) % 4) % 4)))


class TestSignedBuild(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = generate_ed25519_keypair()

    def test_build_and_parse(self):
        payload = build_proof_request(
            verifier_private_key=self.priv,
            key_id="verifier-key-1",
            client_id="x509_san_dns:bank.example.com",
            dcql=DCQL,
            expected_origins=["https://bank.example.com"],
            oauth_token_endpoint="https://bank.example.com/oauth/token",
            request_id="proof-template-financial-customer-v1",
            satisfied_requirements=["urn:example:x401:satisfaction:financial-customer:v1"],
        )
        parsed = parse_proof_request(payload)
        self.assertEqual(parsed["scheme"], "x401")
        self.assertEqual(parsed["version"], "0.2.0")
        req = parsed["credential_requirements"]["digital"]["requests"][0]
        self.assertEqual(req["protocol"], "openid4vp-v1-signed")
        self.assertIn("request", req["data"])

    def test_jar_verifies_and_has_expected_claims(self):
        payload = build_proof_request(
            verifier_private_key=self.priv,
            key_id="verifier-key-1",
            client_id="x509_san_dns:bank.example.com",
            dcql=DCQL,
            ttl=300,
        )
        jar = payload["credential_requirements"]["digital"]["requests"][0]["data"]["request"]
        claims = verify(jar, self.pub, expected_alg="EdDSA")
        self.assertEqual(claims["response_type"], "vp_token")
        self.assertEqual(claims["response_mode"], "dc_api")
        self.assertEqual(claims["client_id"], "x509_san_dns:bank.example.com")
        self.assertEqual(claims["dcql_query"], DCQL)
        self.assertIn("exp", claims)
        # kid embedded for key resolution
        header = json.loads(b64u_decode(jar.split(".")[0]).decode())
        self.assertEqual(header["kid"], "verifier-key-1")

    def test_nonce_is_128_bit_base64url(self):
        payload = build_proof_request(
            verifier_private_key=self.priv,
            key_id="k",
            client_id="cid",
            dcql=DCQL,
        )
        jar = payload["credential_requirements"]["digital"]["requests"][0]["data"]["request"]
        claims = verify(jar, self.pub)
        nonce = claims["nonce"]
        self.assertEqual(len(b64u_decode(nonce)), 16)  # 128 bits
        self.assertNotIn("=", nonce)

    def test_nonce_uniqueness(self):
        nonces = set()
        for _ in range(10):
            payload = build_proof_request(
                verifier_private_key=self.priv, key_id="k", client_id="cid", dcql=DCQL
            )
            jar = payload["credential_requirements"]["digital"]["requests"][0]["data"]["request"]
            nonces.add(verify(jar, self.pub)["nonce"])
        self.assertEqual(len(nonces), 10)

    def test_explicit_nonce_used(self):
        payload = build_proof_request(
            verifier_private_key=self.priv, key_id="k", client_id="cid", dcql=DCQL,
            nonce="fixed-nonce-for-test",
        )
        jar = payload["credential_requirements"]["digital"]["requests"][0]["data"]["request"]
        self.assertEqual(verify(jar, self.pub)["nonce"], "fixed-nonce-for-test")

    def test_es256_jar(self):
        priv, pub = generate_p256_keypair()
        payload = build_proof_request(
            verifier_private_key=priv, key_id="k", client_id="cid", dcql=DCQL, alg="ES256"
        )
        jar = payload["credential_requirements"]["digital"]["requests"][0]["data"]["request"]
        claims = verify(jar, pub, expected_alg="ES256")
        self.assertEqual(claims["client_id"], "cid")

    def test_header_round_trip(self):
        payload = build_proof_request(
            verifier_private_key=self.priv, key_id="k", client_id="cid", dcql=DCQL
        )
        name_val = ("PROOF-REQUEST", encode_payload(payload))
        self.assertEqual(parse_header({"proof-request": name_val[1]}, "PROOF-REQUEST")["scheme"], "x401")


class TestUnsignedBuild(unittest.TestCase):
    def test_unsigned_has_no_request_member(self):
        payload = build_proof_request(
            verifier_private_key=None,
            key_id="k",
            client_id="cid",
            dcql=DCQL,
            protocol="openid4vp-v1-unsigned",
        )
        req = payload["credential_requirements"]["digital"]["requests"][0]
        self.assertEqual(req["protocol"], "openid4vp-v1-unsigned")
        self.assertNotIn("request", req["data"])
        self.assertIn("nonce", req["data"])
        self.assertIn("dcql_query", req["data"])
        parse_proof_request(payload)  # must not raise

    def test_signed_requires_key(self):
        with self.assertRaises(RequestError):
            build_proof_request(
                verifier_private_key=None, key_id="k", client_id="cid", dcql=DCQL
            )

    def test_unknown_protocol_rejected(self):
        priv, _ = generate_ed25519_keypair()
        with self.assertRaises(RequestError):
            build_proof_request(
                verifier_private_key=priv, key_id="k", client_id="cid", dcql=DCQL,
                protocol="openid4vp-v1-multisigned",
            )


class TestParseErrors(unittest.TestCase):
    def valid(self):
        priv, _ = generate_ed25519_keypair()
        return build_proof_request(
            verifier_private_key=priv, key_id="k", client_id="cid", dcql=DCQL
        )

    def test_bad_scheme(self):
        obj = self.valid()
        obj["scheme"] = "x402"
        with self.assertRaises(RequestError):
            parse_proof_request(obj)

    def test_bad_version(self):
        obj = self.valid()
        obj["version"] = "0.1.0"
        with self.assertRaises(RequestError):
            parse_proof_request(obj)

    def test_missing_credential_requirements(self):
        obj = self.valid()
        del obj["credential_requirements"]
        with self.assertRaises(RequestError):
            parse_proof_request(obj)

    def test_empty_requests(self):
        obj = self.valid()
        obj["credential_requirements"]["digital"]["requests"] = []
        with self.assertRaises(RequestError):
            parse_proof_request(obj)

    def test_non_dict(self):
        with self.assertRaises(RequestError):
            parse_proof_request(["not", "a", "dict"])


class TestSpecAppendixAFixture(unittest.TestCase):
    """Spec Appendix A shape: minimal payload with oauth token endpoint."""

    def test_appendix_a_shape_parses(self):
        # Mirrors the spec's minimal example structure.
        payload = {
            "scheme": "x401",
            "version": "0.2.0",
            "credential_requirements": {
                "digital": {
                    "requests": [
                        {
                            "protocol": "openid4vp-v1-signed",
                            "data": {"request": "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2ln"},
                        }
                    ]
                }
            },
            "oauth": {"token_endpoint": "https://bank.example.com/oauth/token"},
            "request_id": "proof-template-financial-customer-v1",
        }
        parsed = parse_proof_request(payload)
        self.assertEqual(parsed["oauth"]["token_endpoint"], "https://bank.example.com/oauth/token")

    def test_structurally_realistic_eddsa_jar(self):
        """Locally-generated EdDSA JAR with the spec's decoded-claim shape."""
        priv, pub = generate_ed25519_keypair()
        payload = build_proof_request(
            verifier_private_key=priv,
            key_id="verifier-2026-10",
            client_id="x509_san_dns:bank.example.com",
            dcql=DCQL,
            expected_origins=["https://bank.example.com"],
            ttl=300,
        )
        jar = payload["credential_requirements"]["digital"]["requests"][0]["data"]["request"]
        # Structurally: compact JWS, EdDSA header, spec-shaped claims.
        self.assertEqual(len(jar.split(".")), 3)
        header = json.loads(b64u_decode(jar.split(".")[0]).decode())
        self.assertEqual(header["alg"], "EdDSA")
        claims = verify(jar, pub)
        for claim in ("response_type", "response_mode", "client_id", "expected_origins",
                      "nonce", "dcql_query", "client_metadata", "exp"):
            self.assertIn(claim, claims)
        # Nonce staleness is fine structurally -- the signature still binds the request.
        self.assertEqual(len(b64u_decode(claims["nonce"])), 16)


if __name__ == "__main__":
    unittest.main()

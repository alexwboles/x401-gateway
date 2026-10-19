"""Unit tests for x401/trust.py -- operator-owned trust list + DCQL satisfaction."""

import json
import os
import tempfile
import unittest

from x401.jws import generate_ed25519_keypair, jwk_public
from x401.trust import TrustList, default_self_issued_only

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

CRED = {
    "id": "cred-1",
    "format": "jwt_vc_json",
    "type": ["VerifiableCredential", "FinancialCustomerCredential"],
    "issuer": "did:web:self.example",
    "credentialSubject": {
        "id": "did:web:holder.example",
        "assurance_level": "VC-AL2",
        "given_name": "Alex",
    },
}


class TestTrustList(unittest.TestCase):
    def setUp(self):
        _, pub = generate_ed25519_keypair()
        self.jwk = jwk_public(pub)
        self.trust = TrustList()

    def test_default_is_empty(self):
        t = default_self_issued_only()
        self.assertFalse(t.is_trusted("did:web:anyone.example"))

    def test_add_and_check(self):
        self.assertFalse(self.trust.is_trusted("did:web:self.example"))
        self.trust.add_issuer("did:web:self.example", self.jwk)
        self.assertTrue(self.trust.is_trusted("did:web:self.example"))
        self.assertFalse(self.trust.is_trusted("did:web:other.example"))

    def test_assurance_levels(self):
        self.trust.add_issuer("did:web:self.example", self.jwk, assurance_levels=["VC-AL2"])
        self.assertTrue(self.trust.is_trusted("did:web:self.example", assurance="VC-AL2"))
        self.assertFalse(self.trust.is_trusted("did:web:self.example", assurance="VC-AL3"))
        self.assertTrue(self.trust.is_trusted("did:web:self.example"))  # no requirement

    def test_remove_issuer(self):
        self.trust.add_issuer("did:web:self.example", self.jwk)
        self.assertTrue(self.trust.remove_issuer("did:web:self.example"))
        self.assertFalse(self.trust.is_trusted("did:web:self.example"))
        self.assertFalse(self.trust.remove_issuer("did:web:self.example"))

    def test_save_load_round_trip(self):
        self.trust.add_issuer("did:web:self.example", self.jwk, assurance_levels=["VC-AL2"])
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "trust.json")
            self.trust.save(path)
            with open(path, encoding="utf-8") as fh:
                on_disk = json.load(fh)
            self.assertIn("issuers", on_disk)
            t2 = TrustList()
            t2.load(path)
            self.assertTrue(t2.is_trusted("did:web:self.example", assurance="VC-AL2"))

    def test_add_issuer_validates(self):
        with self.assertRaises(ValueError):
            self.trust.add_issuer("", self.jwk)
        with self.assertRaises(ValueError):
            self.trust.add_issuer("x", "not-a-dict")


class TestSatisfies(unittest.TestCase):
    def setUp(self):
        self.trust = TrustList()

    def test_satisfied(self):
        ok, details = self.trust.satisfies(DCQL, [CRED])
        self.assertTrue(ok)
        self.assertTrue(details["financial_customer"]["satisfied"])
        self.assertEqual(details["financial_customer"]["matched_credential"], "cred-1")

    def test_format_mismatch(self):
        cred = dict(CRED, format="mso_mdoc")
        ok, details = self.trust.satisfies(DCQL, [cred])
        self.assertFalse(ok)
        self.assertFalse(details["financial_customer"]["satisfied"])

    def test_type_values_mismatch(self):
        cred = dict(CRED)
        cred["type"] = ["VerifiableCredential", "OtherCredential"]
        ok, _ = self.trust.satisfies(DCQL, [cred])
        self.assertFalse(ok)

    def test_claim_value_mismatch(self):
        cred = json.loads(json.dumps(CRED))
        cred["credentialSubject"]["assurance_level"] = "VC-AL1"
        ok, _ = self.trust.satisfies(DCQL, [cred])
        self.assertFalse(ok)

    def test_claim_path_missing(self):
        cred = json.loads(json.dumps(CRED))
        del cred["credentialSubject"]["assurance_level"]
        ok, _ = self.trust.satisfies(DCQL, [cred])
        self.assertFalse(ok)

    def test_no_credentials(self):
        ok, _ = self.trust.satisfies(DCQL, [])
        self.assertFalse(ok)

    def test_multiple_entries_all_must_match(self):
        dcql = {
            "credentials": [
                DCQL["credentials"][0],
                {
                    "id": "second",
                    "format": "jwt_vc_json",
                    "meta": {"type_values": ["NopeCredential"]},
                },
            ]
        }
        ok, details = self.trust.satisfies(dcql, [CRED])
        self.assertFalse(ok)
        self.assertTrue(details["financial_customer"]["satisfied"])
        self.assertFalse(details["second"]["satisfied"])

    def test_nested_claim_path(self):
        dcql = {
            "credentials": [
                {
                    "id": "addr",
                    "format": "jwt_vc_json",
                    "claims": [{"path": ["credentialSubject", "address", "country"], "values": ["US"]}],
                }
            ]
        }
        cred = {
            "format": "jwt_vc_json",
            "credentialSubject": {"address": {"country": "US"}},
        }
        ok, _ = self.trust.satisfies(dcql, [cred])
        self.assertTrue(ok)

    def test_claim_without_values_just_needs_presence(self):
        dcql = {
            "credentials": [
                {
                    "id": "name",
                    "format": "jwt_vc_json",
                    "claims": [{"path": ["credentialSubject", "given_name"]}],
                }
            ]
        }
        ok, _ = self.trust.satisfies(dcql, [CRED])
        self.assertTrue(ok)

    def test_bad_dcql_rejected(self):
        with self.assertRaises(ValueError):
            self.trust.satisfies("not-a-dict", [])


if __name__ == "__main__":
    unittest.main()

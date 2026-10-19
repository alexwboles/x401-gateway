"""Unit tests for x401/jws.py -- real JWS crypto (EdDSA + ES256)."""

import base64
import json
import unittest

from x401.jws import (
    JWSError,
    generate_ed25519_keypair,
    generate_p256_keypair,
    jwk_public,
    key_from_jwk_public,
    parse_x5c,
    sign,
    verify,
)


def b64u_json(s: str) -> dict:
    padded = s + ("=" * ((4 - len(s) % 4) % 4))
    return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))


class TestEdDSA(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = generate_ed25519_keypair()

    def test_round_trip(self):
        payload = {"sub": "agent-1", "n": 42}
        token = sign(payload, self.priv, "EdDSA")
        self.assertEqual(token.count("."), 2)
        self.assertEqual(verify(token, self.pub), payload)

    def test_header_declares_eddsa(self):
        token = sign({"a": 1}, self.priv, "EdDSA")
        self.assertEqual(b64u_json(token.split(".")[0])["alg"], "EdDSA")

    def test_wrong_key_fails(self):
        other_priv, other_pub = generate_ed25519_keypair()
        token = sign({"a": 1}, self.priv, "EdDSA")
        with self.assertRaises(JWSError):
            verify(token, other_pub)

    def test_tampered_payload_fails(self):
        token = sign({"a": 1}, self.priv, "EdDSA")
        h, p, s = token.split(".")
        tampered = {"a": 2}
        p2 = base64.urlsafe_b64encode(json.dumps(tampered).encode()).decode().rstrip("=")
        with self.assertRaises(JWSError):
            verify(f"{h}.{p2}.{s}", self.pub)

    def test_tampered_signature_fails(self):
        token = sign({"a": 1}, self.priv, "EdDSA")
        h, p, s = token.split(".")
        bad_sig = ("A" if s[0] != "A" else "B") + s[1:]
        with self.assertRaises(JWSError):
            verify(f"{h}.{p}.{bad_sig}", self.pub)

    def test_alg_mismatch_fails(self):
        token = sign({"a": 1}, self.priv, "EdDSA")
        with self.assertRaises(JWSError):
            verify(token, self.pub, expected_alg="ES256")
        # matching expectation passes
        self.assertEqual(verify(token, self.pub, expected_alg="EdDSA"), {"a": 1})

    def test_wrong_key_type_fails(self):
        p_priv, p_pub = generate_p256_keypair()
        token = sign({"a": 1}, self.priv, "EdDSA")
        with self.assertRaises(JWSError):
            verify(token, p_pub)

    def test_malformed_compact_rejected(self):
        for bad in ("abc", "a.b", "a.b.c.d", "", 42):
            with self.assertRaises(JWSError):
                verify(bad, self.pub)

    def test_sign_rejects_non_dict(self):
        with self.assertRaises(JWSError):
            sign(["a"], self.priv, "EdDSA")

    def test_unsupported_alg_rejected(self):
        with self.assertRaises(JWSError):
            sign({"a": 1}, self.priv, "RS256")


class TestES256(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = generate_p256_keypair()

    def test_round_trip(self):
        payload = {"iss": "verifier", "exp": 9999999999}
        token = sign(payload, self.priv, "ES256")
        self.assertEqual(verify(token, self.pub), payload)

    def test_signature_is_raw_r_s(self):
        # JOSE: ES256 signature MUST be 64 raw bytes, not DER.
        token = sign({"a": 1}, self.priv, "ES256")
        sig_b64 = token.split(".")[2]
        padded = sig_b64 + ("=" * ((4 - len(sig_b64) % 4) % 4))
        raw = base64.urlsafe_b64decode(padded)
        self.assertEqual(len(raw), 64)
        self.assertFalse(raw.startswith(b"\x30"))  # DER would start with SEQUENCE 0x30

    def test_wrong_key_fails(self):
        _, other_pub = generate_p256_keypair()
        token = sign({"a": 1}, self.priv, "ES256")
        with self.assertRaises(JWSError):
            verify(token, other_pub)

    def test_tampered_payload_fails(self):
        token = sign({"a": 1}, self.priv, "ES256")
        h, p, s = token.split(".")
        p2 = base64.urlsafe_b64encode(json.dumps({"a": 2}).encode()).decode().rstrip("=")
        with self.assertRaises(JWSError):
            verify(f"{h}.{p2}.{s}", self.pub)

    def test_alg_mismatch_fails(self):
        token = sign({"a": 1}, self.priv, "ES256")
        with self.assertRaises(JWSError):
            verify(token, self.pub, expected_alg="EdDSA")

    def test_cross_alg_key_rejected(self):
        e_priv, _ = generate_ed25519_keypair()
        with self.assertRaises(JWSError):
            sign({"a": 1}, e_priv, "ES256")

    def test_header_declares_es256(self):
        token = sign({"a": 1}, self.priv, "ES256")
        self.assertEqual(b64u_json(token.split(".")[0])["alg"], "ES256")


class TestJWK(unittest.TestCase):
    def test_ed25519_jwk_round_trip(self):
        priv, pub = generate_ed25519_keypair()
        jwk = jwk_public(pub)
        self.assertEqual((jwk["kty"], jwk["crv"]), ("OKP", "Ed25519"))
        restored = key_from_jwk_public(jwk)
        token = sign({"a": 1}, priv, "EdDSA")
        self.assertEqual(verify(token, restored), {"a": 1})

    def test_p256_jwk_round_trip(self):
        priv, pub = generate_p256_keypair()
        jwk = jwk_public(pub)
        self.assertEqual((jwk["kty"], jwk["crv"]), ("EC", "P-256"))
        restored = key_from_jwk_public(jwk)
        token = sign({"a": 1}, priv, "ES256")
        self.assertEqual(verify(token, restored), {"a": 1})

    def test_bad_jwk_rejected(self):
        with self.assertRaises(JWSError):
            key_from_jwk_public({"kty": "RSA", "n": "x"})
        with self.assertRaises(JWSError):
            key_from_jwk_public({"kty": "OKP", "crv": "Ed25519"})  # missing x
        with self.assertRaises(JWSError):
            key_from_jwk_public("not-a-dict")


class TestX5C(unittest.TestCase):
    def test_best_effort(self):
        # garbage entries are skipped; a missing member yields []
        self.assertEqual(parse_x5c({}), [])
        self.assertEqual(parse_x5c({"x5c": ["!!!", 42, None]}), [])
        self.assertEqual(parse_x5c({"x5c": "not-a-list"}), [])


if __name__ == "__main__":
    unittest.main()

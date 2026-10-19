"""Unit tests for x401/oauth.py -- token-exchange leg."""

import json
import unittest

from x401.jws import generate_ed25519_keypair, generate_p256_keypair
from x401.oauth import (
    OAuthError,
    RESULT_ARTIFACT_TYPE,
    TOKEN_EXCHANGE_GRANT,
    build_token_request,
    issue_access_token,
    verify_access_token,
)


class TestConstants(unittest.TestCase):
    def test_grant_types(self):
        self.assertEqual(TOKEN_EXCHANGE_GRANT, "urn:ietf:params:oauth:grant-type:token-exchange")
        self.assertEqual(
            RESULT_ARTIFACT_TYPE, "urn:x401:params:oauth:token-type:result_artifact"
        )


class TestBuildTokenRequest(unittest.TestCase):
    def test_fixed_params(self):
        params = build_token_request("subject-token-bytes", "https://bank.example.com/acct")
        self.assertEqual(params["grant_type"], TOKEN_EXCHANGE_GRANT)
        self.assertEqual(params["subject_token_type"], RESULT_ARTIFACT_TYPE)
        self.assertEqual(params["subject_token"], "subject-token-bytes")
        self.assertEqual(params["resource"], "https://bank.example.com/acct")

    def test_resource_optional(self):
        params = build_token_request("t")
        self.assertNotIn("resource", params)


class TestAccessToken(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = generate_ed25519_keypair()

    def issue(self, **kw):
        args = dict(
            agent_id="did:web:agent.example",
            verifier_id="https://bank.example.com",
            request_id="proof-template-financial-customer-v1",
            satisfied_requirements=["urn:example:x401:satisfaction:financial-customer:v1"],
            resource="https://bank.example.com/accounts/applications",
            method="POST",
            signing_key=self.priv,
            key_id="verifier-key-1",
        )
        args.update(kw)
        return issue_access_token(**args)

    def test_round_trip(self):
        token = self.issue()
        claims = verify_access_token(
            token, self.pub, expected_audience="https://bank.example.com/accounts/applications"
        )
        self.assertEqual(claims["iss"], "https://bank.example.com")
        self.assertEqual(claims["sub"], "did:web:agent.example")
        self.assertIn("jti", claims)
        self.assertIn("iat", claims)
        self.assertIn("exp", claims)

    def test_x401_metadata_block(self):
        token = self.issue()
        claims = verify_access_token(token, self.pub)
        x401 = claims["x401"]
        self.assertEqual(x401["agent_id"], "did:web:agent.example")
        self.assertEqual(x401["verifier_id"], "https://bank.example.com")
        self.assertEqual(x401["request_id"], "proof-template-financial-customer-v1")
        self.assertEqual(
            x401["satisfied_requirements"],
            ["urn:example:x401:satisfaction:financial-customer:v1"],
        )
        self.assertEqual(x401["resource"], "https://bank.example.com/accounts/applications")
        self.assertEqual(x401["method"], "POST")
        self.assertIn("expires_at", x401)

    def test_expired_fails(self):
        token = self.issue(ttl=-10)
        with self.assertRaises(OAuthError) as ctx:
            verify_access_token(token, self.pub)
        self.assertEqual(ctx.exception.code, "token_expired")

    def test_wrong_audience_fails(self):
        token = self.issue()
        with self.assertRaises(OAuthError) as ctx:
            verify_access_token(token, self.pub, expected_audience="https://other.example/x")
        self.assertEqual(ctx.exception.code, "invalid_token")

    def test_wrong_key_fails(self):
        _, other_pub = generate_ed25519_keypair()
        token = self.issue()
        with self.assertRaises(OAuthError) as ctx:
            verify_access_token(token, other_pub)
        self.assertEqual(ctx.exception.code, "invalid_token")

    def test_tampered_token_fails(self):
        token = self.issue()
        h, p, s = token.split(".")
        import base64

        claims = json.loads(base64.urlsafe_b64decode(p + "==").decode())
        claims["sub"] = "did:web:attacker.example"
        p2 = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        with self.assertRaises(OAuthError) as ctx:
            verify_access_token(f"{h}.{p2}.{s}", self.pub)
        self.assertEqual(ctx.exception.code, "invalid_token")

    def test_oauth_error_carries_code(self):
        err = OAuthError("token_expired")
        self.assertEqual(err.code, "token_expired")
        self.assertIsInstance(err, ValueError)

    def test_es256_token(self):
        priv, pub = generate_p256_keypair()
        token = self.issue(signing_key=priv, alg="ES256")
        claims = verify_access_token(token, pub)
        self.assertEqual(claims["iss"], "https://bank.example.com")


if __name__ == "__main__":
    unittest.main()

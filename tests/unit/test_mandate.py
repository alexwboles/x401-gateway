"""Unit tests for x401/mandate.py -- the scoped-mandate EXTENSION.

type "x-x401ext-mandate/v1" is a gateway extension; these tests pin its behavior
without claiming any spec status for it.
"""

import base64
import json
import time
import unittest

from x401.mandate import (
    MANDATE_TYPE,
    MandateError,
    build_mandate,
    canonical,
    sign_mandate,
    verify_mandate,
)
from x401.jws import generate_ed25519_keypair, generate_p256_keypair


def make_token(priv, **kw):
    now = int(time.time())
    args = dict(
        agent="did:web:agent.example",
        merchant="merchant.example.com",
        action_category="purchase",
        amount_ceiling={"currency": "USD", "value": "100.00"},
        not_before=now - 60,
        not_after=now + 600,
        nonce="mandate-nonce-1",
        request_id="r1",
    )
    args.update(kw)
    return sign_mandate(build_mandate(**args), priv)


class TestMandate(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = generate_ed25519_keypair()

    def test_type_marked_as_extension(self):
        self.assertEqual(MANDATE_TYPE, "x-x401ext-mandate/v1")
        m = build_mandate(
            agent="a", merchant="m", action_category="purchase",
            amount_ceiling={"currency": "USD", "value": "100.00"},
            not_before=1, not_after=2, nonce="n",
        )
        self.assertEqual(m["type"], "x-x401ext-mandate/v1")

    def test_valid_verifies(self):
        token = make_token(self.priv)
        m = verify_mandate(
            token, self.pub,
            expected_merchant="merchant.example.com",
            tx_amount={"currency": "USD", "value": "50.00"},
        )
        self.assertEqual(m["action_category"], "purchase")

    def test_canonical_is_deterministic(self):
        m1 = build_mandate(
            agent="a", merchant="m", action_category="c",
            amount_ceiling={"currency": "USD", "value": "1.00"},
            not_before=1, not_after=2, nonce="n",
        )
        m2 = {k: m1[k] for k in reversed(list(m1.keys()))}
        self.assertEqual(canonical(m1), canonical(m2))
        self.assertEqual(canonical(m1), b'{"action_category":"c","agent":"a",'
                                        b'"amount_ceiling":{"currency":"USD","value":"1.00"},'
                                        b'"merchant":"m","nonce":"n","not_after":2,'
                                        b'"not_before":1,"type":"x-x401ext-mandate/v1"}')

    def test_tampered_amount_fails(self):
        token = make_token(self.priv)
        h, p, s = token.split(".")
        payload = json.loads(base64.urlsafe_b64decode(p + "==").decode())
        payload["amount_ceiling"]["value"] = "999999.00"
        p2 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        with self.assertRaises(MandateError) as ctx:
            verify_mandate(f"{h}.{p2}.{s}", self.pub)
        self.assertEqual(ctx.exception.code, "invalid_signature")

    def test_tampered_recipient_fails(self):
        token = make_token(self.priv)
        h, p, s = token.split(".")
        payload = json.loads(base64.urlsafe_b64decode(p + "==").decode())
        payload["merchant"] = "evil.example.com"
        p2 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        with self.assertRaises(MandateError) as ctx:
            verify_mandate(f"{h}.{p2}.{s}", self.pub)
        self.assertEqual(ctx.exception.code, "invalid_signature")

    def test_expired_fails(self):
        now = int(time.time())
        token = make_token(self.priv, not_before=now - 1200, not_after=now - 600)
        with self.assertRaises(MandateError) as ctx:
            verify_mandate(token, self.pub)
        self.assertEqual(ctx.exception.code, "expired_mandate")

    def test_not_yet_valid_fails(self):
        now = int(time.time())
        token = make_token(self.priv, not_before=now + 600, not_after=now + 1200)
        with self.assertRaises(MandateError) as ctx:
            verify_mandate(token, self.pub)
        self.assertEqual(ctx.exception.code, "expired_mandate")

    def test_wrong_merchant_fails(self):
        token = make_token(self.priv)
        with self.assertRaises(MandateError) as ctx:
            verify_mandate(token, self.pub, expected_merchant="other.example.com")
        self.assertEqual(ctx.exception.code, "wrong_binding")

    def test_amount_over_ceiling_fails(self):
        token = make_token(self.priv)
        with self.assertRaises(MandateError) as ctx:
            verify_mandate(
                token, self.pub,
                tx_amount={"currency": "USD", "value": "100.01"},
            )
        self.assertEqual(ctx.exception.code, "mandate_exceeded")

    def test_amount_equal_to_ceiling_ok(self):
        token = make_token(self.priv)
        m = verify_mandate(token, self.pub, tx_amount={"currency": "USD", "value": "100.00"})
        self.assertEqual(m["amount_ceiling"]["value"], "100.00")

    def test_currency_mismatch_fails(self):
        token = make_token(self.priv)
        with self.assertRaises(MandateError) as ctx:
            verify_mandate(token, self.pub, tx_amount={"currency": "EUR", "value": "1.00"})
        self.assertEqual(ctx.exception.code, "mandate_exceeded")

    def test_wrong_key_fails(self):
        _, other_pub = generate_ed25519_keypair()
        token = make_token(self.priv)
        with self.assertRaises(MandateError) as ctx:
            verify_mandate(token, other_pub)
        self.assertEqual(ctx.exception.code, "invalid_signature")

    def test_es256_mandate(self):
        priv, pub = generate_p256_keypair()
        token = sign_mandate(
            build_mandate(
                agent="a", merchant="m", action_category="c",
                amount_ceiling={"currency": "USD", "value": "5.00"},
                not_before=int(time.time()) - 10, not_after=int(time.time()) + 600,
                nonce="n",
            ),
            priv, alg="ES256",
        )
        m = verify_mandate(token, pub, expected_merchant="m")
        self.assertEqual(m["merchant"], "m")

    def test_bad_ceiling_rejected_at_build(self):
        with self.assertRaises(MandateError):
            build_mandate(
                agent="a", merchant="m", action_category="c",
                amount_ceiling={"currency": "USD"},  # missing value
                not_before=1, not_after=2, nonce="n",
            )

    def test_mandate_error_carries_code(self):
        err = MandateError("wrong_binding")
        self.assertEqual(err.code, "wrong_binding")
        self.assertIsInstance(err, ValueError)


if __name__ == "__main__":
    unittest.main()

"""Unit tests for x401/result.py."""

import unittest

from x401.result import ERROR_TOKENS, ResultError, make_result, parse_result


class TestMakeResult(unittest.TestCase):
    def test_minimal(self):
        r = make_result("invalid_signature")
        self.assertEqual(r, {"scheme": "x401", "version": "0.2.0", "error": "invalid_signature"})

    def test_full(self):
        r = make_result(
            "untrusted_issuer",
            description="Issuer not on the trust list.",
            error_uri="https://x401.id/spec/errors",
            request_id="r1",
        )
        self.assertEqual(r["error_description"], "Issuer not on the trust list.")
        self.assertEqual(r["error_uri"], "https://x401.id/spec/errors")
        self.assertEqual(r["request_id"], "r1")

    def test_round_trip(self):
        r = make_result("replayed_nonce", description="nonce already used", request_id="r9")
        self.assertEqual(parse_result(r), r)


class TestErrorTokens(unittest.TestCase):
    def test_standard_tokens_present(self):
        for token in (
            "invalid_request", "invalid_response", "unsupported_version",
            "unknown_nonce", "replayed_nonce", "expired_challenge",
            "invalid_signature", "untrusted_issuer", "unsatisfied_requirements",
            "wrong_binding", "expired_mandate", "tampered_mandate",
            "mandate_exceeded", "invalid_token", "token_expired",
            "ssrf_blocked", "unsupported_protocol",
        ):
            self.assertIn(token, ERROR_TOKENS, token)


class TestParseResult(unittest.TestCase):
    def test_bad_scheme(self):
        with self.assertRaises(ResultError):
            parse_result({"scheme": "x402", "version": "0.2.0", "error": "x"})

    def test_bad_version(self):
        with self.assertRaises(ResultError):
            parse_result({"scheme": "x401", "version": "0.1.0", "error": "x"})

    def test_missing_error(self):
        with self.assertRaises(ResultError):
            parse_result({"scheme": "x401", "version": "0.2.0"})

    def test_empty_error(self):
        with self.assertRaises(ResultError):
            parse_result({"scheme": "x401", "version": "0.2.0", "error": ""})

    def test_non_dict(self):
        with self.assertRaises(ResultError):
            parse_result("nope")


if __name__ == "__main__":
    unittest.main()

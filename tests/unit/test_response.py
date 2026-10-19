"""Unit tests for x401/response.py -- forms parsing + SSRF-guarded dereference."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from x401.response import ResponseError, _check_host_ips, _check_uri, dereference, parse_proof_response


class TestForms(unittest.TestCase):
    def test_inline_form(self):
        obj = {
            "request_id": "r1",
            "credential_result": {"protocol": "openid4vp-v1-signed", "data": "vp-token-here"},
        }
        out = parse_proof_response(obj)
        self.assertEqual(out["form"], "inline")
        self.assertEqual(out["request_id"], "r1")
        self.assertEqual(out["credential_result"]["protocol"], "openid4vp-v1-signed")

    def test_by_reference_form(self):
        obj = {
            "request_id": "r1",
            "credential_result_uri": "https://bank.example.com/.well-known/x401/results/abc123",
        }
        out = parse_proof_response(obj)
        self.assertEqual(out["form"], "by_reference")
        self.assertEqual(out["credential_result_uri"], obj["credential_result_uri"])

    def test_token_object_form(self):
        obj = {
            "scheme": "x401",
            "version": "0.2.0",
            "token_type": "Bearer",
            "access_token": "eyJhbGciOiJFZERTQSJ9.e30.c2ln",
        }
        out = parse_proof_response(obj)
        self.assertEqual(out["form"], "token_object")
        self.assertEqual(out["token_type"], "Bearer")

    def test_zero_forms_rejected(self):
        with self.assertRaises(ResponseError):
            parse_proof_response({"request_id": "r1"})

    def test_two_forms_rejected(self):
        obj = {
            "credential_result": {"protocol": "p", "data": "d"},
            "credential_result_uri": "https://example.com/x",
        }
        with self.assertRaises(ResponseError):
            parse_proof_response(obj)

    def test_token_object_with_result_rejected(self):
        obj = {
            "scheme": "x401",
            "version": "0.2.0",
            "token_type": "Bearer",
            "access_token": "t",
            "credential_result": {"protocol": "p", "data": "d"},
        }
        with self.assertRaises(ResponseError):
            parse_proof_response(obj)

    def test_inline_needs_protocol_and_data(self):
        with self.assertRaises(ResponseError):
            parse_proof_response({"credential_result": {"protocol": "p"}})

    def test_ref_must_be_https(self):
        with self.assertRaises(ResponseError):
            parse_proof_response({"credential_result_uri": "http://example.com/x"})

    def test_token_object_scheme_version(self):
        with self.assertRaises(ResponseError):
            parse_proof_response(
                {"scheme": "x401", "version": "0.1.0", "token_type": "Bearer", "access_token": "t"}
            )

    def test_non_dict_rejected(self):
        with self.assertRaises(ResponseError):
            parse_proof_response(["x"])


class TestURIAndHostGuards(unittest.TestCase):
    def test_non_https_rejected(self):
        with self.assertRaises(ResponseError) as ctx:
            _check_uri("http://example.com/x", "http://example.com/")
        self.assertEqual(ctx.exception.code, "ssrf_blocked")

    def test_prefix_mismatch_rejected(self):
        with self.assertRaises(ResponseError) as ctx:
            _check_uri("https://evil.example/x", "https://bank.example.com/results/")
        self.assertEqual(ctx.exception.code, "ssrf_blocked")

    def test_prefix_match_ok(self):
        _check_uri("https://bank.example.com/results/abc", "https://bank.example.com/results/")

    def test_private_ips_blocked(self):
        for host in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.5",
                     "169.254.169.254", "224.0.0.1", "::1", "0.0.0.0"):
            with self.assertRaises(ResponseError, msg=host) as ctx:
                _check_host_ips(host)
            self.assertEqual(ctx.exception.code, "ssrf_blocked")

    def test_unresolvable_blocked(self):
        with self.assertRaises(ResponseError) as ctx:
            _check_host_ips("nonexistent.invalid")
        self.assertEqual(ctx.exception.code, "ssrf_blocked")


class _Handler(BaseHTTPRequestHandler):
    mode = "ok"

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "/elsewhere")
            self.end_headers()
        elif self.mode == "big":
            body = b"x" * 70000
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.mode == "notjson":
            body = b"not json"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = json.dumps({"credential_result": {"protocol": "p", "data": "d"}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


class TestDereference(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()

    def url(self, path="/result"):
        return f"http://127.0.0.1:{self.port}{path}"

    def public_dns(self):
        # Guard sees a public IP; the real connection still goes to 127.0.0.1
        # because urllib resolves the host itself.
        patcher = mock.patch("x401.response.socket")
        msock = patcher.start()
        self.addCleanup(patcher.stop)
        msock.getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
        return msock

    def test_success(self):
        self.public_dns()
        _Handler.mode = "ok"
        out = dereference(self.url(), allowed_prefix=self.url("/"), _allow_http=True)
        self.assertEqual(out["credential_result"]["data"], "d")

    def test_prefix_mismatch(self):
        self.public_dns()
        with self.assertRaises(ResponseError) as ctx:
            dereference(self.url(), allowed_prefix="https://bank.example.com/", _allow_http=True)
        self.assertEqual(ctx.exception.code, "ssrf_blocked")

    def test_http_blocked_without_hook(self):
        with self.assertRaises(ResponseError) as ctx:
            dereference(self.url(), allowed_prefix=self.url("/"))
        self.assertEqual(ctx.exception.code, "ssrf_blocked")

    def test_redirect_not_followed(self):
        self.public_dns()
        _Handler.mode = "redirect"
        try:
            with self.assertRaises(ResponseError) as ctx:
                dereference(self.url(), allowed_prefix=self.url("/"), _allow_http=True)
            self.assertEqual(ctx.exception.code, "redirect_blocked")
        finally:
            _Handler.mode = "ok"

    def test_too_large(self):
        self.public_dns()
        _Handler.mode = "big"
        try:
            with self.assertRaises(ResponseError) as ctx:
                dereference(self.url(), allowed_prefix=self.url("/"), _allow_http=True,
                            max_bytes=65536)
            self.assertEqual(ctx.exception.code, "too_large")
        finally:
            _Handler.mode = "ok"

    def test_non_json_rejected(self):
        self.public_dns()
        _Handler.mode = "notjson"
        try:
            with self.assertRaises(ResponseError) as ctx:
                dereference(self.url(), allowed_prefix=self.url("/"), _allow_http=True)
            self.assertEqual(ctx.exception.code, "invalid_response")
        finally:
            _Handler.mode = "ok"

    def test_private_host_blocked_end_to_end(self):
        # No DNS mock: 127.0.0.1 resolves to itself -> blocked.
        with self.assertRaises(ResponseError) as ctx:
            dereference(self.url(), allowed_prefix=self.url("/"), _allow_http=True)
        self.assertEqual(ctx.exception.code, "ssrf_blocked")


if __name__ == "__main__":
    unittest.main()

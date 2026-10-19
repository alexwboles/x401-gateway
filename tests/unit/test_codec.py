"""Unit tests for x401/codec.py -- strict wire encoding."""

import base64
import json
import unittest

from x401.codec import (
    CodecError,
    decode_payload,
    emit_header,
    encode_payload,
    parse_header,
)


class TestEncodeDecode(unittest.TestCase):
    def test_round_trip(self):
        obj = {"scheme": "x401", "version": "0.2.0", "b": [1, 2], "a": "x"}
        s = encode_payload(obj)
        self.assertNotIn("=", s)
        self.assertEqual(decode_payload(s), obj)

    def test_canonical_form(self):
        # sorted keys, compact separators
        self.assertEqual(encode_payload({"b": 1, "a": 2}), encode_payload({"a": 2, "b": 1}))
        raw = base64.urlsafe_b64decode(encode_payload({"b": 1}) + "==")
        self.assertEqual(raw, b'{"b":1}')

    def test_no_padding_emitted(self):
        # payloads whose raw length is not a multiple of 3 must have no '='
        for obj in ({"a": "x"}, {"a": "xy"}, {"a": "xyz"}, {"a": "xyzw"}):
            self.assertNotIn("=", encode_payload(obj))

    def test_encode_rejects_non_dict(self):
        for bad in (["a"], "str", 42, None):
            with self.assertRaises(CodecError):
                encode_payload(bad)

    def test_padding_rejected(self):
        s = encode_payload({"a": 1})
        with self.assertRaises(CodecError):
            decode_payload(s + "=")
        with self.assertRaises(CodecError):
            decode_payload("=abc")

    def test_multiline_rejected(self):
        s = encode_payload({"a": 1})
        half = len(s) // 2
        with self.assertRaises(CodecError):
            decode_payload(s[:half] + "\n" + s[half:])
        with self.assertRaises(CodecError):
            decode_payload(s + "\r\n")

    def test_whitespace_rejected(self):
        with self.assertRaises(CodecError):
            decode_payload(" " + encode_payload({"a": 1}))
        with self.assertRaises(CodecError):
            decode_payload(encode_payload({"a": 1}) + "\t")

    def test_comma_rejected(self):
        s = encode_payload({"a": 1})
        with self.assertRaises(CodecError):
            decode_payload(s + "," + s)

    def test_bad_alphabet_rejected(self):
        with self.assertRaises(CodecError):
            decode_payload("!!!not-base64!!!")
        with self.assertRaises(CodecError):
            decode_payload("abc+def")  # '+' is not base64url

    def test_non_object_json_rejected(self):
        for obj in ([1, 2], "str", 42):
            raw = base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
            with self.assertRaises(CodecError):
                decode_payload(raw)

    def test_bad_length_rejected(self):
        with self.assertRaises(CodecError):
            decode_payload("a")  # len % 4 == 1 is impossible

    def test_non_utf8_rejected(self):
        raw = base64.urlsafe_b64encode(b"\xff\xfe binary").decode().rstrip("=")
        with self.assertRaises(CodecError):
            decode_payload(raw)

    def test_empty_rejected(self):
        with self.assertRaises(CodecError):
            decode_payload("")
        with self.assertRaises(CodecError):
            decode_payload(None)


class TestParseHeader(unittest.TestCase):
    def setUp(self):
        self.obj = {"scheme": "x401", "version": "0.2.0"}
        self.value = encode_payload(self.obj)

    def test_case_insensitive_lookup(self):
        for name in ("PROOF-REQUEST", "proof-request", "Proof-Request", "pRoOf-ReQuEsT"):
            headers = {name: self.value}
            self.assertEqual(parse_header(headers, "PROOF-REQUEST"), self.obj)

    def test_missing_header(self):
        with self.assertRaises(CodecError):
            parse_header({}, "PROOF-REQUEST")

    def test_comma_joined_rejected(self):
        headers = {"PROOF-REQUEST": self.value + "," + self.value}
        with self.assertRaises(CodecError):
            parse_header(headers, "PROOF-REQUEST")

    def test_multiline_rejected(self):
        headers = {"PROOF-REQUEST": self.value + "\n" + self.value}
        with self.assertRaises(CodecError):
            parse_header(headers, "PROOF-REQUEST")

    def test_multiple_values_rejected(self):
        headers = {"PROOF-REQUEST": [self.value, self.value]}
        with self.assertRaises(CodecError):
            parse_header(headers, "PROOF-REQUEST")

    def test_non_string_value_rejected(self):
        with self.assertRaises(CodecError):
            parse_header({"PROOF-REQUEST": 42}, "PROOF-REQUEST")

    def test_emit_header(self):
        name, value = emit_header("PROOF-REQUEST", self.obj)
        self.assertEqual(name, "PROOF-REQUEST")
        self.assertEqual(decode_payload(value), self.obj)


if __name__ == "__main__":
    unittest.main()

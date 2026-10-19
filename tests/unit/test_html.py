"""Unit tests for x401/html.py -- the <data> embed mirror."""

import json
import unittest

from x401.html import SCHEMA_URL, embed_html


class TestEmbedHtml(unittest.TestCase):
    def test_structure(self):
        payload = {"scheme": "x401", "version": "0.2.0"}
        html = embed_html(payload)
        self.assertTrue(html.startswith('<data value="application/json;x401=proof-required" hidden>'))
        self.assertTrue(html.endswith("</data>"))

    def test_contains_unencoded_json_plus_schema(self):
        payload = {
            "scheme": "x401",
            "version": "0.2.0",
            "credential_requirements": {"digital": {"requests": []}},
        }
        html = embed_html(payload)
        inner = html.split(">", 1)[1].rsplit("<", 1)[0]
        obj = json.loads(inner)
        self.assertEqual(obj["scheme"], "x401")
        self.assertEqual(obj["credential_requirements"], payload["credential_requirements"])
        self.assertEqual(obj["$schema"], SCHEMA_URL)
        self.assertEqual(obj["$schema"], "https://x401.id/spec/schemas/request.json")

    def test_cannot_break_out_of_element(self):
        payload = {"note": "</data><script>alert(1)</script>", "x": "a&b"}
        html = embed_html(payload)
        # Only the one legitimate closing </data> may appear.
        self.assertEqual(html.count("</data>"), 1)
        self.assertNotIn("<script>", html)
        # And the JSON still parses back to the original values.
        inner = html.split(">", 1)[1].rsplit("<", 1)[0]
        obj = json.loads(inner)
        self.assertEqual(obj["note"], "</data><script>alert(1)</script>")
        self.assertEqual(obj["x"], "a&b")

    def test_rejects_non_dict(self):
        with self.assertRaises(ValueError):
            embed_html(["x"])


if __name__ == "__main__":
    unittest.main()

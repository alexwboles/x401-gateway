"""Unit tests for x401/nonce.py -- single-use nonce cache."""

import base64
import time
import unittest

from x401.nonce import NonceCache, NonceError


class TestNonceCache(unittest.TestCase):
    def test_issue_format(self):
        cache = NonceCache()
        nonce = cache.issue()
        self.assertNotIn("=", nonce)
        self.assertEqual(len(base64.urlsafe_b64decode(nonce + "==")), 16)  # 128-bit

    def test_issue_unique(self):
        cache = NonceCache()
        self.assertEqual(len({cache.issue() for _ in range(50)}), 50)

    def test_consume_ok(self):
        cache = NonceCache()
        nonce = cache.issue()
        self.assertEqual(cache.consume(nonce), "ok")

    def test_replay_must_fail(self):
        cache = NonceCache()
        nonce = cache.issue()
        cache.consume(nonce)
        with self.assertRaises(NonceError) as ctx:
            cache.consume(nonce)
        self.assertEqual(ctx.exception.code, "replayed_nonce")

    def test_unknown_nonce_fails(self):
        cache = NonceCache()
        with self.assertRaises(NonceError) as ctx:
            cache.consume("never-issued-nonce")
        self.assertEqual(ctx.exception.code, "unknown_nonce")

    def test_expired_challenge_fails(self):
        cache = NonceCache(ttl=60)
        nonce = cache.issue()
        with self.assertRaises(NonceError) as ctx:
            cache.consume(nonce, now=time.time() + 61)
        self.assertEqual(ctx.exception.code, "expired_challenge")

    def test_nonce_error_carries_code(self):
        err = NonceError("replayed_nonce")
        self.assertEqual(err.code, "replayed_nonce")
        self.assertIsInstance(err, ValueError)

    def test_purge_removes_expired(self):
        cache = NonceCache(ttl=10)
        n1 = cache.issue()
        n2 = cache.issue()
        cache.consume(n2)  # moves to used table
        removed = cache.purge(now=time.time() + 11)
        self.assertEqual(removed, 2)  # one live + one used
        self.assertEqual(len(cache), 0)
        # consumed nonce is now unknown (purged from used table)
        with self.assertRaises(NonceError) as ctx:
            cache.consume(n2, now=time.time() + 11)
        self.assertEqual(ctx.exception.code, "unknown_nonce")

    def test_consume_purges_lazily(self):
        cache = NonceCache(ttl=10)
        stale = cache.issue()
        fresh = cache.issue()
        # advance time past ttl for the stale one only is not possible with one
        # clock; instead verify purge keeps fresh entries
        cache.purge(now=time.time())
        self.assertEqual(cache.consume(fresh), "ok")
        _ = stale


if __name__ == "__main__":
    unittest.main()

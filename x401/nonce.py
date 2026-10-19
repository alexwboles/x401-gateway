"""Single-use nonce cache for replay protection.

The spec grades replay protection as SHOULD; this gateway enforces it as MUST:
every issued nonce is single-use and short-lived. ``consume`` distinguishes
unknown / replayed / expired nonces with dedicated codes.
"""

from __future__ import annotations

import base64
import secrets
import time

__all__ = ["NonceError", "NonceCache"]


class NonceError(ValueError):
    """Raised by NonceCache.consume; carries a machine-readable ``.code``."""

    def __init__(self, code: str, message: str | None = None):
        self.code = code
        super().__init__(message or code)


class NonceCache:
    """Issue and single-use-consume 128-bit nonces."""

    def __init__(self, ttl: int = 300):
        self.ttl = ttl
        self._live: dict[str, float] = {}  # nonce -> expires_at
        self._used: dict[str, float] = {}  # consumed nonces -> expires_at (for replay detection)

    def issue(self) -> str:
        """Create a fresh 128-bit base64url nonce and record it with an expiry."""
        nonce = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")
        self._live[nonce] = time.time() + self.ttl
        return nonce

    def consume(self, nonce: str, *, now: float | None = None) -> str:
        """Consume a nonce exactly once.

        Returns 'ok'. Raises NonceError('replayed_nonce') if already consumed,
        NonceError('expired_challenge') if past expiry, NonceError('unknown_nonce')
        if never issued. Purges expired entries on each call.
        """
        now = time.time() if now is None else now
        if nonce in self._used:
            raise NonceError("replayed_nonce", "nonce has already been consumed")
        expires_at = self._live.get(nonce)
        if expires_at is None:
            self.purge(now=now)
            raise NonceError("unknown_nonce", "nonce was never issued")
        if now >= expires_at:
            del self._live[nonce]
            self.purge(now=now)
            raise NonceError("expired_challenge", "nonce has expired")
        del self._live[nonce]
        self._used[nonce] = expires_at
        self.purge(now=now)
        return "ok"

    def purge(self, *, now: float | None = None) -> int:
        """Drop expired entries from both tables; return the number removed."""
        now = time.time() if now is None else now
        removed = 0
        for table in (self._live, self._used):
            for nonce in [n for n, exp in table.items() if now >= exp]:
                del table[nonce]
                removed += 1
        return removed

    def __len__(self) -> int:
        return len(self._live)

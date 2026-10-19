"""Fallback ``x401.nonce`` — single-use nonce replay cache."""

import secrets
import time

from .codec import b64u_encode

__all__ = ["NonceError", "NonceCache"]


class NonceError(Exception):
    """Nonce validation failure; ``code`` is one of the x401 error tokens."""

    def __init__(self, code: str, description: str = ""):
        super().__init__(description or code)
        self.code = code


class NonceCache:
    """Issue fresh 128-bit nonces; ``consume`` enforces single use + expiry.

    Only a fully-validated proof burns its nonce (see demo/merchant.py): failed
    validations leave the nonce live so the agent can retry with a corrected proof.
    """

    def __init__(self, ttl: int = 300, default_ttl: int | None = None):
        # Accepts both the delivered signature (ttl) and the brief's
        # (default_ttl) so demo code can call either.
        self.default_ttl = default_ttl if default_ttl is not None else ttl
        self._entries: dict[str, dict] = {}

    def issue(self, ttl: int | None = None) -> str:
        """Issue a fresh nonce valid for ``ttl`` seconds."""
        ttl = self.default_ttl if ttl is None else ttl
        nonce = b64u_encode(secrets.token_bytes(16))
        self._entries[nonce] = {"exp": time.time() + ttl, "used": False}
        return nonce

    def consume(self, nonce: str) -> dict:
        """Mark a nonce used; raises :class:`NonceError` on unknown/replay/expiry."""
        entry = self._entries.get(nonce)
        if entry is None:
            raise NonceError("unknown_nonce", "nonce was not issued by this verifier")
        if entry["used"]:
            raise NonceError("replayed_nonce", "nonce has already been consumed")
        if time.time() > entry["exp"]:
            del self._entries[nonce]
            raise NonceError("expired_challenge", "challenge expired before use")
        entry["used"] = True
        return {"exp": entry["exp"]}

    def purge(self) -> int:
        """Drop expired entries; returns the number removed."""
        now = time.time()
        expired = [n for n, e in self._entries.items() if now > e["exp"]]
        for n in expired:
            del self._entries[n]
        return len(expired)

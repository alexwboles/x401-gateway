"""Fallback ``x401.trust`` — operator-owned local trust list.

This is the gateway's answer to trust centralization: instead of inheriting a
curated registry, the operator explicitly lists the issuers (and device keys) they
trust. Self-issued credentials are first-class — add the holder's own device key.
"""

__all__ = ["TrustList"]


class TrustList:
    """Maps issuer ids to their trusted public keys (optionally per key id)."""

    def __init__(self):
        self._issuers: dict[str, dict] = {}

    def add_issuer(self, issuer_id: str, public_key, key_id: str | None = None):
        """Trust ``public_key`` for ``issuer_id`` (optionally under ``key_id``)."""
        self._issuers.setdefault(issuer_id, {})[key_id or ""] = public_key
        return self

    def is_trusted(self, issuer_id: str) -> bool:
        return issuer_id in self._issuers

    def find_key(self, issuer_id: str | None = None, key_id: str | None = None):
        """Resolve a verification key by issuer and/or key id; None if untrusted."""
        if issuer_id is not None:
            keys = self._issuers.get(issuer_id)
            if not keys:
                return None
            if key_id in keys:
                return keys[key_id]
            if len(keys) == 1:
                return next(iter(keys.values()))
            return None
        if key_id is not None:
            for keys in self._issuers.values():
                if key_id in keys:
                    return keys[key_id]
        return None

    def issuers(self) -> list:
        return list(self._issuers)

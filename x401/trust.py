"""Operator-owned issuer trust list + DCQL satisfaction checking.

Default posture: the list starts EMPTY and only trusts explicitly added
issuers (self-hosted / self-issued credentials are first-class here -- this is
the gateway's differentiation from registry-anchored deployments).
"""

from __future__ import annotations

import json

__all__ = ["TrustList", "default_self_issued_only"]


def _walk_path(root: dict, path: list) -> tuple[bool, object]:
    """Navigate a claim path (list of str keys / int indexes) from root."""
    node: object = root
    for step in path:
        if isinstance(node, dict) and isinstance(step, str):
            if step not in node:
                return False, None
            node = node[step]
        elif isinstance(node, list) and isinstance(step, int):
            if step < 0 or step >= len(node):
                return False, None
            node = node[step]
        else:
            return False, None
    return True, node


def _credential_types(cred: dict) -> list[str]:
    """Collect type names from common VC shapes (jwt_vc_json, sd-jwt disclosures)."""
    types: list[str] = []
    for candidate in (
        cred.get("type"),
        cred.get("vc", {}).get("type") if isinstance(cred.get("vc"), dict) else None,
        cred.get("types"),
    ):
        if isinstance(candidate, str):
            types.append(candidate)
        elif isinstance(candidate, list):
            types.extend(t for t in candidate if isinstance(t, str))
    return types


def _claim_root(cred: dict) -> dict:
    """The object claim paths are evaluated against (credentialSubject when present)."""
    subject = cred.get("credentialSubject")
    return subject if isinstance(subject, dict) else cred


class TrustList:
    """Operator-owned trust list: entries are dicts, persisted as JSON."""

    def __init__(self):
        self._issuers: dict[str, dict] = {}

    # -- issuer management -------------------------------------------------
    def add_issuer(self, issuer_id: str, public_key_jwk: dict, assurance_levels: list[str] | None = None) -> None:
        if not issuer_id or not isinstance(public_key_jwk, dict):
            raise ValueError("issuer_id and public_key_jwk (dict) are required")
        self._issuers[issuer_id] = {
            "issuer_id": issuer_id,
            "public_key_jwk": public_key_jwk,
            "assurance_levels": list(assurance_levels) if assurance_levels else [],
        }

    def remove_issuer(self, issuer_id: str) -> bool:
        return self._issuers.pop(issuer_id, None) is not None

    def load(self, path: str) -> None:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        entries = data.get("issuers", []) if isinstance(data, dict) else []
        self._issuers = {}
        for entry in entries:
            if isinstance(entry, dict) and entry.get("issuer_id"):
                self._issuers[entry["issuer_id"]] = entry

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"issuers": list(self._issuers.values())}, fh, indent=2, sort_keys=True)

    # -- trust decisions ---------------------------------------------------
    def is_trusted(self, issuer_id: str, assurance: str | None = None) -> bool:
        entry = self._issuers.get(issuer_id)
        if entry is None:
            return False
        if assurance is None:
            return True
        levels = entry.get("assurance_levels") or []
        return assurance in levels

    # -- DCQL satisfaction -------------------------------------------------
    def satisfies(self, dcql: dict, credentials: list[dict]) -> tuple[bool, dict]:
        """Check each DCQL credential entry against the presented credentials.

        For each entry: ``format`` must match the credential's format,
        ``meta.type_values`` must all appear in the credential's types, and each
        ``claims`` entry's ``path``/``values`` must match against the
        credentialSubject. Returns (all_satisfied, details_by_entry_id).
        """
        if not isinstance(dcql, dict):
            raise ValueError("dcql must be a dict")
        entries = dcql.get("credentials", [])
        details: dict = {}
        all_ok = True
        for entry in entries:
            entry_id = entry.get("id", "?") if isinstance(entry, dict) else "?"
            ok, matched = self._match_entry(entry if isinstance(entry, dict) else {}, credentials or [])
            details[entry_id] = {"satisfied": ok, "matched_credential": matched}
            if not ok:
                all_ok = False
        return all_ok, details

    def _match_entry(self, entry: dict, credentials: list[dict]) -> tuple[bool, str | None]:
        want_format = entry.get("format")
        want_types = (entry.get("meta") or {}).get("type_values", []) if isinstance(entry.get("meta"), dict) else []
        want_claims = entry.get("claims", []) or []
        for cred in credentials:
            if not isinstance(cred, dict):
                continue
            if want_format and cred.get("format") != want_format:
                continue
            have_types = _credential_types(cred)
            if any(t not in have_types for t in want_types):
                continue
            root = cred
            claims_ok = True
            for claim in want_claims:
                path = claim.get("path", [])
                values = claim.get("values", [])
                found, value = _walk_path(root, path)
                if not found:
                    claims_ok = False
                    break
                if values and value not in values:
                    claims_ok = False
                    break
            if claims_ok:
                return True, cred.get("id")
        return False, None

    # NOTE: DCQL claim paths (e.g. ["credentialSubject", "assurance_level"]) are
    # evaluated from the credential root. _claim_root() is kept for callers
    # that need the subject object directly.


def default_self_issued_only() -> TrustList:
    """Return an empty operator-owned trust list.

    Nothing is trusted until the operator explicitly calls ``add_issuer`` --
    self-hosted / self-issued issuers are first-class; no external registry is
    consulted.
    """
    return TrustList()

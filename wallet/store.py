"""Holder credential store: a JSON file of the person's credentials.

Credential shape::

    {"id": "cred-...", "type": "IdentityCredential",
     "issuer": "did:example:alex", "subject": "did:example:alex",
     "claims": {"given_name": ..., ...}, "added_at": "<iso8601>"}

Thread-safe; atomic writes (write-temp-then-rename).
"""

from __future__ import annotations

import json
import os
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class CredentialStore:
    """JSON-file store for holder credentials."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._creds: list[dict] = []
        self._load()

    # -- persistence ------------------------------------------------------
    def _load(self) -> None:
        with self._lock:
            if self.path.exists():
                try:
                    data = json.loads(self.path.read_text(encoding="utf-8"))
                    creds = data.get("credentials", []) if isinstance(data, dict) else []
                    self._creds = [c for c in creds if isinstance(c, dict)]
                except (json.JSONDecodeError, OSError):
                    self._creds = []
            else:
                self._creds = []

    def _save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"credentials": self._creds}, indent=2,
                                      ensure_ascii=False) + "\n",
                           encoding="utf-8")
            os.replace(tmp, self.path)

    # -- CRUD -------------------------------------------------------------
    def add_credential(self, cred: dict) -> str:
        """Add a credential dict; returns its id (generated if missing)."""
        if not isinstance(cred, dict):
            raise TypeError("credential must be a dict")
        with self._lock:
            record = dict(cred)
            record.setdefault("id", "cred-" + secrets.token_urlsafe(8))
            record.setdefault("added_at", _utcnow_iso())
            record.setdefault("claims", {})
            # replace on id collision, else append
            self._creds = [c for c in self._creds if c.get("id") != record["id"]]
            self._creds.append(record)
            self._save()
            return record["id"]

    def list_credentials(self) -> list[dict]:
        with self._lock:
            return [dict(c) for c in self._creds]

    def get_credential(self, cred_id: str) -> dict | None:
        with self._lock:
            for c in self._creds:
                if c.get("id") == cred_id:
                    return dict(c)
            return None

    def delete_credential(self, cred_id: str) -> bool:
        with self._lock:
            before = len(self._creds)
            self._creds = [c for c in self._creds if c.get("id") != cred_id]
            if len(self._creds) == before:
                return False
            self._save()
            return True


def seed_demo_credential(store: CredentialStore,
                         subject: str = "did:example:alex") -> dict:
    """Add a self-issued demo IdentityCredential for trying the flow."""
    cred = {
        "type": "IdentityCredential",
        "issuer": subject,  # self-issued: no commercial CA involved
        "subject": subject,
        "claims": {
            "given_name": "Alex",
            "family_name": "Demo",
            "assurance_level": "SELF-ATTESTED",
            "note": "Demo credential issued by the wallet itself. "
                    "Replace with a real issuer credential for production use.",
        },
    }
    cred_id = store.add_credential(cred)
    return store.get_credential(cred_id)

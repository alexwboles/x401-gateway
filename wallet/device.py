"""Per-device approval key.

This is the self-hosted stand-in for Proof's "biometric + hardware-protected
key": one Ed25519 keypair generated on the device that runs the wallet.  The
private key never leaves this device (it lives in the wallet data dir); the
public JWK is what mandate signatures are verified against.

Upgrade path: replace ``DeviceKey.sign`` with a WebAuthn/passkey assertion
over the mandate hash (challenge = mandate hash + verifier id + nonce).
See docs/WALLET.md for details.
"""

from __future__ import annotations

import json
import os
import stat
import threading
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from wallet import _compat as x


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class DeviceKey:
    """The device's Ed25519 approval key, persisted in the wallet data dir."""

    FILENAME = "device.json"

    def __init__(self, data_dir: str | Path, label: str = "Primary device"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.data_dir / self.FILENAME
        self._lock = threading.RLock()
        if self.path.exists():
            self._load()
        else:
            self._create(label)

    # -- persistence ------------------------------------------------------
    def _create(self, label: str) -> None:
        with self._lock:
            private_key, public_jwk = x.generate_keypair()
            self._label = label
            self._created_at = _utcnow_iso()
            self._kid = x.key_id(public_jwk)
            self._public_jwk = public_jwk
            # Private material: raw 32-byte seed, base64url.  File is 0600.
            # This is the software stand-in for a hardware enclave key --
            # see docs/WALLET.md ("WebAuthn/passkey upgrade path").
            seed = x.b64u_encode(
                private_key.private_bytes(
                    Encoding.Raw, PrivateFormat.Raw, NoEncryption()
                )
            )
            payload = {
                "label": self._label,
                "created_at": self._created_at,
                "kid": self._kid,
                "public_jwk": self._public_jwk,
                "private_seed_b64": seed,
                "note": "Device approval key. The private seed never leaves "
                        "this device. Back it up like a password manager "
                        "vault; anyone with this file can sign mandates as you.",
            }
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
            os.replace(tmp, self.path)
            os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
            self._private_key = private_key

    def _load(self) -> None:
        with self._lock:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            self._label = payload["label"]
            self._created_at = payload["created_at"]
            self._kid = payload["kid"]
            self._public_jwk = payload["public_jwk"]
            self._private_key = x.normalize_private_key(payload["private_seed_b64"])
            # keep file permissions tight even if the file was copied in
            try:
                os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass

    # -- public surface ---------------------------------------------------
    @property
    def label(self) -> str:
        return self._label

    @property
    def created_at(self) -> str:
        return self._created_at

    @property
    def kid(self) -> str:
        """Stable key id (fingerprint of the public key)."""
        return self._kid

    @property
    def public_jwk(self) -> dict:
        return dict(self._public_jwk)

    @property
    def private_key(self):
        """The Ed25519 private key object (for mandate signing)."""
        return self._private_key

    def sign(self, data: bytes) -> bytes:
        """Sign raw bytes with the device key."""
        with self._lock:
            return self._private_key.sign(data)

    def info(self) -> dict:
        return {
            "label": self._label,
            "created_at": self._created_at,
            "kid": self._kid,
            "public_jwk": self.public_jwk,
        }

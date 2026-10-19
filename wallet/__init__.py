"""x401 self-hosted identity wallet (holder side).

The holder-side half of the x401 loop: software that lets a person hold
credentials, see exactly what an agent is asking for, and approve or deny on
their own device — no commercial provider involved.

Modules:
    store   -- JSON-file credential store (holder's credentials).
    device  -- per-device Ed25519 approval key (self-hosted stand-in for a
               biometric + hardware key; see docs/WALLET.md for the
               WebAuthn/passkey upgrade path).
    service -- stdlib-only HTTP service: approval queue, person-facing
               approval page, mandate signing, return_uri relay.
    _compat -- defensive interop with the sibling ``x401`` package (built in
               parallel); local fallbacks when it is absent.
"""

__version__ = "0.1.0"

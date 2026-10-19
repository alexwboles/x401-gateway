# x401 Wallet — self-hosted holder-side wallet

The holder side of x401: software that lets a **person** hold credentials, see
exactly what an agent is being asked to do, and approve or deny on their own
device — with no commercial provider in the loop.

This is the gap in the ecosystem: free/open **verifier-side** x401 code exists,
but every wallet/approval surface is a commercial product (Proof's Digital ID
cloud wallet, Superfluid Wallet). This wallet is the free, self-hosted
equivalent of that holder side.

## What it is

- **Credential store** (`wallet/store.py`): a JSON file of the holder's
  credentials (`wallet-data/credentials.json`). Nothing leaves the device
  except mandates the person explicitly approves.
- **Device approval key** (`wallet/device.py`): a per-device Ed25519 keypair
  generated on first run and persisted in the wallet data dir
  (`wallet-data/device.json`, mode `0600`). The private key never leaves the
  device running the wallet.
- **Approval service** (`wallet/service.py`): a stdlib-only HTTP server
  (`http.server.ThreadingHTTPServer`, no framework). Agents POST proof
  requests; the person approves on a person-facing page; the wallet signs a
  **scoped mandate** and the agent polls for the result.

## Quickstart

```bash
cd ~/workspace/x401-gateway
python3 -m wallet.service
# x401 wallet listening on http://127.0.0.1:8765/
```

Open `http://127.0.0.1:8765/` — the wallet home shows the device key, the
credential list, the pending approval queue, and a curl example for agents.

Try the full loop (second terminal):

```bash
# 1. Agent submits a proof request + human-readable terms
curl -s -X POST http://127.0.0.1:8765/api/requests \
  -H 'Content-Type: application/json' -d '{
    "proof_request": {"scheme": "x401", "version": "0.2.0",
      "credential_requirements": {"digital": {"requests": []}}},
    "terms": {"merchant_display": "Acme Bank",
              "action_category": "purchase",
              "amount_ceiling": {"currency": "USD", "value": "250.00"},
              "expires_in": 600}
  }'
# -> {"approval_id": "appr-...", "approval_url": "http://.../approve/appr-...",
#     "qr_text": "http://.../approve/appr-...", ...}

# 2. Person opens the approval_url (or scans the QR), reviews, approves.

# 3. Agent polls for the signed mandate
curl -s http://127.0.0.1:8765/api/status/appr-... | python3 -m json.tool
# -> {"status": "approved",
#     "proof_response": {"request_id": ...,
#       "credential_result": {"protocol": "x-x401ext-mandate/v1",
#                             "data": "<JWS>"}}}
```

Environment overrides:

| Variable           | Default          | Meaning                          |
|--------------------|------------------|----------------------------------|
| `X401_WALLET_DIR`  | `./wallet-data`  | data directory (device key + credentials) |
| `X401_WALLET_HOST` | `127.0.0.1`      | bind host                        |
| `X401_WALLET_PORT` | `8765`           | bind port                        |

## Device registration

There is no enrollment server and no account. The first run generates the
device key automatically:

```
wallet-data/
  device.json        # label, created_at, kid, public JWK, private seed (0600)
  credentials.json   # holder credentials
```

The `kid` (key id) is the first 96 bits of SHA-256 over the public key,
base64url-encoded — a stable fingerprint shown in the UI and the JWS header.
Treat `device.json` like a password-manager vault: anyone holding it can sign
mandates as you. Back it up; don't copy it to machines you don't control.

## The approval flow

1. **Submit** — `POST /api/requests` with `{"proof_request": {...}, "terms":
   {...}}`. Terms not supplied explicitly default from the proof request where
   sensible (`merchant_display`, `action_category`, `amount_ceiling`,
   `agent`). The wallet immediately fixes the **exact mandate claims** to be
   signed (including a fresh anti-replay nonce and the validity window), so
   the person sees precisely what their key will sign — the SIWE property.
   Returns `approval_id`, absolute `approval_url` (from the `Host` header),
   `qr_text` (the same URL), and `expires_at`.
2. **Review** — `GET /approve/<id>` renders the person-facing page: who is
   asking (merchant display name + verifier `client_id`), what is requested
   (action category, amount ceiling, time window, agent id), a collapsible
   **"Exact signed terms"** block showing the canonical JSON byte-for-byte,
   an expiry countdown, big Approve / Deny buttons, and a QR panel for
   approving on a second device (the RFC 8628 device-grant shape: the agent
   shows the code/URL, the person approves on their own device).
3. **Decide** — `POST /api/approve/<id>` with `{"decision":
   "approve"|"deny"}`. On approve, the wallet signs the pre-fixed mandate
   claims with the device key (JWS compact, EdDSA) and stores
   `{"protocol": "x-x401ext-mandate/v1", "data": <JWS>}` as the
   `credential_result`. On deny, the denial is recorded and nothing is signed.
   Expired approvals return `410`.
4. **Collect** — `GET /api/status/<id>` returns `pending | approved | denied |
   expired`; when approved it includes the `proof_response`
   (`request_id` + `credential_result`), which the agent forwards as the
   x401 `PROOF-RESPONSE` result artifact.

## Credential management

Credentials are managed in `wallet/store.py` (`CredentialStore`) and surfaced
on the wallet home page:

- `add_credential(cred)` / `list_credentials()` / `get_credential(id)` /
  `delete_credential(id)` — credential shape is `{"id", "type", "issuer",
  "subject", "claims": {...}, "added_at"}`.
- `seed_demo_credential()` adds a self-issued demo `IdentityCredential`
  (also available as the "Seed demo credential" button on the home page).

## The `return_uri` relay

Per the x401 v0.2.0 wire spec, a relaying intermediary may attach a
`return_uri` to the proof request — an `https` URL the remote handler POSTs
the `{protocol, data}` credential result to. If the submitted proof request
contains an `https` `return_uri`, the wallet POSTs the credential result to
it **after** approval, best-effort (5 s timeout, failures logged and ignored,
sent on a background thread so approval never blocks). Non-`https` values
are ignored and logged.

## The scoped mandate (extension)

x401 v0.2.0 standardizes the verifier↔agent wire but **not** the mandate
credential schema (delegation is an open question in the spec). This wallet
defines its own profile and marks it an `x-` extension:

- **Type:** `x-x401ext-mandate/v1`
- **Claims:** `type`, `iss` (wallet device id), `agent`, `merchant`,
  `action_category`, `amount_ceiling` (`currency`, `value` as a string —
  no float rounding), `not_before` / `not_after` (unix seconds), `nonce`
  (fresh per mandate), optional `request_id` echo.
- **Serialization:** canonical JSON (`sort_keys`, compact separators),
  JWS compact serialization with `alg: EdDSA`, `kid` in the header.
- **Verification:** signature over the exact bytes shown to the person —
  flipping a single character (e.g. in the amount) fails verification; the
  verifier also checks the type tag and the validity window.

See `wallet/_compat.py` for the build/sign/verify implementation, which
prefers the sibling `x401` package's `x401.mandate` API when importable and
falls back to the local implementation otherwise.

## Security notes

- **Device key custody.** The private seed sits in `device.json` (0600) on
  the machine running the wallet. That machine *is* the hardware boundary:
  run the wallet on the person's own device, not on shared infrastructure.
  Anyone with the file can sign mandates as the holder.
- **WebAuthn/passkey upgrade path.** The current software key is the
  stand-in for Proof's biometric + hardware-protected key. The upgrade is to
  replace `DeviceKey.sign` with a WebAuthn/passkey assertion: the platform
  authenticator (Touch ID / Face ID / Windows Hello) holds a device-bound key
  whose private half never leaves the secure enclave, and the assertion is
  computed over `SHA-256(canonical mandate) ‖ verifier id ‖ nonce` as the
  challenge — giving phishing-resistant, biometric-gated approval with no new
  hardware and no PKI to run. The mandate format needs no change: only the
  signer changes.
- **Approval expiry.** Pending approvals expire (`expires_in`, default
  600 s); expired approvals return `410` and can never be approved. Mandates
  carry their own `not_before`/`not_after` window (default 1 h from when the
  terms were presented).
- **Localhost binding.** The service binds `127.0.0.1` by default. Expose it
  beyond localhost only behind TLS and authentication you control; the
  approval URLs are bearer capabilities (anyone with the URL can open the
  approval page).
- **Unsigned proof requests.** The wallet displays what it is given; it does
  not enforce verifier policy. Verifiers should still use signed
  (`openid4vp-v1-signed`) requests — the wallet surfaces the verifier
  `client_id` so the person can see who claims to be asking.

## How this differs from Proof's commercial wallet

|                        | Proof's wallet | This wallet |
|------------------------|----------------|-------------|
| Hosting                | Cloud-hosted (no app download; "one API call" enrollment) | Self-hosted by the operator, on the person's own device |
| Identity proofing      | IAL2 via Proof's pipeline (biometric + government ID) | Bring your own: self-issued credentials work; any issuer the verifier trusts |
| Approval key           | Hardware-protected key in Proof's cloud wallet | Device Ed25519 key, private half never leaves the device (WebAuthn upgrade path documented) |
| Trust                  | Proof's CA + curated registry | Operator-owned: local trust lists, self-issued credentials first-class |
| Cost / license         | Commercial | Free, MIT, stdlib + `cryptography` |
| Mandate schema         | Product-level (not standardized) | Explicit `x-` extension (`x-x401ext-mandate/v1`), documented above |

The wire protocol spoken is x401 v0.2.0; the mandate profile is ours until
the spec standardizes delegation.

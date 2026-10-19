# x401-gateway

A free, self-hosted, MIT-licensed **x401 (v0.2.0) agent identity gateway**: a Python verifier
library plus the thing that doesn't exist anywhere else for free — a **self-hosted identity
wallet** where a person reviews and approves what their agent is about to do.

x401 (Proof, [spec](https://x401.proof.com/spec/latest)) answers *"who is behind the agent?"*
with an HTTP header protocol: a verifier challenges with `PROOF-REQUEST`, the agent returns
proof in `PROOF-RESPONSE`, the verifier answers with `PROOF-RESULT`. It stacks with x402
(which answers *"how does the agent pay?"*). This gateway implements the real v0.2.0 wire
spec and adds the missing holder side, with operator-owned local trust lists — no dependency
on any commercial CA network.

## What's in the box

| Part | Path | Description |
|---|---|---|
| Core library | `x401/` | Strict header codec, JWS (EdDSA/Ed25519 + ES256), `PROOF-REQUEST` build/parse (signed + unsigned), `PROOF-RESPONSE` parsing (inline / by-reference / token object, SSRF-guarded), `PROOF-RESULT` errors, local trust lists + DCQL satisfaction, mandatory single-use nonce cache, OAuth token-exchange leg, HTML `<data>` embed mirror |
| Wallet | `wallet/` | Credential store, per-device key registration, approval queue, stdlib-only web service, premium approval UI, QR/deep-link transport, `return_uri` relay |
| Demo | `demo/` | Demo merchant (verifier) + agent CLI + orchestrator; `Dockerfile` |
| Tests | `tests/` | 169 unit tests, 6 end-to-end tests, `tests/smoke.sh` |
| Docs | `docs/` | `PROTOCOL.md` (conformance), `WALLET.md`, `SECURITY.md` (threat model) |

Dependency footprint: **stdlib + `cryptography` only.** No web frameworks, no paid services.

## Quickstart

```bash
pip install cryptography
git clone https://github.com/alexwboles/x401-gateway.git
cd x401-gateway

# 1. Start the wallet (holder side) — port 8071
python3 -m wallet.service &

# 2. Start the demo merchant (verifier side) — port 8072
python3 -m demo.run_demo --serve-only &

# 3. Run the agent: it fetches the challenge, hands it to the wallet,
#    and prints the approval URL. Open that URL, review, approve —
#    the agent retries with proof and gets granted.
python3 -m demo.agent --merchant http://127.0.0.1:8072 --wallet http://127.0.0.1:8071
```

Or the fully automatic loop (approves programmatically — for CI, not for people):

```bash
python3 -m demo.run_demo --auto-approve
```

Run the whole verification suite:

```bash
bash tests/smoke.sh   # 169 unit + 6 e2e, must all pass
```

## The full loop

```
 Agent                              Wallet (person's device)              Merchant (verifier)
   |                                            |                                     |
   |  GET /resource                             |                                     |
   |------------------------------------------->|                                     |
   |  401 + PROOF-REQUEST (signed JAR challenge)|                                     |
   |<-------------------------------------------|                                     |
   |                                            |                                     |
   |  POST /api/requests {proof_request, terms}  |                                     |
   | -----------------------------------------> |                                     |
   |  {approval_id, approval_url, QR}            |                                     |
   | <----------------------------------------- |                                     |
   |                                            |                                     |
   |   (person opens approval URL, reviews the   |                                     |
   |    exact signed terms, approves)             | ---- device key signs mandate JWS ---> |
   |                                            |                                     |
   |  poll /api/status -> approved               |                                     |
   | <----------------------------------------- |                                     |
   |  {credential_result: mandate JWS}           |                                     |
   |                                            |                                     |
   |  GET /resource + PROOF-RESPONSE             |                                     |
   |------------------------------------------->|  verify: nonce single-use, mandate  |
   |                                            |  signature, merchant, ceiling, trust |
   |  200 {granted: true}                        |                                     |
   |<-------------------------------------------|                                     |
```

If anything fails — tampered amount, expired mandate, replayed nonce, untrusted
issuer — the merchant answers with a precise `PROOF-RESULT` error
(`tampered_mandate`, `expired_mandate`, `replayed_nonce`, `mandate_exceeded`,
`untrusted_issuer`, …). The e2e suite asserts every one of these.

## Spec vs. extension

Implemented from the v0.2.0 wire spec: strict codec, all three headers, signed and
unsigned `PROOF-REQUEST`, JAR verification (EdDSA + ES256), inline / by-reference /
token-object artifacts, the OAuth token-exchange leg, `PROOF-RESULT` errors, the HTML
`<data>` embed mirror, and replay protection (spec's SHOULD is our MUST).

**Extensions** (clearly marked `x-`, never claimed as spec): the scoped-mandate
credential schema (`x-x401ext-mandate/v1` — agent, merchant, action category, amount
ceiling, time window; any term tampering invalidates the signature), DID-issuer trust
constraints, and the per-device wallet key as the self-hosted stand-in for
biometric+hardware keys (WebAuthn/passkey is the documented upgrade path).

See `docs/PROTOCOL.md` for the full conformance matrix and `docs/SECURITY.md` for the
threat model (unsigned-mode harvesting warning, `credential_result_uri` SSRF surface,
trust-list centralization and our answer to it).

## License

MIT. The vendored QR generator in `wallet/vendor/` is Nayuki's, also MIT
(attribution in `wallet/vendor/LICENSE`).

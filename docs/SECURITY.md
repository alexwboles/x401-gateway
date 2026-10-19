# x401-gateway — Threat model and security posture

Applies to the demo merchant (`demo/merchant.py`), the self-hosted wallet
(`wallet/`), and the agent CLI (`demo/agent.py`). This is a **demo**, not a
production deployment — each section ends with what changes in production.

## Nonce freshness + single-use cache

* Every challenge carries a fresh 128-bit nonce and a short expiry
  (`--challenge-ttl`, default 120s).
* `x401.nonce.NonceCache`: `unknown_nonce` (never issued), `replayed_nonce`
  (already consumed), `expired_challenge` (past expiry).
* Only a **fully-validated** proof burns its binding. Failed validations
  (bad signature, untrusted issuer, expired mandate…) leave the challenge live
  so the agent can retry with a corrected proof — at the cost of letting an
  attacker probe error messages. Error tokens are coarse by design; no oracle
  beyond pass/fail per check.
* Production: consider burning the binding on any well-formed attempt if
  probing resistance matters more than retry ergonomics.

## Unsigned-mode credential-harvesting warning (default posture)

* `x401/request.py` implements `openid4vp-v1-unsigned`, but the demo merchant
  only issues **signed** challenges.
* Unsigned mode binds only to the invoking origin + the verifier's nonce. The
  spec warns explicitly: a malicious page/relay can invoke it in front of a
  different holder and relay the result. Do not enable unsigned challenges
  unless you compensate with fresh unique nonces, agent binding, or origin
  constraining.

## `credential_result_uri` SSRF surface + our guards

* By-reference artifacts are capability URLs and a first-class SSRF surface.
* Guards (`x401/response.py::dereference`): https-only; URI must start with a
  verifier-issued `allowed_prefix`; the host is DNS-resolved and **every**
  resolved IP must be publicly routable (private/loopback/link-local/multicast/
  reserved rejected); redirects are not followed; fetch is size- and
  time-bounded.
* Default posture in the demo merchant: **no prefix configured → by-reference
  refused** (`ssrf_blocked`). Enable it only with a prefix you mint.
* Residual: DNS TOCTOU between the address check and the fetch exists, as in
  any resolve-then-fetch guard. Production: fetch through an egress proxy that
  enforces the same policy at connection time.

## Proof / payment separation

* x401 never touches payment. A `402` leg (e.g. x402) is a separate protocol
  with its own headers; the two compose (prove first, then pay) but neither
  carries the other. The demo merchant implements no payment leg at all.

## Trust-list centralization — and our answer

* The protocol is nominally issuer-neutral, but the live ecosystem's trust
  anchor is a curated registry plus one CA's IAL2 pipeline. A verifier that
  "accepts the registry" outsources its trust policy.
* Our answer: **operator-owned local trust** (`x401/trust.py`). The list
  starts empty; the operator explicitly adds issuers as JWKs. Self-issued
  credentials are first-class — the demo wires the wallet's device key as
  `x401-wallet:<kid>`. No external registry is consulted, ever.
* Consequence: trust is only as good as the operator's vetting. Key rotation
  is explicit (`remove_issuer` + `add_issuer`); there is no automatic
  revocation feed in the demo.

## Device-key custody

* The wallet's device key is the self-hosted stand-in for Proof's biometric +
  hardware-protected key. In this demo it is a software Ed25519 key persisted
  (0600) in the wallet data dir.
* Compromise of the device key = full mandate-forgery capability for that
  holder. Response: rotate the device key, remove the old issuer id from every
  verifier's trust list, and treat in-flight mandates as suspect (short
  `not_after` windows bound the damage).
* Production: move signing into the platform keystore / Secure Enclave, or
  replace it with a WebAuthn/passkey assertion over the mandate hash
  (challenge = mandate hash + verifier id + nonce).

## Replay / tamper / expiry handling (tested)

* `tests/e2e.py` asserts each negative exactly: tampered terms (signature no
  longer verifies) → `tampered_mandate`/`invalid_signature`; amount over
  ceiling → `mandate_exceeded`; `not_after` in the past → `expired_mandate`;
  reused proof → `replayed_nonce`; unknown signer → `untrusted_issuer`;
  garbage/expired Bearer → `invalid_token`/`token_expired`.
* The mandate binds the challenge two ways: the JAR nonce (wallets that echo
  it) or the unique per-challenge `request_id` the merchant issues (the
  delivered wallet mints its own mandate nonce). Either binding is single-use.

## What we do NOT protect against

* **Holder-device compromise.** If the person's device is owned, approvals can
  be faked at the source. No protocol fixes a compromised holder endpoint.
* **Verifier key compromise.** The merchant's Ed25519 key signs challenges
  (JARs) and access tokens. Response: rotate the key id, flush the nonce
  cache, shrink token TTLs; previously issued Bearer tokens die at `exp`.
* **Network attackers on the demo transport.** The demo binds 127.0.0.1 with
  no TLS. Production: terminate TLS at the edge, put the wallet behind the
  holder's own authentication, and never expose the approval endpoints to
  the open internet without it.
* **Bearer token theft.** Access tokens are bearer credentials by design;
  theft within their (short) lifetime grants the resource. Mitigations in
  place: 5-minute default TTL, audience bound to the exact resource route,
  unique `jti`. DPoP / mTLS binding is the upgrade path (omitted — see
  `PROTOCOL.md`).
* **The person approving what they did not read.** The wallet shows the exact
  signed terms (the SIWE property: what you see is what you sign), but a
  rushed or deceived approver is outside the technical threat model.

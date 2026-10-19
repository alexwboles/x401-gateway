# x401-gateway — Protocol conformance (x401 v0.2.0)

This documents what the gateway implements against **x401: HTTP Proof Requirement
Protocol, Draft v0.2.0** (spec: https://x401.proof.com/spec/latest), what it adds
as a namespaced extension, and what it deliberately omits. Wire behavior was
researched in `../x401-research/SPEC-RESEARCH.md` (kept outside this repo).

## IMPLEMENTED (core wire — conformant)

| Area | What we do |
|---|---|
| Codec strictness | base64url, URL-safe alphabet, **no padding**; single-line values; comma-joined lists rejected; `scheme`/`version` checked (`x401/codec.py`) |
| Headers | `PROOF-REQUEST` (verifier → agent), `PROOF-RESPONSE` (agent → verifier), `PROOF-RESULT` (verifier → agent); status codes independent of proof state; `Cache-Control: no-store` on challenges |
| PROOF-REQUEST | `openid4vp-v1-signed` (JAR, RFC 9101) **and** `openid4vp-v1-unsigned`; fresh 128-bit `nonce` per challenge; short `exp`; `client_id` + `expected_origins`; DCQL query; `oauth.token_endpoint`; `request_id`; `satisfied_requirements` |
| JAR algorithms | EdDSA/Ed25519 **and** ES256 (whatever the JAR header declares, per JOSE); standard JWS compact serialization — no custom canonicalization |
| Result Artifact | inline form **and** by-reference form; x401 Token Object as alternative `PROOF-RESPONSE` placement |
| By-reference fetch | https-only; must match a verifier-issued `allowed_prefix`; DNS resolution with non-public-address rejection; no redirects; size/time bounds (`x401/response.py`) |
| OAuth token-exchange leg | fixed `grant_type` / `subject_token_type` (never repeated in the payload); subject artifact validated with the **same** proof-validation rules as direct retry; short-lived Bearer JWT carrying the spec's `x401` metadata block (`agent_id`, `verifier_id`, `request_id`, `satisfied_requirements`, `resource`, `method`, `expires_at`, `jti`); accepted via `Authorization` **and** Token-Object placement |
| PROOF-RESULT | precise `error` tokens: `invalid_request`, `invalid_response`, `unsupported_version`, `unknown_nonce`, `replayed_nonce`, `expired_challenge`, `invalid_signature`, `untrusted_issuer`, `unsatisfied_requirements`, `wrong_binding`, `expired_mandate`, `tampered_mandate`, `mandate_exceeded`, `invalid_token`, `token_expired`, `ssrf_blocked`, `unsupported_protocol` |
| HTML embed mirror | `<data value="application/json;x401=proof-required" hidden>` with unencoded payload + `$schema`; informational only, header authoritative (`x401/html.py`) |
| Replay protection | `NonceCache`: fresh nonce per challenge, single-use consume; `unknown_nonce` / `replayed_nonce` / `expired_challenge` |
| Trust | operator-owned local `TrustList` (`x401/trust.py`); default posture is **empty** — nothing trusted until the operator adds it; self-issued issuers first-class; DCQL satisfaction checking |

## EXTENSION (namespaced, not claimed as spec)

| Extension | Rationale |
|---|---|
| Scoped mandate, type `x-x401ext-mandate/v1` (`x401/mandate.py`) | v0.2.0 standardizes the proof wire but leaves delegation/mandate schema an explicit open question ("Fully Autonomous Delegation"). The demo needs *which agent / merchant / action category / amount ceiling / time window* signed by the holder. Claims: `agent`, `merchant`, `action_category`, `amount_ceiling{currency,value}`, `not_before`, `not_after`, `nonce`, optional `request_id`, `iss`. JWS-signed canonical JSON — any alteration invalidates the signature. Marked `x-` and documented as an extension everywhere. |
| DID-issuer trust constraints via local trust list | `trusted_authorities` (`openid_federation` / `etsi_tl` / `aki`) has no DID-issuer type (upstream: openid/OpenID4VP#494). Operator-owned local trust with self-issued issuers is this project's answer to trust centralization — no curated-registry dependency. |
| Per-device wallet key as biometric stand-in | The self-hosted equivalent of Proof's biometric + hardware-protected key: one Ed25519 device key, private material never leaves the wallet host. Production upgrade path: WebAuthn/passkey-bound signing of the mandate. |
| Challenge binding via single-use `request_id` | The delivered wallet mints its **own** mandate nonce (it does not echo the JAR nonce), so the merchant additionally issues a unique `request_id` per challenge and consumes it single-use. A mandate bound to a consumed/unknown request id fails with `replayed_nonce` / `unknown_nonce`. Wallets that echo the JAR nonce take the `NonceCache` path instead. |
| `credential_result.protocol` carrying the mandate type | The delivered wallet sets `protocol` to `x-x401ext-mandate/v1` (the artifact *is* the mandate). The merchant accepts it alongside the OpenID4VP protocol labels. |

## OMITTED (deliberate, with reasons)

| Omitted | Reason |
|---|---|
| v0.1.0 header names (`PROOF-REQUIRED` / `PROOF-PRESENTATION`) | Superseded by the v0.2.0 renames. Rejected, not accepted — documented incompatibility. |
| `openid4vp-v1-multisigned` | Spec gap (proof/x401#41): not in the v0.2.0 `protocol` enum. |
| VP response encryption | No in-spec mechanism to implement; out of scope for the demo. |
| DPoP / mTLS agent binding | Optional in the spec; the demo binds proof to verifier + challenge + mandate. Agent binding is a deployment decision, noted in `SECURITY.md`. |
| Unsigned-mode challenges in the demo merchant | Implemented in `x401/request.py`, but the demo merchant only issues **signed** challenges (see `SECURITY.md`: unsigned mode binds only to invoking origin + nonce — credential-harvesting exposure). |

## Interop notes (earned while integrating the parallel tracks)

* The delivered `x401.codec.parse_header` takes a **headers mapping + name** (not a raw value), and `emit_header` returns a `(name, value)` tuple. Demo code uses `decode_payload` / `encode_payload` directly.
* `x401.response.parse_proof_response` returns a **normalized** envelope (`{'form': 'inline'|'by_reference'|'token_object', ...}`); the demo detects the form defensively so it also accepts raw artifacts.
* `x401.response.dereference` takes a single `allowed_prefix` (verifier-issued); unset means by-reference is refused (`ssrf_blocked`).
* `x401.oauth.issue_access_token` sets `aud` to the **resource**; the merchant verifies the audience against the requested route.
* `x401.trust.TrustList` stores **JWK dicts** and answers trust decisions; the merchant keeps a parallel key map (issuer → live public key) for signature verification.
* `demo/_compat.py` is the single guarded-import layer: real `x401`/`wallet` packages when importable, `demo/_fallback` reference implementations otherwise, plus small signature adapters. `demo/_compat.py::backend_summary()` reports what resolved where.

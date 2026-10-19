#!/usr/bin/env python3
"""Orchestrator for the x401-gateway human demo.

Starts the wallet + merchant on localhost, wires the operator-owned trust
(merchant trusts the wallet's device key as a self-issued issuer), then runs the
agent flow. The human step is kept: the approval URL is printed and the run waits
for the person to approve — unless ``--auto-approve`` (used by e2e-style runs).

    python3 -m demo.run_demo --auto-approve        # full loop, no human needed
    python3 -m demo.run_demo                      # prints approval URL, waits
    python3 -m demo.run_demo --serve-only          # just serve; run agent manually
"""

import argparse
import json
import sys
import threading
import time

from demo import _compat as C
from demo import agent as agent_mod
from demo import merchant as merchant_mod





def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="x401-gateway demo orchestrator")
    ap.add_argument("--wallet-port", type=int, default=8071)
    ap.add_argument("--merchant-port", type=int, default=8072)
    ap.add_argument("--charge-amount", default="49.99")
    ap.add_argument("--token-ttl", type=int, default=300)
    ap.add_argument("--auto-approve", action="store_true",
                    help="approve the wallet session programmatically")
    ap.add_argument("--serve-only", action="store_true",
                    help="start wallet + merchant and serve (run the agent manually)")
    ap.add_argument("--use-oauth", action="store_true",
                    help="agent uses the OAuth token-exchange leg")
    args = ap.parse_args(argv)

    print(f"x401-gateway demo ({C.backend_summary()})")
    if C.using_fallback():
        print("NOTE: running on the demo/_fallback reference implementations — "
              "the real x401/wallet packages were not importable. "
              "Wire behavior is identical; swap in the real packages when ready.")

    wallet = C.open_wallet(port=args.wallet_port)
    print(f"wallet:   {wallet.url}  (device issuer {wallet.issuer_id}, "
          f"kid {wallet.key_id})")

    # Operator-owned local trust: the merchant trusts the wallet's device key
    # directly as a self-issued issuer — no curated registry involved.
    trust = C.trust.TrustList()
    C.add_trust_issuer(trust, issuer_id=wallet.issuer_id,
                       public_key=wallet.public_key,
                       public_jwk=wallet.public_jwk, key_id=wallet.key_id)
    config = merchant_mod.MerchantConfig(
        trust=trust,
        charge_amount={"currency": "USD", "value": args.charge_amount},
        token_ttl=args.token_ttl,
    )
    config.key_map[wallet.issuer_id] = (wallet.key_id, wallet.public_key)
    server = merchant_mod.create_server("127.0.0.1", args.merchant_port, config)
    thread = threading.Thread(target=server.serve_forever,
                              kwargs={"poll_interval": 0.1}, daemon=True)
    thread.start()
    merchant_url = f"http://127.0.0.1:{server.server_address[1]}"
    print(f"merchant: {merchant_url}  (charge USD {args.charge_amount})")

    if args.serve_only:
        print()
        print("Serving. In another terminal, run the agent manually:")
        print(f"  python3 -m demo.agent --merchant {merchant_url} "
              f"--wallet {wallet.url}")
        print("  (add --use-oauth to exercise the token-exchange leg)")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            print("\nstopping.")
        return 0

    # Non-interactive agent flow up to the human step.
    status, headers, _body = agent_mod.fetch_challenge(merchant_url)
    assert status == 401 and "PROOF-REQUEST" in headers, \
        f"expected 401 + PROOF-REQUEST, got HTTP {status}"
    payload = C.request.parse_proof_request(
        C.codec.decode_payload(headers["PROOF-REQUEST"]))
    client_id = agent_mod.jar_claims(payload).get("client_id")
    terms = agent_mod.build_terms(client_id, amount=args.charge_amount,
                                  ceiling="100.00", agent_id="demo-agent/1")
    session = agent_mod.submit_wallet_request(wallet.url, payload, terms)
    approval_id = session["approval_id"]
    print()
    print("=" * 64)
    print("ACTION REQUIRED — open this URL to approve as the person:")
    print("  " + session["approval_url"])
    print("=" * 64)
    print()

    if args.auto_approve:
        code = C.wallet_approve(wallet, approval_id)
        print(f"auto-approved via POST /api/approve/{approval_id} "
              f"(HTTP {code})")
    else:
        print("waiting for the person to approve "
              "(Ctrl-C to stop) ...")

    final = agent_mod.poll_status(wallet.url, approval_id,
                                  timeout=600, interval=2)
    if final["status"] != "approved":
        print(f"wallet session ended: {final['status']}")
        return 1
    print("approved; retrying the merchant ...")
    proof_response = final["proof_response"]
    if args.use_oauth:
        token_endpoint = payload.get("oauth", {}).get(
            "token_endpoint", merchant_url + "/oauth/token")
        token = agent_mod.exchange_for_token(token_endpoint, proof_response,
                                             merchant_url + "/resource")
        status, headers, body = agent_mod.fetch_with_bearer(
            merchant_url, token["access_token"])
    else:
        status, headers, body = agent_mod.retry_with_proof(merchant_url,
                                                          proof_response)
    print(f"HTTP {status}")
    print(body.decode())
    if "PROOF-RESULT" in headers:
        res = C.result.parse_result(C.codec.decode_payload(headers["PROOF-RESULT"]))
        print("PROOF-RESULT:", json.dumps(res, indent=2))
    return 0 if status == 200 else 1


if __name__ == "__main__":
    sys.exit(main())

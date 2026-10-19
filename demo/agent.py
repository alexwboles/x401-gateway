#!/usr/bin/env python3
"""Demo x401 agent (CLI).

Flow:
    GET /resource -> 401 + PROOF-REQUEST
    -> POST challenge + terms to the wallet's /api/requests
    -> PRINT the approval URL (the human step: approve as the person)
    -> poll /api/status until approved / denied / expired
    -> on approval, retry /resource with PROOF-RESPONSE (or --use-oauth:
       exchange the artifact for a Bearer token first)
    -> print grant/deny + any PROOF-RESULT.
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from demo import _compat as C


def _request(method: str, url: str, *, headers=None, data=None,
             content_type=None, timeout: int = 15):
    req = urllib.request.Request(url, data=data, headers=dict(headers or {}),
                                 method=method)
    if content_type:
        req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def fetch_challenge(merchant_url: str):
    """GET /resource; returns (status, headers, body)."""
    return _request("GET", merchant_url + "/resource")


def jar_claims(payload: dict) -> dict:
    """Extract the OpenID4VP request claims from a parsed PROOF-REQUEST."""
    data = payload["credential_requirements"]["digital"]["requests"][0]["data"]
    if "request" in data:  # signed JAR
        _header, claims = C.decode_compact_unverified(data["request"])
        return claims
    return data  # unsigned: raw params


def submit_wallet_request(wallet_url: str, proof_request: dict, terms: dict) -> dict:
    """POST the challenge + terms to the wallet; returns the session object."""
    status, _headers, body = _request(
        "POST", wallet_url + "/api/requests",
        data=json.dumps({"proof_request": proof_request,
                         "terms": terms}).encode("utf-8"),
        content_type="application/json")
    if status != 200:
        raise RuntimeError(f"wallet /api/requests failed: HTTP {status}: "
                           f"{body.decode()[:300]}")
    return json.loads(body)


def poll_status(wallet_url: str, approval_id: str, *, timeout: int = 180,
                interval: int = 2) -> dict:
    """Poll /api/status until the session leaves 'pending'."""
    deadline = time.time() + timeout
    while True:
        status, _headers, body = _request(
            "GET", f"{wallet_url}/api/status/{approval_id}")
        if status != 200:
            raise RuntimeError(f"wallet status failed: HTTP {status}: "
                               f"{body.decode()[:200]}")
        state = json.loads(body)
        if state["status"] != "pending" or time.time() >= deadline:
            return state
        time.sleep(interval)


def retry_with_proof(merchant_url: str, proof_response: dict):
    """GET /resource with the PROOF-RESPONSE header."""
    return _request("GET", merchant_url + "/resource",
                    headers={"PROOF-RESPONSE": C.codec.encode_payload(proof_response)})


def fetch_with_bearer(merchant_url: str, access_token: str):
    """GET /resource with Authorization: Bearer."""
    return _request("GET", merchant_url + "/resource",
                    headers={"Authorization": "Bearer " + access_token})


def exchange_for_token(token_endpoint: str, proof_response: dict,
                       resource: str) -> dict:
    """Run the OAuth token-exchange leg; returns the token response."""
    subject_token = C.codec.encode_payload(proof_response)
    form = C.oauth.build_token_request(subject_token=subject_token,
                                       resource=resource)
    status, _headers, body = _request(
        "POST", token_endpoint,
        data=urllib.parse.urlencode(form).encode("utf-8"),
        content_type="application/x-www-form-urlencoded")
    if status != 200:
        raise RuntimeError(f"token exchange failed: HTTP {status}: "
                           f"{body.decode()[:300]}")
    return json.loads(body)


def build_terms(client_id: str, *, amount: str, ceiling: str,
                agent_id: str) -> dict:
    """Terms the agent asks the person to authorize (demo: fixed purchase).

    Superset shape: the delivered wallet reads merchant_display /
    action_category / amount_ceiling / agent; the fallback wallet reads
    merchant / action / amount / ceiling / agent_id.
    """
    money = {"currency": "USD", "value": amount}
    limit = {"currency": "USD", "value": ceiling}
    return {
        "merchant_display": client_id,
        "merchant": client_id,
        "action_category": "purchase",
        "action": "purchase",
        "amount": money,
        "amount_ceiling": limit,
        "ceiling": limit,
        "agent": agent_id,
        "agent_id": agent_id,
        "expires_in": 600,
        "window_seconds": 600,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Demo x401 agent")
    ap.add_argument("--merchant", required=True, help="merchant base URL")
    ap.add_argument("--wallet", required=True, help="wallet base URL")
    ap.add_argument("--amount", default="49.99", help="charge amount to authorize")
    ap.add_argument("--ceiling", default="100.00", help="mandate ceiling")
    ap.add_argument("--agent-id", default="demo-agent/1")
    ap.add_argument("--use-oauth", action="store_true",
                    help="use the OAuth token-exchange leg instead of direct retry")
    ap.add_argument("--poll-timeout", type=int, default=180)
    ap.add_argument("--poll-interval", type=int, default=2)
    args = ap.parse_args(argv)
    merchant_url = args.merchant.rstrip("/")
    wallet_url = args.wallet.rstrip("/")

    print(f"x401 demo agent ({C.backend_summary()})")
    status, headers, body = fetch_challenge(merchant_url)
    if status == 200:
        print("resource granted without proof:")
        print(body.decode())
        return 0
    if status != 401 or "PROOF-REQUEST" not in headers:
        print(f"unexpected first response: HTTP {status}")
        print(body.decode()[:500])
        return 1

    payload = C.request.parse_proof_request(
        C.codec.decode_payload(headers["PROOF-REQUEST"]))
    claims = jar_claims(payload)
    client_id = claims.get("client_id", "?")
    print(f"challenge from {client_id} "
          f"(request_id={payload.get('request_id')})")

    terms = build_terms(client_id, amount=args.amount, ceiling=args.ceiling,
                        agent_id=args.agent_id)
    session = submit_wallet_request(wallet_url, payload, terms)
    print()
    print("=" * 64)
    print("ACTION REQUIRED — open this URL to approve as the person:")
    print("  " + session["approval_url"])
    print("=" * 64)
    print()

    final = poll_status(wallet_url, session["approval_id"],
                        timeout=args.poll_timeout, interval=args.poll_interval)
    if final["status"] != "approved":
        print(f"wallet session ended: {final['status']}")
        return 1
    print("approved by the person; retrying the merchant ...")
    proof_response = final["proof_response"]

    if args.use_oauth:
        token_endpoint = payload.get("oauth", {}).get(
            "token_endpoint", merchant_url + "/oauth/token")
        token = exchange_for_token(token_endpoint, proof_response,
                                   merchant_url + "/resource")
        print(f"token: {token['token_type']} "
              f"(expires_in={token['expires_in']}, scope={token.get('scope')})")
        status, headers, body = fetch_with_bearer(merchant_url,
                                                  token["access_token"])
    else:
        status, headers, body = retry_with_proof(merchant_url, proof_response)

    print(f"HTTP {status}")
    print(body.decode())
    if "PROOF-RESULT" in headers:
        res = C.result.parse_result(C.codec.decode_payload(headers["PROOF-RESULT"]))
        print("PROOF-RESULT:", json.dumps(res, indent=2))
    return 0 if status == 200 else 1


if __name__ == "__main__":
    sys.exit(main())

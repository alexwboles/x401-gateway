"""HTML <data> embed mirror for header-blind clients (in-spec supplement).

For clients that only surface response bodies (e.g. AI assistants), a verifier
MAY mirror the payload as an HTML <data> element containing the UNENCODED JSON
payload plus the spec's $schema member. Informational disclosure only -- the
PROOF-REQUEST header remains authoritative.
"""

from __future__ import annotations

import json

__all__ = ["embed_html"]

SCHEMA_URL = "https://x401.id/spec/schemas/request.json"


def embed_html(payload: dict) -> str:
    """Return a <data value="application/json;x401=proof-required" hidden> snippet.

    The element contains the unencoded JSON payload plus "$schema". Angle
    brackets and ampersands are unicode-escaped so the JSON cannot break out of
    the element while remaining valid JSON.
    """
    if not isinstance(payload, dict):
        raise ValueError("payload must be a dict")
    mirrored = dict(payload)
    mirrored["$schema"] = SCHEMA_URL
    text = json.dumps(mirrored, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    text = text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return f'<data value="application/json;x401=proof-required" hidden>{text}</data>'

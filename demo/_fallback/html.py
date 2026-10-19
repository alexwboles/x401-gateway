"""Fallback ``x401.html`` — HTML ``<data>`` embed mirror for header-blind clients."""

import json

__all__ = ["SCHEMA_URL", "embed_html"]

SCHEMA_URL = "https://x401.id/spec/schemas/request.json"


def embed_html(payload: dict) -> str:
    """Mirror the PROOF-REQUEST payload as an HTML ``<data>`` element.

    Informational disclosure only: the header remains authoritative and enforcement
    still happens on the protected route.
    """
    doc = {"$schema": SCHEMA_URL}
    doc.update(payload)
    raw = json.dumps(doc, ensure_ascii=True, separators=(",", ":"))
    raw = raw.replace("</", "<\\/")  # keep the embed parse-safe inside HTML
    return f'<data value="application/json;x401=proof-required" hidden>{raw}</data>'

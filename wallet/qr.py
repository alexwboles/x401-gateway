"""QR codes for the approval handoff (RFC 8628 device-grant shape).

Encoding uses the vendored Nayuki ``qrcodegen`` core
(``wallet/vendor/qrcodegen.py``, MIT -- see ``wallet/vendor/LICENSE``);
SVG rendering is our own small addition (the vendored file has no SVG
output), drawing sharp square modules -- no rounded edges.
"""

from __future__ import annotations

try:
    from wallet.vendor import qrcodegen as _qrcodegen
    HAVE_QR = True
except Exception:  # pragma: no cover - vendoring is expected to succeed
    _qrcodegen = None
    HAVE_QR = False


def qr_to_svg(text: str, border: int = 4, module_px: int = 6,
              fg: str = "#141310", bg: str = "#ffffff") -> str:
    """Render *text* as a QR code, returned as an SVG string."""
    if not HAVE_QR:
        raise RuntimeError("qrcodegen vendor library unavailable")
    qr = _qrcodegen.QrCode.encode_text(text, _qrcodegen.QrCode.Ecc.MEDIUM)
    size = qr.get_size()
    dim = (size + border * 2) * module_px
    runs: list[str] = []
    for y in range(size):
        for x_pos in range(size):
            if qr.get_module(x_pos, y):
                px = (x_pos + border) * module_px
                py = (y + border) * module_px
                runs.append(f"M{px},{py}h{module_px}v{module_px}h{-module_px}Z")
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" version="1.1" '
        f'viewBox="0 0 {dim} {dim}" shape-rendering="crispEdges" '
        f'role="img" aria-label="QR code">'
        f'<rect width="{dim}" height="{dim}" fill="{bg}"/>'
        f'<path d="{" ".join(runs)}" fill="{fg}"/></svg>'
    )

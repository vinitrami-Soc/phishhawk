"""Response headers. Every page gets a strict policy; the stored HTML report
gets a sandbox on top of its own policy, so it runs in an opaque origin."""

from __future__ import annotations

APP_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
           "connect-src 'self'; frame-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
REPORT_CSP = ("sandbox allow-popups allow-popups-to-escape-sandbox allow-downloads; default-src 'none'; "
              "style-src 'unsafe-inline'; img-src data:; font-src data:; base-uri 'none'; form-action 'none'; "
              "frame-ancestors 'self'")
BASE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "X-Robots-Tag": "noindex, nofollow",
}
HSTS = "max-age=31536000"

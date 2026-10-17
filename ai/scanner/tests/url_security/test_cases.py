"""URL security test-case catalogue.

Each test maps to one normalized finding emitted by the URL scanner
(ai/scanner/engine/url_scanner.py). The engine fills in the dynamic
`status`, `severity`, `confidence`, `summary`, and `evidence`; the static
metadata below (`title`, `recommendation`, `header`) stays here so the
checks stay data-driven.
"""

URL_SECURITY_TEST_CASES = [
    {
        "test_id": "TLS-001",
        "category": "TLS",
        "title": "HTTPS availability and certificate validity",
        "recommendation": (
            "Serve all traffic over HTTPS with a valid TLS certificate from a "
            "trusted CA and redirect HTTP requests to HTTPS."
        ),
    },
    {
        "test_id": "HDR-001",
        "category": "Security Headers",
        "header": "Strict-Transport-Security",
        "title": "Strict-Transport-Security (HSTS) header",
        "recommendation": (
            "Enable Strict-Transport-Security with a sensible max-age "
            "(e.g. max-age=31536000) on all HTTPS responses."
        ),
    },
    {
        "test_id": "HDR-002",
        "category": "Security Headers",
        "header": "Content-Security-Policy",
        "title": "Content-Security-Policy header",
        "recommendation": (
            "Set a Content-Security-Policy that restricts the sources "
            "scripts, styles, and other content may load from."
        ),
    },
    {
        "test_id": "HDR-003",
        "category": "Security Headers",
        "header": "X-Content-Type-Options",
        "title": "X-Content-Type-Options header",
        "recommendation": (
            "Include X-Content-Type-Options: nosniff so browsers refuse "
            "MIME sniffing of responses."
        ),
    },
    {
        "test_id": "HDR-004",
        "category": "Security Headers",
        "header": "X-Frame-Options",
        "title": "X-Frame-Options header",
        "recommendation": (
            "Deny framing of the site with X-Frame-Options: DENY (or "
            "SAMEORIGIN) or use the CSP frame-ancestors directive."
        ),
    },
    {
        "test_id": "HDR-005",
        "category": "Security Headers",
        "header": "Referrer-Policy",
        "title": "Referrer-Policy header",
        "recommendation": (
            "Set a Referrer-Policy such as strict-origin-when-cross-origin "
            "to limit what is shared in the Referer header."
        ),
    },
    {
        "test_id": "HDR-006",
        "category": "Security Headers",
        "header": "Permissions-Policy",
        "title": "Permissions-Policy header",
        "recommendation": (
            "Set a Permissions-Policy to restrict browser feature access "
            "such as camera, microphone, and geolocation."
        ),
    },
    {
        "test_id": "EXP-001",
        "category": "Public Exposure",
        "title": "Basic public exposure assessment",
        "recommendation": (
            "Keep the service public only when intended, review any "
            "cross-host redirects, and restrict unexpected open endpoints."
        ),
    },
]

URL_SECURITY_TEST_MAP = {
    case["test_id"]: case for case in URL_SECURITY_TEST_CASES
}
"""Offline unit tests for the URL security scanner (ai/scanner/engine/url_scanner.py).

All tests inject fake resolvers/fetchers so nothing touches the network.
"""

import unittest
from unittest import mock

from ai.scanner.engine.url_scanner import (
    FetchRecord,
    UnsafeUrlError,
    UrlConnectionError,
    default_fetch,
    run_url_scan,
)

EXPECTED_KEYS = {
    "test_id",
    "category",
    "status",
    "severity",
    "confidence",
    "summary",
    "evidence",
    "recommendation",
}

VALID_STATUSES = {"pass", "warning", "vulnerable"}
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_CONFIDENCE = {"low", "medium", "high"}

CLEAN_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=()",
}


def resolver(host):
    return {
        "public.example.com": ["93.184.216.34"],
        "redirector.example.com": ["93.184.216.35"],
        "mixed.example.com": ["93.184.216.36", "10.0.0.9"],
        "localhost": ["127.0.0.1"],
        "internal.example.com": ["10.0.0.5"],
    }.get(host, [])


def make_fetch(
    status=200,
    headers=None,
    ssl_error=None,
    raise_conn=False,
):
    def fetch(url):
        if raise_conn:
            raise UrlConnectionError("Could not reach target 'x': ConnectionError.")
        return FetchRecord(
            status_code=status,
            headers=dict(headers) if headers is not None else dict(CLEAN_HEADERS),
            ssl_error=ssl_error,
            scheme="https" if url.startswith("https://") else "http",
            final_url=url,
            hops=0,
        )

    return fetch


class UrlScannerTests(unittest.TestCase):
    def assert_rejected(self, url, msg=None, **kwargs):
        with self.assertRaises(UnsafeUrlError):
            run_url_scan(url, resolver=resolver, **kwargs)
        if msg:
            try:
                run_url_scan(url, resolver=resolver, **kwargs)
            except UnsafeUrlError as exc:
                self.assertIn(msg, str(exc))

    def assert_valid_finding(self, finding):
        self.assertEqual(set(finding), EXPECTED_KEYS)
        self.assertIn(finding["status"], VALID_STATUSES)
        self.assertIn(finding["severity"], VALID_SEVERITIES)
        self.assertIn(finding["confidence"], VALID_CONFIDENCE)

    def test_rejects_private_ip_literals(self):
        for ip in ("127.0.0.1", "192.168.1.1", "10.0.0.8", "172.16.9.9", "169.254.169.254", "0.0.0.0"):
            self.assert_rejected(f"http://{ip}/")
            self.assert_rejected(f"https://{ip}/")

    def test_rejects_reserved_metadata_hosts(self):
        self.assert_rejected("http://metadata.google.internal/", "reserved")
        self.assert_rejected("http://metadata/")

    def test_rejects_hosts_resolving_to_private_ips(self):
        self.assert_rejected("http://localhost/", "non-public IP")
        self.assert_rejected("http://internal.example.com/", "non-public IP")

    def test_rejects_hosts_with_any_private_ip(self):
        self.assert_rejected("http://mixed.example.com/", "non-public IP")

    def test_rejects_bad_scheme(self):
        self.assert_rejected("ftp://public.example.com/", "scheme")
        self.assert_rejected("file:///etc/passwd")

    def test_rejects_missing_host(self):
        self.assert_rejected("http://")

    def test_rejects_custom_ports(self):
        self.assert_rejected("https://public.example.com:8080/", "port")
        self.assert_rejected("http://public.example.com:22/")

    def test_redirect_to_private_target_is_not_followed(self):
        class FakeResponse:
            def __init__(self):
                self.status_code = 302
                self.headers = {"Location": "http://127.0.0.1/evil"}
                self.is_redirect = True

            def close(self):
                pass

        with mock.patch(
            "ai.scanner.engine.url_scanner.requests.get",
            return_value=FakeResponse(),
        ):
            with self.assertRaises(UnsafeUrlError):
                default_fetch("http://93.184.216.34/")

    def test_clean_scan_passes(self):
        result = run_url_scan(
            "https://public.example.com/",
            resolver=resolver,
            fetch=make_fetch(),
        )
        self.assertEqual(result["risk"], "info")
        self.assertEqual(result["findings_count"], 8)
        self.assertEqual(result["target"]["host"], "public.example.com")
        self.assertEqual(result["target"]["resolved_ip"], "93.184.216.34")
        self.assertEqual(result["target"]["scheme"], "https")
        for finding in result["findings"]:
            self.assert_valid_finding(finding)
        tls = next(f for f in result["findings"] if f["test_id"] == "TLS-001")
        self.assertEqual(tls["status"], "pass")

    def test_missing_header_is_warning(self):
        headers = {k: v for k, v in CLEAN_HEADERS.items() if k != "x-content-type-options"}
        result = run_url_scan(
            "https://public.example.com/",
            resolver=resolver,
            fetch=make_fetch(status=200, headers=headers),
        )
        hdr = next(f for f in result["findings"] if f["test_id"] == "HDR-003")
        self.assertEqual(hdr["status"], "warning")
        self.assertEqual(hdr["severity"], "low")
        self.assertIn("did not include", hdr["evidence"])

    def test_tls_certificate_failure_is_vulnerable(self):
        result = run_url_scan(
            "https://public.example.com/",
            resolver=resolver,
            fetch=make_fetch(ssl_error="certificate verify failed: self-signed"),
        )
        tls = next(f for f in result["findings"] if f["test_id"] == "TLS-001")
        self.assertEqual(tls["status"], "vulnerable")
        self.assertEqual(tls["severity"], "high")
        self.assertEqual(result["risk"], "high")
        self.assertNotIn("HDR-003", [f["test_id"] for f in result["findings"]])

    def test_http_target_without_https_is_warning(self):
        def probe_blocks(url):
            if url.startswith("https://"):
                raise UrlConnectionError("Could not reach target 'public.example.com'.")
            return FetchRecord(
                status_code=200,
                headers=dict(CLEAN_HEADERS),
                scheme="http",
                final_url=url,
                hops=0,
            )

        result = run_url_scan(
            "http://public.example.com/",
            resolver=resolver,
            fetch=probe_blocks,
        )
        tls = next(f for f in result["findings"] if f["test_id"] == "TLS-001")
        self.assertEqual(tls["status"], "warning")
        self.assertEqual(tls["severity"], "medium")
        self.assertEqual(result["risk"], "medium")


if __name__ == "__main__":
    unittest.main()
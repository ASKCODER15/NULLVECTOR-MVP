"""URL security scanner engine.

Performs a safe, single-request HTTP inspection of a user-supplied URL and
returns normalized findings (docs/PROJECT_CONTEXT.md §6) for three checks:

  * TLS-001   HTTPS availability and certificate validity
  * HDR-001.. Security response headers
  * EXP-001   Basic public exposure

SSRF hardening (docs/PROJECT_CONTEXT.md §13):
  * only http/https schemes, ports 80/443 only
  * private, loopback, link-local, reserved, multicast, unspecified, and
    cloud-metadata IPs (incl. 169.254.169.254 / 100.100.100.200) are rejected
  * every redirect hop is re-validated before it is followed
  * a short timeout and a hard response-size cap are enforced
  * no subprocess execution; only the exact URL (plus one TLS probe of the
    same host) is fetched
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address
from socket import getaddrinfo
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

from ..tests.url_security.test_cases import URL_SECURITY_TEST_MAP

ALLOWED_SCHEMES = ("http", "https")
ALLOWED_PORTS = (80, 443)
MAX_REDIRECTS = 3
REQUEST_TIMEOUT = 8
MAX_RESPONSE_BYTES = 524288

CLOUD_METADATA_HOSTS = {
    "metadata",
    "metadata.google.internal",
    "metadata.azure.internal",
    "metadata.aws.internal",
    "metadata.aliyuncs.com",
}

CLOUD_METADATA_IPS = {
    "169.254.169.254",
    "169.254.170.2",
    "100.100.100.200",
    "100.100.100.204",
}

REQUEST_HEADERS = {
    "User-Agent": "NullVector/0.1 (security scanner; authorized target)",
}

SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

REVERSE_SEVERITY = {rank: name for name, rank in SEVERITY_RANK.items()}


class UnsafeUrlError(ValueError):
    """The target failed a safety check and must not be scanned."""


class UrlConnectionError(ConnectionError):
    """The target could not be reached by the scanner."""


@dataclass(frozen=True)
class TargetInfo:
    scheme: str
    host: str
    port: int
    path: str
    ips: tuple
    primary_ip: str


@dataclass
class FetchRecord:
    status_code: Optional[int] = None
    headers: dict = field(default_factory=dict)
    body_size: int = 0
    truncated: bool = False
    ssl_error: Optional[str] = None
    scheme: Optional[str] = None
    final_url: Optional[str] = None
    hops: int = 0


def _is_ip_literal(host):
    try:
        ip_address(host)
        return True
    except ValueError:
        return False


def _ip_is_restricted(ip):
    if ip in CLOUD_METADATA_IPS:
        return True
    try:
        address = ip_address(ip)
    except ValueError:
        return True
    return any(
        (
            address.is_private,
            address.is_loopback,
            address.is_link_local,
            address.is_reserved,
            address.is_multicast,
            address.is_unspecified,
        )
    )


def resolve_host(host):
    try:
        infos = getaddrinfo(host, None)
    except OSError as exc:
        raise UnsafeUrlError(f"Could not resolve host {host!r}: {exc}.") from exc
    return sorted({info[4][0] for info in infos})


def _absolute_url(scheme, host, port, path):
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{host}{path}"
    return f"{scheme}://{host}:{port}{path}"


def _scheme_of(url):
    return urlparse(url).scheme.lower() or "http"


def resolve_target(url, *, resolver=None):
    """Validate and resolve a URL, rejecting any non-public target."""
    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeUrlError(
            f"Unsupported scheme {parsed.scheme!r}. Only http and https are allowed."
        )

    host = parsed.hostname
    if not host:
        raise UnsafeUrlError("The supplied URL has no host to scan.")

    host = host.strip("[]").rstrip(".").lower()

    if parsed.username is not None or parsed.password is not None:
        raise UnsafeUrlError("URLs that embed credentials are not allowed.")

    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80
    if port not in ALLOWED_PORTS:
        raise UnsafeUrlError(
            f"Port {port} is not allowed. URL scanning is limited to ports 80 and 443."
        )

    if host in CLOUD_METADATA_HOSTS:
        raise UnsafeUrlError(
            f"Target host {host!r} is a reserved cloud-metadata host and is not allowed."
        )

    resolver = resolver or resolve_host

    if _is_ip_literal(host):
        if _ip_is_restricted(host):
            raise UnsafeUrlError(
                f"Target is a non-public IP ({host!r}) and cannot be scanned."
            )
        ips = [host]
    else:
        ips = list(resolver(host))
        if not ips:
            raise UnsafeUrlError(f"Could not resolve host {host!r}.")

    restricted = [ip for ip in ips if _ip_is_restricted(ip)]
    if restricted:
        raise UnsafeUrlError(
            f"Target resolves to a non-public IP ({restricted[0]!r}) and cannot be scanned."
        )

    path = parsed.path or "/"
    return TargetInfo(scheme, host, port, path, tuple(ips), ips[0])


def default_fetch(url, *, timeout=REQUEST_TIMEOUT, max_bytes=MAX_RESPONSE_BYTES):
    """Fetch a URL with SSRF guards, capped redirects, and a size limit."""
    resolve_target(url)

    current = url
    for hops in range(1, MAX_REDIRECTS + 1):
        try:
            response = requests.get(
                current,
                timeout=timeout,
                allow_redirects=False,
                headers=REQUEST_HEADERS,
                stream=True,
            )
        except requests.exceptions.SSLError as exc:
            return FetchRecord(
                ssl_error=str(exc)[:200],
                scheme=_scheme_of(current),
                final_url=current,
                hops=hops,
            )
        except requests.exceptions.RequestException as exc:
            raise UrlConnectionError(
                f"Could not reach target {urlparse(current).hostname!r}: "
                f"{exc.__class__.__name__}."
            ) from exc

        scheme = _scheme_of(current)

        if response.is_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                return FetchRecord(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    scheme=scheme,
                    final_url=current,
                    hops=hops,
                )
            next_url = urljoin(current, location)
            resolve_target(next_url)
            current = next_url
            continue

        headers = {key.lower(): value for key, value in response.headers.items()}
        body_size = int(response.headers.get("Content-Length") or 0)
        truncated = False
        for chunk in response.iter_content(chunk_size=16384):
            body_size += len(chunk)
            if body_size > max_bytes:
                truncated = True
                break
        response.close()

        return FetchRecord(
            status_code=response.status_code,
            headers=headers,
            body_size=body_size,
            truncated=truncated,
            scheme=scheme,
            final_url=current,
            hops=hops,
        )

    raise UrlConnectionError("Target exceeded the maximum number of redirects.")


def _new_finding(test_id, status, severity, confidence, summary, evidence):
    meta = URL_SECURITY_TEST_MAP[test_id]
    return {
        "test_id": test_id,
        "category": meta["category"],
        "status": status,
        "severity": severity,
        "confidence": confidence,
        "summary": summary,
        "evidence": evidence,
        "recommendation": meta["recommendation"],
    }


def _check_tls(target, main, fetch):
    test_id = "TLS-001"
    scheme, host, port, path = target.scheme, target.host, target.port, target.path

    if scheme == "https":
        if main.ssl_error:
            return _new_finding(
                test_id,
                "vulnerable",
                "high",
                "high",
                "HTTPS is served with an invalid or untrusted certificate.",
                f"Certificate verification failed: {main.ssl_error}.",
            )
        if main.status_code:
            return _new_finding(
                test_id,
                "pass",
                "info",
                "high",
                "HTTPS is available with a valid certificate.",
                f"GET https://{host} returned HTTP {main.status_code}.",
            )
        return _new_finding(
            test_id,
            "warning",
            "medium",
            "medium",
            "HTTPS could not be verified.",
            f"No usable TLS response was received from {host}.",
        )

    try:
        probe = fetch(_absolute_url("https", host, 443, path))
    except UrlConnectionError as exc:
        return _new_finding(
            test_id,
            "warning",
            "medium",
            "medium",
            "The target does not appear to offer HTTPS.",
            f"TLS probe of {host} failed: {exc}.",
        )

    if probe.ssl_error:
        return _new_finding(
            test_id,
            "vulnerable",
            "high",
            "high",
            "HTTPS is served with an invalid or untrusted certificate.",
            f"Certificate verification failed: {probe.ssl_error}.",
        )
    if probe.status_code:
        return _new_finding(
            test_id,
            "pass",
            "info",
            "high",
            "HTTPS is available with a valid certificate.",
            f"GET https://{host} returned HTTP {probe.status_code}.",
        )
    return _new_finding(
        test_id,
        "warning",
        "medium",
        "medium",
        "HTTPS could not be verified.",
        f"No usable TLS response was received from {host}.",
    )


def _check_headers(target, main):
    findings = []

    if main.status_code is None or main.ssl_error:
        return findings

    for test_id, meta in URL_SECURITY_TEST_MAP.items():
        header = meta.get("header")
        if not header:
            continue

        value = main.headers.get(header.lower())
        if value is None or value == "":
            findings.append(
                _new_finding(
                    test_id,
                    "warning",
                    "medium" if test_id in ("HDR-001", "HDR-002") else "low",
                    "high",
                    f"{meta['title']} is missing.",
                    f"Response from {target.host} did not include the "
                    f"{header!r} header.",
                )
            )
            continue

        if test_id == "HDR-003" and value.strip().lower() != "nosniff":
            findings.append(
                _new_finding(
                    test_id,
                    "warning",
                    "low",
                    "high",
                    "X-Content-Type-Options is not set to nosniff.",
                    f"Header value was {value!r}; expected 'nosniff'.",
                )
            )
            continue

        findings.append(
            _new_finding(
                test_id,
                "pass",
                "info",
                "high",
                f"{meta['title']} is present.",
                f"Header {header!r} was set to {value[:120]!r}.",
            )
        )

    return findings


def _check_exposure(target, main):
    test_id = "EXP-001"
    summary = "Target is publicly reachable."
    severity = "info"
    evidence = (
        f"Host {target.host} resolved to public IP {target.primary_ip} and "
        f"returned HTTP {main.status_code if main.status_code else 'n/a'}."
    )

    if main.ssl_error or main.status_code is None:
        return _new_finding(
            test_id,
            "warning",
            "medium",
            "high",
            "The target did not return a usable response.",
            f"Host {target.host} resolved to public IP {target.primary_ip} but "
            "no usable HTTP response was received.",
        )

    if main.hops:
        evidence += f" Request followed {main.hops} redirect(s) to {main.final_url}."
        if urlparse(main.final_url).hostname != target.host:
            summary = "Target redirects to a different host."
            severity = "medium"

    if main.truncated:
        evidence += (
            f" Response body exceeded {MAX_RESPONSE_BYTES} bytes and inspection "
            "was truncated."
        )
        summary = "Target response exceeded the scan size limit."
        severity = "low"

    return _new_finding(
        test_id,
        "pass" if severity == "info" else "warning",
        severity,
        "high",
        summary,
        evidence,
    )


def _overall_risk(findings):
    rank = max(SEVERITY_RANK[finding["severity"]] for finding in findings)
    return REVERSE_SEVERITY[rank]


def run_url_scan(url, *, resolver=None, fetch=None):
    """Run the three URL security checks and return normalized findings."""
    target = resolve_target(url, resolver=resolver)
    fetcher = fetch or default_fetch

    main = fetcher(url)

    findings = [
        _check_tls(target, main, fetcher),
        *(_check_headers(target, main)),
        _check_exposure(target, main),
    ]

    return {
        "url": url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "risk": _overall_risk(findings),
        "findings_count": len(findings),
        "target": {
            "host": target.host,
            "resolved_ip": target.primary_ip,
            "scheme": target.scheme,
        },
        "findings": findings,
    }
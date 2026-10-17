"""URL security scan service.

Thin delegation layer mirroring llm_service.py: the backend calls the scanner
engine in ai/scanner and returns the normalized scan result unchanged.
"""

from ai.scanner.engine.url_scanner import run_url_scan


def scan_url(url: str) -> dict:
    """Scan an authorized public URL and return normalized findings."""
    return run_url_scan(url)
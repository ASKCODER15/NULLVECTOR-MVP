"""Tests for the static frontend.

The safety tests are regression guards for the defect the retired OnyxSec UI
had: model-derived text interpolated into an HTML sink. The current frontend
must render untrusted values as text only.
"""

import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"
for path in (REPO_ROOT, BACKEND_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from app.main import app
from fastapi.testclient import TestClient

FRONTEND = REPO_ROOT / "frontend"

# Assigning to these from untrusted strings turns data into markup/script.
UNSAFE_DOM_PATTERNS = (
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "eval(",
)


class FrontendServedTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_ui_is_served(self):
        response = self.client.get("/app/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])
        self.assertIn("NullVector", response.text)
        self.assertIn("authorized", response.text)

    def test_assets_are_served(self):
        script = self.client.get("/app/app.js")
        self.assertEqual(script.status_code, 200)
        self.assertIn("javascript", script.headers["content-type"])

        styles = self.client.get("/app/styles.css")
        self.assertEqual(styles.status_code, 200)
        self.assertIn("css", styles.headers["content-type"])

    def test_api_root_still_returns_json(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["project"], "NullVector")
        self.assertEqual(body["ui"], "/app/")


class FrontendSafetyTests(unittest.TestCase):
    def test_javascript_never_assigns_html(self):
        source = (FRONTEND / "app.js").read_text(encoding="utf-8")
        for pattern in UNSAFE_DOM_PATTERNS:
            self.assertNotIn(
                pattern,
                source,
                msg=f"app.js must not use {pattern!r}; render untrusted text with textContent",
            )

    def test_markup_has_no_inline_handlers(self):
        markup = (FRONTEND / "index.html").read_text(encoding="utf-8")
        handlers = re.findall(r"\son[a-z]+\s*=", markup, flags=re.IGNORECASE)
        self.assertEqual(handlers, [], msg=f"inline event handlers found: {handlers}")

    def test_markup_loads_no_remote_assets(self):
        markup = (FRONTEND / "index.html").read_text(encoding="utf-8")
        remote = re.findall(r'(?:src|href)="https?://[^"]+"', markup, flags=re.IGNORECASE)
        self.assertEqual(remote, [], msg=f"remote assets found: {remote}")


if __name__ == "__main__":
    unittest.main()

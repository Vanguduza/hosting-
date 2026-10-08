import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/api"))
from hosting_api.portal import ASSETS, serve


class Response:
    def __init__(self):
        self.wfile = io.BytesIO()
        self.headers = {}
        self.status = None

    def send_response(self, status):
        self.status = status

    def send_header(self, name, value):
        self.headers[name] = value

    def end_headers(self):
        pass


class PortalTests(unittest.TestCase):
    def test_assets_are_public_static_content_with_browser_boundaries(self):
        for path in ASSETS:
            with self.subTest(path=path):
                response = Response()
                self.assertTrue(serve(response, path))
                self.assertEqual(response.status, 200)
                self.assertEqual(int(response.headers["Content-Length"]), len(response.wfile.getvalue()))
                self.assertEqual(response.headers["Cache-Control"], "no-store")
                self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
                self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
                self.assertIn("connect-src 'self'", response.headers["Content-Security-Policy"])
                self.assertNotIn("unsafe-inline", response.headers["Content-Security-Policy"])
                self.assertNotIn("Set-Cookie", response.headers)

    def test_unlisted_and_traversal_paths_never_read_files(self):
        for path in ("/portal/../__main__.py", "/portal/%2e%2e/__main__.py", "/portal/index.html",
                     "/portal/portal.py", "/portal/portal.mjs/", "/portal//portal.css", "/etc/passwd"):
            with self.subTest(path=path):
                response = Response()
                self.assertFalse(serve(response, path))
                self.assertIsNone(response.status)
                self.assertEqual(response.wfile.getvalue(), b"")

    def test_page_has_external_assets_and_accessible_feedback(self):
        response = Response()
        serve(response, "/portal")
        html = response.wfile.getvalue().decode()
        self.assertIn('src="/portal/portal.mjs"', html)
        self.assertIn('href="/portal/portal.css"', html)
        self.assertIn('aria-live="polite"', html)
        self.assertIn('type="password"', html)
        self.assertNotIn("onclick=", html)

"""Operator CLI contract and local transport boundary checks."""
import io
import json
import os
import re
import sys
import tempfile
import threading
import unittest
import uuid
from contextlib import redirect_stdout, redirect_stderr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "services/api"))
from hosting_cli import call, main, origin, parser, private_file, request_for
from hosting_api.openapi import document


class CliTests(unittest.TestCase):
    def test_transport_rejects_nonlocal_http_and_redirects(self):
        for invalid in ("http://control.example:8080", "https://user:password@control.example:443",
                        "https://control.example:443/path", "https://control.example:443/?token=x"):
            with self.subTest(origin=invalid), self.assertRaises(ValueError):
                origin(invalid)
        self.assertEqual(origin("http://127.0.0.1:8080"), "http://127.0.0.1:8080")

        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "https://other.example.invalid/steal")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with self.assertRaisesRegex(ValueError, "Redirect rejected"):
                call(f"http://127.0.0.1:{server.server_port}", "/ready", "jwt-value")
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)

    def test_private_token_file_and_http_request(self):
        with tempfile.TemporaryDirectory() as temp:
            token = Path(temp) / "token"
            token.write_text("eyJhbGciOiJSUzI1NiJ9.payload.signature")
            os.chmod(token, 0o600)
            self.assertEqual(private_file(str(token), "API token"), token.read_text())
            os.chmod(token, 0o644)
            with self.assertRaises(ValueError):
                private_file(str(token), "API token")
            os.chmod(token, 0o600)

            class Capture(BaseHTTPRequestHandler):
                def do_POST(self):
                    self.server.observed = {"path": self.path,
                        "authorization": self.headers.get("Authorization"),
                        "body": json.loads(self.rfile.read(int(self.headers["Content-Length"]))) }
                    payload = b'{"id":"test","state":"QUEUED"}'
                    self.send_response(202)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)

                def log_message(self, *args):
                    pass

            server = ThreadingHTTPServer(("127.0.0.1", 0), Capture)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            org, app, key = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
            try:
                output = io.StringIO()
                with redirect_stdout(output):
                    code = main(["--base-url", f"http://127.0.0.1:{server.server_port}",
                                 "--token-file", str(token), "postgres-create", org, app, "512", "250",
                                 "--idempotency-key", key])
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(output.getvalue())["idempotency_key"], key)
                self.assertEqual(server.observed["authorization"], "Bearer " + token.read_text())
                self.assertEqual(server.observed["path"], f"/v1/organizations/{org}/applications/{app}/postgres")
                self.assertEqual(server.observed["body"],
                                 {"idempotency_key": key, "memory_mb": 512, "cpu_milli": 250})
                self.assertNotIn(token.read_text(), output.getvalue())
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=5)

    def test_every_cli_command_maps_to_published_route(self):
        one, two, three, four = (str(uuid.uuid4()) for _ in range(4))
        samples = {
            "live": [], "ready": [], "openapi": [], "orgs": [],
            "audit": [one], "capacity": [one, "2026-09-24T00:00:00Z", "2026-09-25T00:00:00Z"],
            "projects": [one], "project-create": [one, "alpha"],
            "applications": [one, two], "application-create": [one, two, "api", "production"],
            "traffic": [one, three], "suspend": [one, three, "Owner requested pause"],
            "resume": [one, three, "Owner requested resume"],
            "domain": [one, three], "domain-register": [one, three, "app.example.org"],
            "domain-verify": [one, three], "builds": [one, three],
            "releases": [one, three], "release-queue": [one, three,
                "registry.example/app@sha256:" + "a" * 64, "8080", "/health", "256", "250"],
            "rollback": [one, three, four], "postgres": [one, three],
            "postgres-create": [one, three, "512", "250"], "valkey": [one, three],
            "valkey-create": [one, three, "256", "250"], "team-invitations": [one],
            "team-invite": [one, "admin", "24"], "team-revoke": [one, four],
            "team-members": [one], "team-remove": [one, "subject"],
        }
        paths = document()["paths"]
        for name, params in samples.items():
            with self.subTest(command=name):
                args = parser().parse_args(["--base-url", "https://control.example:443", name, *params])
                path, body, key = request_for(args)
                matching = [template for template in paths if re.fullmatch(
                    re.sub(r"\{[^}]+\}", "[^/]+", template), path.partition("?")[0])]
                self.assertEqual(len(matching), 1)
                self.assertIn("post" if body is not None else "get", paths[matching[0]])
                if name in ("team-invite", "release-queue", "rollback", "postgres-create", "valkey-create"):
                    self.assertEqual(body["idempotency_key"], key)
        args = parser().parse_args(["--base-url", "https://control.example:443", "audit", one,
                                    "--after", "42"])
        self.assertEqual(request_for(args)[0], f"/v1/organizations/{one}/audit?after=42")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "invitation"
            path.write_text("A" * 43)
            os.chmod(path, 0o600)
            args = parser().parse_args(["--base-url", "https://control.example:443", "team-accept",
                                        "--invitation-file", str(path)])
            self.assertEqual(request_for(args)[0], "/v1/team/invitations/accept")


if __name__ == "__main__":
    unittest.main()

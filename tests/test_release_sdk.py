"""Exercise the installable machine client against a local HTTP contract boundary."""
import json
import sys
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk/python"))
from dial_hosting import ApiError, ClientError, ReleaseClient


class LocalApi(BaseHTTPRequestHandler):
    calls = []
    def do_GET(self):
        self.calls.append(("GET", self.path, self.headers.get("Authorization"), None))
        self.respond(200, {"releases": []})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.calls.append(("POST", self.path, self.headers.get("Authorization"), body))
        if body["port"] == 9999:
            return self.respond(409, {"error": "capacity_unavailable"})
        if body["port"] == 9998:
            self.send_response(307)
            self.send_header("Location", "http://127.0.0.1:1/other")
            self.end_headers()
            return
        self.respond(202, {"id": str(uuid.uuid4()), "state": "QUEUED"})

    def respond(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class ReleaseClientTests(unittest.TestCase):
    def test_scoped_requests_token_rotation_errors_and_redirect(self):
        LocalApi.calls = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), LocalApi)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            org, app, key = (str(uuid.uuid4()) for _ in range(3))
            tokens = iter(("first", "second", "third", "fourth"))
            client = ReleaseClient(f"http://127.0.0.1:{server.server_port}", org, app, lambda: next(tokens))
            self.assertEqual(client.list_releases(), [])
            image = "registry.example.org/team/app@sha256:" + "a" * 64
            self.assertEqual(client.queue_release(image, 8080, "/health", 128, 100,
                                                  idempotency_key=key)["state"], "QUEUED")
            with self.assertRaises(ApiError) as failure:
                client.queue_release(image, 9999, "/health", 128, 100, idempotency_key=key)
            self.assertEqual((failure.exception.status, failure.exception.code), (409, "capacity_unavailable"))
            with self.assertRaises(ClientError):
                client.queue_release(image, 9998, "/health", 128, 100, idempotency_key=key)
            self.assertEqual(len(LocalApi.calls), 4)
            self.assertEqual([call[2] for call in LocalApi.calls],
                             ["Bearer first", "Bearer second", "Bearer third", "Bearer fourth"])
            self.assertTrue(all(call[1] == f"/v1/organizations/{org}/applications/{app}/releases"
                                for call in LocalApi.calls))
            self.assertEqual(LocalApi.calls[1][3]["idempotency_key"], key)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_rejects_remote_plaintext_and_invalid_spec_without_token(self):
        with self.assertRaises(ClientError):
            ReleaseClient("http://public.example.org:8080", str(uuid.uuid4()), str(uuid.uuid4()), lambda: "token")
        org, app = str(uuid.uuid4()), str(uuid.uuid4())
        client = ReleaseClient("https://api.example.org:443", org, app, lambda: "token")
        with self.assertRaises(ClientError):
            client.queue_release("mutable:latest", 8080, "/health", 128, 100,
                                 idempotency_key=str(uuid.uuid4()))

import hashlib
import hmac
import json
import sys
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/api"))
from hosting_api.event_worker import deliver, endpoint


class EventDeliveryTests(unittest.TestCase):
    def test_endpoint_requires_fixed_https_target(self):
        for url in ("http://example.org/events", "https://localhost/events",
                    "https://user:pass@example.org/events", "https://example.org/events?token=x",
                    "https://example.org/events#anchor", "https://example.org",
                    "https://example.org:bad/events"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                endpoint(url)
        self.assertEqual(endpoint("https://events.example.org:443/ingest").path, "/ingest")

    def test_signature_and_stable_event_id(self):
        event_id = 123
        row = {"audit_event_id": event_id, "organization_id": uuid.uuid4(),
               "actor_sub": "alice", "action": "release.serving", "resource_id": uuid.uuid4(),
               "request_id": uuid.uuid4(), "previous_hash": "a" * 64, "event_hash": "b" * 64,
               "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc)}
        calls = []

        class Response:
            status = 202

            def read(self, limit):
                return b""

        class Connection:
            def __init__(self, host, port, *, context, timeout):
                self.assertions = (host, port, timeout)

            def request(self, method, path, *, body, headers):
                calls.append((method, path, body, headers))

            def getresponse(self):
                return Response()

            def close(self):
                pass

        with patch("hosting_api.event_worker.http.client.HTTPSConnection", Connection):
            deliver(row, endpoint("https://events.example.org/ingest"), b"s" * 32, now=1234567890)
        method, path, body, headers = calls[0]
        self.assertEqual((method, path), ("POST", "/ingest"))
        self.assertEqual(json.loads(body)["id"], event_id)
        self.assertEqual(headers["X-Dial-Event-Id"], str(event_id))
        self.assertEqual(headers["X-Dial-Event-Signature"], "v1=" + hmac.new(
            b"s" * 32, b"1234567890." + body, hashlib.sha256).hexdigest())


if __name__ == "__main__":
    unittest.main()

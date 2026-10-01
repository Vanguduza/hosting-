"""The committed outbox sender and isolated receiver share one exact wire contract."""
import hashlib
import http.client
import json
import sys
import tempfile
import threading
import unittest
import uuid
from contextlib import closing
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "services/api"))
from event_receiver import Handler, accept, connect, inspect
from hosting_api.event_worker import deliver, endpoint


class EventReceiverTests(unittest.TestCase):
    def test_actual_sender_is_durable_idempotent_and_chain_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "events.sqlite3"
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            server.database, server.signing_key = db_path, b"s" * 32
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            class LocalTLS:
                def __init__(self, hostname, port, *, context, timeout):
                    self.connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=timeout)

                def request(self, *args, **kwargs):
                    self.connection.request(*args, **kwargs)

                def getresponse(self):
                    return self.connection.getresponse()

                def close(self):
                    self.connection.close()

            org = uuid.uuid4()

            def event(id_, previous=""):
                actor, action, resource, request = "alice", "release.serving", uuid.uuid4(), uuid.uuid4()
                value = hashlib.sha256((previous + actor + action + str(resource) + str(request)).encode()).hexdigest()
                return {"audit_event_id": id_, "organization_id": org, "actor_sub": actor,
                        "action": action, "resource_id": resource, "request_id": request,
                        "previous_hash": previous, "event_hash": value,
                        "created_at": datetime.now(timezone.utc)}

            first = event(10)
            second = event(12, first["event_hash"])
            missing = event(14, second["event_hash"])
            try:
                with patch("hosting_api.event_worker.http.client.HTTPSConnection", LocalTLS):
                    deliver(first, endpoint("https://events.example.org/ingest"), b"s" * 32)
                    with self.assertRaises(RuntimeError):
                        deliver(missing, endpoint("https://events.example.org/ingest"), b"s" * 32)
                    deliver(second, endpoint("https://events.example.org/ingest"), b"s" * 32)
                    deliver(first, endpoint("https://events.example.org/ingest"), b"s" * 32)
                with closing(connect(db_path)) as db:
                    self.assertEqual(inspect(db)["events"], 2)
                    db.execute("UPDATE events SET action='privileged.rewrite' WHERE id=10")
                    with self.assertRaisesRegex(RuntimeError, "chain invalid"):
                        inspect(db)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()

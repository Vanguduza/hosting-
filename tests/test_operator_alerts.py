"""Operator alerts survive check restarts and delivery uncertainty."""
import hashlib
import hmac
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from operator_alerts import (CHECKS, claim, connect, deliver, destination, dispatch,
                             finalize, health, observe, run_check)


class OperatorAlertTests(unittest.TestCase):
    def test_transition_queue_survives_restart_and_reports_unacknowledged_alerts(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "alerts.sqlite3"
            db = connect(file)
            self.assertEqual(run_check(db, "release", [sys.executable, "-c", "pass"], 10), 0)
            self.assertEqual(run_check(db, "release", [sys.executable, "-c", "raise SystemExit(2)"], 10), 2)
            self.assertEqual(run_check(db, "release", [sys.executable, "-c", "raise SystemExit(2)"], 10), 2)
            first = db.execute("SELECT * FROM alerts").fetchall()
            self.assertEqual(len(first), 1)
            self.assertEqual(first[0]["state"], "DOWN")
            db.close()
            db = connect(file)
            row = claim(db)
            self.assertEqual(row["id"], first[0]["id"])
            self.assertIsNone(claim(db))
            self.assertTrue(finalize(db, row, "receiver unavailable"))
            self.assertIsNone(claim(db))  # bounded retry delay
            db.execute("UPDATE alerts SET next_at=0 WHERE id=?", (row["id"],))
            retried = claim(db)
            self.assertEqual(retried["id"], row["id"])
            self.assertFalse(finalize(db, row))  # stale lease cannot acknowledge
            self.assertTrue(finalize(db, retried))
            self.assertEqual(run_check(db, "release", [sys.executable, "-c", "pass"], 10), 0)
            recovery = claim(db)
            self.assertEqual((recovery["state"], recovery["sequence"]), ("UP", 2))
            for name in CHECKS - {"release"}:
                observe(db, name, True)
            self.assertEqual(health(db)["pending"], 1)
            finalize(db, recovery)
            self.assertTrue(health(db)["healthy"])
            db.close()

    def test_expired_claim_retries_same_id_and_dead_alert_is_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            db = connect(Path(directory) / "alerts.sqlite3")
            alert_id = observe(db, "node", False)
            claimed = claim(db)
            db.execute("UPDATE alerts SET lease_until=0 WHERE id=?", (alert_id,))
            again = claim(db)
            self.assertEqual(again["id"], alert_id)
            self.assertFalse(finalize(db, claimed))
            db.execute("UPDATE alerts SET attempts=12,lease_token=NULL,lease_until=NULL WHERE id=?", (alert_id,))
            self.assertEqual(health(db)["dead"], [alert_id])
            self.assertIsNone(claim(db))
            db.close()

    def test_signed_delivery_and_rejects_unsafe_receiver(self):
        for target in ("http://alerts.example.org/ingest", "https://localhost/ingest",
                       "https://user:pass@alerts.example.org/ingest",
                       "https://alerts.example.org/ingest?key=secret", "https://alerts.example.org"):
            with self.assertRaises(ValueError):
                destination(target)
        calls = []

        class Response:
            status = 204

            def read(self, count):
                return b""

        class Connection:
            def __init__(self, *args, **kwargs):
                pass

            def request(self, method, path, *, body, headers):
                calls.append((method, path, body, headers))

            def getresponse(self):
                return Response()

            def close(self):
                pass

        row = {"id": "sample-id", "name": "event", "sequence": 4,
               "state": "DOWN", "created_at": int(time.time())}
        with patch("operator_alerts.http.client.HTTPSConnection", Connection):
            deliver(row, destination("https://alerts.example.org/ingest"), b"s" * 32)
        method, path, body, headers = calls[0]
        self.assertEqual((method, path, json.loads(body)["id"]), ("POST", "/ingest", "sample-id"))
        expected = hmac.new(b"s" * 32, headers["X-Dial-Alert-Timestamp"].encode() + b"." + body,
                            hashlib.sha256).hexdigest()
        self.assertEqual(headers["X-Dial-Alert-Signature"], "v1=" + expected)

    def test_dispatch_retries_without_losing_next_transition(self):
        with tempfile.TemporaryDirectory() as directory:
            db = connect(Path(directory) / "alerts.sqlite3")
            down = observe(db, "external", False)
            up = observe(db, "external", True)
            with patch("operator_alerts.deliver", side_effect=OSError("offline")):
                self.assertEqual(dispatch(db, destination("https://alerts.example.org/a"), b"k" * 32), 1)
            self.assertIsNone(db.execute("SELECT delivered_at FROM alerts WHERE id=?", (down,)).fetchone()[0])
            self.assertIsNone(db.execute("SELECT delivered_at FROM alerts WHERE id=?", (up,)).fetchone()[0])
            db.execute("UPDATE alerts SET next_at=0 WHERE id=?", (down,))
            with patch("operator_alerts.deliver") as send:
                self.assertEqual(dispatch(db, destination("https://alerts.example.org/a"), b"k" * 32), 2)
                self.assertEqual([call.args[0]["id"] for call in send.call_args_list], [down, up])
            db.close()


if __name__ == "__main__":
    unittest.main()

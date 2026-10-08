"""A receiver acknowledges only authenticated and durably deduplicated alerts."""
import hashlib
import hmac
import http.client
import json
import smtplib
import sys
import tempfile
import threading
import time
import unittest
import uuid
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
from http.server import ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services"))
from alert_receiver import Handler, accept, claim, connect, dispatch, finish, health, mail, validate


class AlertReceiverTests(unittest.TestCase):
    def signed(self, alert, key, stamp):
        body = json.dumps(alert, separators=(",", ":")).encode()
        return body, {"X-Dial-Alert-Id": alert["id"], "X-Dial-Alert-Timestamp": str(stamp),
                      "X-Dial-Alert-Signature": "v1=" + hmac.new(
                          key, str(stamp).encode() + b"." + body, hashlib.sha256).hexdigest()}

    def test_http_ingest_deduplicates_and_does_not_acknowledge_bad_signatures(self):
        now = int(time.time())
        key = b"k" * 32
        alert = {"id": str(uuid.uuid4()), "check": "node", "sequence": 0,
                 "state": "DOWN", "created_at": now}
        body, headers = self.signed(alert, key, now)
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "receiver.sqlite3"
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            server.signing_key, server.database = key, database
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                def post(payload, signed_headers):
                    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                    try:
                        conn.request("POST", "/ingest", payload, signed_headers)
                        response = conn.getresponse()
                        response.read()
                        return response.status
                    finally:
                        conn.close()

                self.assertEqual(post(body, headers), 202)
                self.assertEqual(post(body, headers), 202)
                self.assertEqual(post(body, {**headers, "X-Dial-Alert-Signature": "v1=" + "0" * 64}), 401)
                self.assertEqual(post(body, {**headers, "X-Dial-Alert-Timestamp": str(now-600)}), 401)
                changed = {**alert, "state": "UP"}
                changed_body, changed_headers = self.signed(changed, key, now)
                self.assertEqual(post(changed_body, changed_headers), 409)
                with closing(connect(database)) as db:
                    self.assertEqual(db.execute("SELECT count(*) FROM alerts").fetchone()[0], 1)
                    self.assertEqual(db.execute("SELECT state FROM alerts").fetchone()[0], "DOWN")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

    def test_delivery_retries_and_fences_expired_lease(self):
        now = int(time.time())
        with tempfile.TemporaryDirectory() as directory, closing(connect(Path(directory) / "db")) as db:
            first = {"id": str(uuid.uuid4()), "check": "release", "sequence": 0,
                     "state": "DOWN", "created_at": now}
            second = {**first, "id": str(uuid.uuid4()), "sequence": 1, "state": "UP"}
            self.assertTrue(accept(db, first, json.dumps(first).encode()))
            self.assertFalse(accept(db, first, json.dumps(first).encode()))
            self.assertTrue(accept(db, second, json.dumps(second).encode()))
            old = claim(db)
            self.assertEqual(old["id"], first["id"])
            self.assertIsNone(claim(db))
            db.execute("UPDATE alerts SET lease_until=0 WHERE id=?", (old["id"],))
            new = claim(db)
            self.assertFalse(finish(db, old))
            self.assertTrue(finish(db, new, "SMTP unavailable"))
            self.assertIsNone(claim(db))
            db.execute("UPDATE alerts SET next_at=0 WHERE id=?", (old["id"],))
            sent = []
            with patch("alert_receiver.mail", side_effect=lambda row, config, password: sent.append(row["id"])):
                self.assertEqual(dispatch(db, {}, "password"), 2)
            self.assertEqual(sent, [first["id"], second["id"]])
            self.assertTrue(health(db)["healthy"])

    def test_authentication_rejects_replay_and_malformed_event(self):
        key, now = b"k" * 32, int(time.time())
        alert = {"id": str(uuid.uuid4()), "check": "external", "sequence": 7,
                 "state": "DOWN", "created_at": now}
        body, headers = self.signed(alert, key, now)
        self.assertEqual(validate(headers, body, key, now), alert)
        with self.assertRaises(PermissionError):
            validate(headers, body, key, now + 301)
        bad_body, bad_headers = self.signed({**alert, "sequence": True}, key, now)
        with self.assertRaises(ValueError):
            validate(bad_headers, bad_body, key, now)

    def test_mail_requires_tls_before_authentication_and_reports_partial_refusal(self):
        actions = []

        class SMTP:
            refused = False
            def __init__(self, host, port, timeout):
                actions.append(("connect", host, port, timeout))

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def ehlo(self):
                actions.append("ehlo")

            def starttls(self, *, context):
                actions.append("tls")

            def login(self, user, password):
                actions.append("login")

            def send_message(self, message):
                actions.append(("send", message["Message-ID"]))
                return {"owner@example.org": (550, b"rejected")} if self.refused else {}

        config = {"smtp_host": "smtp.example.org", "smtp_port": 587,
                  "smtp_user": "alerts@example.org", "from": "alerts@example.org",
                  "to": ["owner@example.org"], "message_domain": "example.org"}
        row = {"id": str(uuid.uuid4()), "name": "node", "state": "DOWN",
               "sequence": 0, "created_at": int(time.time())}
        with patch("alert_receiver.smtplib.SMTP", SMTP):
            mail(row, config, "private-password")
        self.assertEqual(actions[:4], [("connect", "smtp.example.org", 587, 15),
                                       "ehlo", "tls", "ehlo"])
        self.assertEqual(actions[4], "login")
        self.assertIn(row["id"], actions[5][1])
        SMTP.refused = True
        with patch("alert_receiver.smtplib.SMTP", SMTP), self.assertRaises(smtplib.SMTPRecipientsRefused):
            mail(row, config, "private-password")


if __name__ == "__main__":
    unittest.main()

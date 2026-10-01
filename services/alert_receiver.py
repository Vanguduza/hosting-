"""Durable HMAC alert intake and retryable SMTP delivery, behind an HTTPS proxy."""
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import sys
import time
import uuid
from contextlib import closing
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, sequence INTEGER NOT NULL,
 state TEXT NOT NULL, created_at INTEGER NOT NULL, body_sha256 TEXT NOT NULL,
 accepted_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
 next_at INTEGER NOT NULL, lease_token TEXT, lease_until INTEGER,
 delivered_at INTEGER, last_error TEXT,
 UNIQUE(name,sequence)
);
CREATE INDEX IF NOT EXISTS alerts_mail_due ON alerts(next_at,accepted_at)
 WHERE delivered_at IS NULL AND attempts<12;
"""
CHECKS = {"release", "node", "event", "external"}


def connect(path):
    path = Path(path)
    if path.is_symlink() or not path.parent.is_dir():
        raise RuntimeError("Receiver state unavailable")
    db = sqlite3.connect(path, timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout=10000")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.executescript(SCHEMA)
    path.chmod(0o600)
    return db


def validate(headers, body, key, now=None):
    now = int(time.time() if now is None else now)
    if not 32 <= len(key) <= 4096 or len(body) > 2048:
        raise ValueError("Invalid signature key or payload")
    alert_id = headers.get("X-Dial-Alert-Id", "")
    stamp = headers.get("X-Dial-Alert-Timestamp", "")
    signature = headers.get("X-Dial-Alert-Signature", "")
    if not re.fullmatch(r"[0-9]{10,11}", stamp) or abs(now - int(stamp)) > 300 or \
            not re.fullmatch(r"v1=[a-f0-9]{64}", signature):
        raise PermissionError("Invalid alert authentication")
    expected = "v1=" + hmac.new(key, stamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise PermissionError("Invalid alert authentication")
    try:
        alert = json.loads(body)
        if (type(alert) is not dict or set(alert) !=
                {"id", "check", "sequence", "state", "created_at"} or
                str(uuid.UUID(alert["id"])) != alert["id"] or
                alert["id"] != alert_id or alert["check"] not in CHECKS or
                type(alert["sequence"]) is not int or alert["sequence"] < 0 or
                alert["state"] not in ("UP", "DOWN") or
                type(alert["created_at"]) is not int or
                not 0 <= now - alert["created_at"] <= 86400):
            raise ValueError("Invalid alert")
    except (ValueError, TypeError, KeyError, UnicodeError, AttributeError) as exc:
        raise ValueError("Invalid alert payload") from exc
    return alert


def accept(db, alert, body, now=None):
    now = int(time.time() if now is None else now)
    digest = hashlib.sha256(body).hexdigest()
    db.execute("BEGIN IMMEDIATE")
    try:
        existing = db.execute("SELECT body_sha256 FROM alerts WHERE id=?", (alert["id"],)).fetchone()
        if existing:
            if existing["body_sha256"] != digest:
                raise ValueError("Alert ID collision")
            db.execute("COMMIT")
            return False
        # A different alert ID cannot reuse a check sequence.
        db.execute("INSERT INTO alerts(id,name,sequence,state,created_at,body_sha256,"
                   "accepted_at,next_at) VALUES (?,?,?,?,?,?,?,?)",
                   (alert["id"], alert["check"], alert["sequence"], alert["state"],
                    alert["created_at"], digest, now, now))
        db.execute("COMMIT")
        return True
    except BaseException:
        db.execute("ROLLBACK")
        raise


def claim(db, now=None):
    now = int(time.time() if now is None else now)
    db.execute("BEGIN IMMEDIATE")
    try:
        row = db.execute("SELECT a.* FROM alerts a WHERE a.delivered_at IS NULL AND a.attempts<12 "
                         "AND a.next_at<=? AND (a.lease_until IS NULL OR a.lease_until<?) "
                         "AND NOT EXISTS (SELECT 1 FROM alerts prior WHERE prior.name=a.name "
                         "AND prior.sequence<a.sequence AND prior.delivered_at IS NULL) "
                         "ORDER BY a.accepted_at,a.name,a.sequence LIMIT 1", (now, now)).fetchone()
        if row is None:
            db.execute("COMMIT")
            return None
        token = secrets.token_hex(16)
        db.execute("UPDATE alerts SET attempts=attempts+1,lease_token=?,lease_until=? WHERE id=?",
                   (token, now + 120, row["id"]))
        db.execute("COMMIT")
        return dict(row) | {"attempts": row["attempts"] + 1, "lease_token": token}
    except BaseException:
        db.execute("ROLLBACK")
        raise


def finish(db, row, error=None, now=None):
    now = int(time.time() if now is None else now)
    db.execute("BEGIN IMMEDIATE")
    try:
        if error is None:
            result = db.execute("UPDATE alerts SET delivered_at=?,lease_token=NULL,lease_until=NULL,"
                                "last_error=NULL WHERE id=? AND lease_token=?",
                                (now, row["id"], row["lease_token"]))
        else:
            result = db.execute("UPDATE alerts SET next_at=?,lease_token=NULL,lease_until=NULL,"
                                "last_error=? WHERE id=? AND lease_token=?",
                                (now + min(2 ** min(row["attempts"], 10), 3600),
                                 str(error)[:160], row["id"], row["lease_token"]))
        db.execute("COMMIT")
        return result.rowcount == 1
    except BaseException:
        db.execute("ROLLBACK")
        raise


def mail(row, config, password):
    message = EmailMessage()
    message["From"] = config["from"]
    message["To"] = ", ".join(config["to"])
    message["Subject"] = "DIAL monitor: %s %s" % (row["name"], row["state"])
    message["Message-ID"] = "<%s@%s>" % (row["id"], config["message_domain"])
    message.set_content("Monitor check: %s\nState: %s\nSequence: %s\nEvent ID: %s\n"
                        "Observed Unix time: %s\n" % (row["name"], row["state"],
                        row["sequence"], row["id"], row["created_at"]))
    context = ssl.create_default_context()
    with smtplib.SMTP(config["smtp_host"], config["smtp_port"], timeout=15) as smtp:
        smtp.ehlo()
        smtp.starttls(context=context)
        smtp.ehlo()
        smtp.login(config["smtp_user"], password)
        refused = smtp.send_message(message)
        if refused:
            raise smtplib.SMTPRecipientsRefused(refused)


def dispatch(db, config, password, limit=100):
    count = 0
    for _ in range(limit):
        row = claim(db)
        if row is None:
            break
        try:
            mail(row, config, password)
            finish(db, row)
        except (OSError, smtplib.SMTPException) as exc:
            finish(db, row, type(exc).__name__)
        count += 1
    return count


def health(db, max_age=300):
    now = int(time.time())
    rows = db.execute("SELECT id,attempts,accepted_at FROM alerts WHERE delivered_at IS NULL").fetchall()
    return {"pending": len(rows), "stale": [r["id"] for r in rows if now-r["accepted_at"]>max_age],
            "dead": [r["id"] for r in rows if r["attempts"]>=12],
            "healthy": not any(r["attempts"]>=12 or now-r["accepted_at"]>max_age for r in rows)}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/ingest":
            return self.respond(404)
        try:
            length = int(self.headers.get("Content-Length", ""))
            if not 1 <= length <= 2048:
                return self.respond(413)
            body = self.rfile.read(length)
            alert = validate(self.headers, body, self.server.signing_key)
            with closing(connect(self.server.database)) as db:
                accept(db, alert, body)
            return self.respond(202)
        except PermissionError:
            return self.respond(401)
        except (ValueError, sqlite3.IntegrityError):
            return self.respond(409)
        except (OSError, sqlite3.Error):
            return self.respond(503)

    def do_GET(self):
        # Liveness only; queue health is checked by the separately scheduled CLI.
        return self.respond(200 if self.path == "/live" else 404)

    def respond(self, status):
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()


def config_file(path):
    path = Path(path)
    if (path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077 or
            path.stat().st_uid != os.geteuid()):
        raise RuntimeError("Private receiver config required")
    config = json.loads(path.read_text())
    if (set(config) != {"smtp_host", "smtp_port", "smtp_user", "password_file", "from", "to",
                       "message_domain", "signing_key_file", "database"} or
            not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", config["smtp_host"]) or
            type(config["smtp_port"]) is not int or not 1 <= config["smtp_port"] <= 65535 or
            not isinstance(config["smtp_user"], str) or not config["smtp_user"] or
            not isinstance(config["to"], list) or not 1 <= len(config["to"]) <= 10 or
            not all(isinstance(a, str) and re.fullmatch(r"[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+", a)
                    for a in [config["from"], *config["to"]]) or
            not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", config["message_domain"])):
        raise ValueError("Invalid receiver configuration")
    for name in ("password_file", "signing_key_file"):
        file = Path(config[name])
        if (not file.is_absolute() or file.is_symlink() or not file.is_file() or
                file.stat().st_mode & 0o077 or file.stat().st_uid != os.geteuid()):
            raise RuntimeError("Private receiver credential required")
    database = Path(config["database"])
    if not database.is_absolute() or database.is_symlink():
        raise ValueError("Absolute receiver database path required")
    return config


def main():
    os.umask(0o077)
    if len(sys.argv) != 3 or sys.argv[1] not in ("serve", "dispatch", "health"):
        raise SystemExit("Usage: alert_receiver.py serve|dispatch|health /private/config.json")
    action, config = sys.argv[1], config_file(sys.argv[2])
    if action == "serve":
        key = Path(config["signing_key_file"]).read_bytes()
        if not 32 <= len(key) <= 4096:
            raise RuntimeError("Invalid signing key")
        server = ThreadingHTTPServer(("127.0.0.1", 9143), Handler)
        server.database = config["database"]
        server.signing_key = key
        server.serve_forever()
    else:
        with closing(connect(config["database"])) as db:
            if action == "dispatch":
                password = Path(config["password_file"]).read_text().strip()
                if not password:
                    raise RuntimeError("SMTP password required")
                print(json.dumps({"attempted": dispatch(db, config, password)}))
            result = health(db)
            print(json.dumps(result, sort_keys=True))
            if not result["healthy"]:
                raise SystemExit(2)


if __name__ == "__main__":
    main()

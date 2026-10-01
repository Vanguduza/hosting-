"""Isolated signed audit-event sink with durable tenant-chain verification."""
import hashlib
import hmac
import json
import os
import re
import sqlite3
import sys
import time
import uuid
from contextlib import closing
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY, organization_id TEXT NOT NULL,
 actor_sub TEXT NOT NULL, action TEXT NOT NULL,
 resource_id TEXT NOT NULL, request_id TEXT NOT NULL UNIQUE,
 previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL,
 created_at TEXT NOT NULL, body_sha256 TEXT NOT NULL,
 received_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS events_org_order ON events(organization_id,id);
CREATE TABLE IF NOT EXISTS heads (
 organization_id TEXT PRIMARY KEY, event_id INTEGER NOT NULL,
 event_hash TEXT NOT NULL
);
"""
HASH = re.compile(r"[a-f0-9]{64}\Z")


def connect(path):
    path = Path(path)
    if path.is_symlink() or not path.parent.is_dir():
        raise RuntimeError("Event sink state unavailable")
    db = sqlite3.connect(path, timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout=10000")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.executescript(SCHEMA)
    path.chmod(0o600)
    return db


def event_payload(headers, body, key, now=None):
    now = int(time.time() if now is None else now)
    stamp = headers.get("X-Dial-Event-Timestamp", "")
    signature = headers.get("X-Dial-Event-Signature", "")
    if (not 32 <= len(key) <= 4096 or not 1 <= len(body) <= 8192 or
            not re.fullmatch(r"[0-9]{10,11}", stamp) or abs(now - int(stamp)) > 300 or
            not re.fullmatch(r"v1=[a-f0-9]{64}", signature)):
        raise PermissionError("Invalid event authentication")
    expected = "v1=" + hmac.new(key, stamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise PermissionError("Invalid event authentication")
    try:
        event = json.loads(body)
        if type(event) is not dict or set(event) != {
                "id", "organization_id", "actor_sub", "action", "resource_id", "request_id",
                "previous_hash", "event_hash", "created_at"}:
            raise ValueError("Invalid event shape")
        if (type(event["id"]) is not int or not 1 <= event["id"] <= 9223372036854775807 or
                str(event["id"]) != headers.get("X-Dial-Event-Id") or
                any(str(uuid.UUID(event[name])) != event[name] for name in
                    ("organization_id", "resource_id", "request_id")) or
                not isinstance(event["actor_sub"], str) or not 1 <= len(event["actor_sub"]) <= 255 or
                not isinstance(event["action"], str) or not event["action"] or
                event["previous_hash"] != "" and not HASH.fullmatch(event["previous_hash"]) or
                not HASH.fullmatch(event["event_hash"])):
            raise ValueError("Invalid event fields")
        created = datetime.fromisoformat(event["created_at"])
        if created.tzinfo is None:
            raise ValueError("Event timestamp requires timezone")
        calculated = hashlib.sha256((event["previous_hash"] + event["actor_sub"] + event["action"] +
                                     event["resource_id"] + event["request_id"]).encode()).hexdigest()
        if calculated != event["event_hash"]:
            raise ValueError("Audit hash mismatch")
        return event
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError) as exc:
        raise ValueError("Invalid signed event") from exc


def accept(db, event, body, now=None):
    now = int(time.time() if now is None else now)
    digest = hashlib.sha256(body).hexdigest()
    db.execute("BEGIN IMMEDIATE")
    try:
        existing = db.execute("SELECT body_sha256 FROM events WHERE id=?", (event["id"],)).fetchone()
        if existing:
            if existing["body_sha256"] != digest:
                raise ValueError("Audit event ID collision")
            db.execute("COMMIT")
            return False
        head = db.execute("SELECT event_id,event_hash FROM heads WHERE organization_id=?",
                          (event["organization_id"],)).fetchone()
        if ((head and (event["id"] <= head["event_id"] or
                       event["previous_hash"] != head["event_hash"])) or
                (not head and event["previous_hash"] != "")):
            raise ValueError("Missing or reordered tenant audit event")
        db.execute("INSERT INTO events(id,organization_id,actor_sub,action,resource_id,request_id,"
                   "previous_hash,event_hash,created_at,body_sha256,received_at) "
                   "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                   (event["id"], event["organization_id"], event["actor_sub"], event["action"],
                    event["resource_id"], event["request_id"], event["previous_hash"],
                    event["event_hash"], event["created_at"], digest, now))
        db.execute("INSERT INTO heads(organization_id,event_id,event_hash) VALUES (?,?,?) "
                   "ON CONFLICT(organization_id) DO UPDATE SET event_id=excluded.event_id,"
                   "event_hash=excluded.event_hash",
                   (event["organization_id"], event["id"], event["event_hash"]))
        db.execute("COMMIT")
        return True
    except BaseException:
        db.execute("ROLLBACK")
        raise


def inspect(db, min_events=1):
    if type(min_events) is not int or min_events < 0:
        raise ValueError("Invalid event floor")
    if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise RuntimeError("Event sink database integrity failed")
    heads = {r["organization_id"]: (r["event_id"], r["event_hash"])
             for r in db.execute("SELECT * FROM heads")}
    previous = {}
    count = 0
    for row in db.execute("SELECT * FROM events ORDER BY id"):
        prior = previous.get(row["organization_id"], (0, ""))
        calculated = hashlib.sha256((prior[1] + row["actor_sub"] + row["action"] +
                                     row["resource_id"] + row["request_id"]).encode()).hexdigest()
        if row["id"] <= prior[0] or row["previous_hash"] != prior[1] or row["event_hash"] != calculated:
            raise RuntimeError("Stored tenant audit chain invalid")
        previous[row["organization_id"]] = (row["id"], row["event_hash"])
        count += 1
    if heads != previous:
        raise RuntimeError("Stored audit heads differ from event history")
    return {"events": count, "organizations": len(heads), "min_events": min_events,
            "healthy": count >= min_events}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/ingest":
            return self.respond(404)
        try:
            length = int(self.headers.get("Content-Length", ""))
            if not 1 <= length <= 8192:
                return self.respond(413)
            body = self.rfile.read(length)
            event = event_payload(self.headers, body, self.server.signing_key)
            with closing(connect(self.server.database)) as db:
                accept(db, event, body)
            return self.respond(202)
        except PermissionError:
            return self.respond(401)
        except (ValueError, sqlite3.IntegrityError):
            return self.respond(409)
        except (OSError, sqlite3.Error):
            return self.respond(503)

    def do_GET(self):
        return self.respond(200 if self.path == "/live" else 404)

    def respond(self, status):
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()


def private_file(path):
    path = Path(path)
    if (path.is_symlink() or not path.is_file() or path.stat().st_uid != os.geteuid() or
            path.stat().st_mode & 0o077):
        raise RuntimeError("Private event receiver file required")
    return path


def main():
    os.umask(0o077)
    if len(sys.argv) != 4 or sys.argv[1] not in ("serve", "health"):
        raise SystemExit("Usage: event_receiver.py serve|health /private/key /private/database")
    action, key_path, database = sys.argv[1:]
    database = Path(database)
    if not database.is_absolute() or database.is_symlink():
        raise RuntimeError("Absolute event receiver database required")
    if action == "serve":
        key = private_file(key_path).read_bytes()
        if not 32 <= len(key) <= 4096:
            raise RuntimeError("Invalid event receiver key")
        server = ThreadingHTTPServer(("127.0.0.1", 9152), Handler)
        server.database, server.signing_key = database, key
        server.serve_forever()
    else:
        with closing(connect(database)) as db:
            result = inspect(db, int(os.environ.get("EVENT_RECEIVER_MIN_EVENTS", "1")))
        print(json.dumps(result, sort_keys=True))
        if not result["healthy"]:
            raise SystemExit(2)


if __name__ == "__main__":
    main()

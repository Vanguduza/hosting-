#!/usr/bin/env python3
"""Durable, independently dispatched state changes from operator checks."""
import argparse
import hashlib
import hmac
import http.client
import json
import os
import secrets
import sqlite3
import ssl
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit


CHECKS = {"release", "node", "event", "external"}
SCHEMA = """
CREATE TABLE IF NOT EXISTS checks (
 name TEXT PRIMARY KEY, state TEXT NOT NULL CHECK(state IN ('UP','DOWN')),
 sequence INTEGER NOT NULL CHECK(sequence>=0), observed_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, sequence INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('UP','DOWN')),
 created_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
 next_at INTEGER NOT NULL, lease_token TEXT, lease_until INTEGER,
 delivered_at INTEGER, last_error TEXT,
 UNIQUE(name,sequence), CHECK((lease_token IS NULL)=(lease_until IS NULL))
);
CREATE INDEX IF NOT EXISTS alerts_due ON alerts(next_at,created_at)
 WHERE delivered_at IS NULL AND attempts<12;
"""


def connect(path):
    path = Path(path)
    if path.is_symlink() or not path.parent.is_dir():
        raise RuntimeError("Alert state directory unavailable")
    if path.exists() and (path.stat().st_mode & 0o077):
        raise RuntimeError("Alert database must be private")
    db = sqlite3.connect(path, timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout=10000")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.executescript(SCHEMA)
    if "observed_at" not in {row["name"] for row in db.execute("PRAGMA table_info(checks)")}:
        db.execute("ALTER TABLE checks ADD COLUMN observed_at INTEGER NOT NULL DEFAULT 0")
    path.chmod(0o600)
    return db


def observe(db, name, healthy, now=None):
    if name not in CHECKS or type(healthy) is not bool:
        raise ValueError("Unknown check or result")
    now = int(time.time() if now is None else now)
    state = "UP" if healthy else "DOWN"
    db.execute("BEGIN IMMEDIATE")
    try:
        previous = db.execute("SELECT state,sequence FROM checks WHERE name=?", (name,)).fetchone()
        if previous is None:
            db.execute("INSERT INTO checks(name,state,sequence,observed_at) VALUES (?,?,0,?)", (name, state, now))
            sequence = 0
        elif previous["state"] == state:
            db.execute("UPDATE checks SET observed_at=? WHERE name=?", (now, name))
            db.execute("COMMIT")
            return None
        else:
            sequence = previous["sequence"] + 1
            db.execute("UPDATE checks SET state=?,sequence=?,observed_at=? WHERE name=?",
                       (state, sequence, now, name))
        # Establishing a healthy baseline is not an incident. A first failed
        # check is an incident and must be delivered even without prior state.
        alert_id = None
        if state == "DOWN" or previous is not None:
            alert_id = str(uuid.uuid4())
            db.execute("INSERT INTO alerts(id,name,sequence,state,created_at,next_at) "
                       "VALUES (?,?,?,?,?,?)", (alert_id, name, sequence, state, now, now))
        db.execute("COMMIT")
        return alert_id
    except BaseException:
        db.execute("ROLLBACK")
        raise


def run_check(db, name, command, timeout):
    if name not in CHECKS or not command or not 1 <= timeout <= 240:
        raise ValueError("Invalid check invocation")
    try:
        completed = subprocess.run(command, timeout=timeout, check=False)
        healthy = completed.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        healthy = False
    observe(db, name, healthy)
    return 0 if healthy else 2


def destination(value):
    url = urlsplit(value)
    try:
        port = url.port
    except ValueError as exc:
        raise ValueError("Invalid alert receiver port") from exc
    if (url.scheme != "https" or not url.hostname or url.username or url.password or
            url.query or url.fragment or not url.path.startswith("/") or
            url.hostname.endswith(".") or url.hostname == "localhost" or port == 0):
        raise ValueError("Alert receiver requires a fixed HTTPS URL")
    return url


def claim(db, now=None):
    now = int(time.time() if now is None else now)
    db.execute("BEGIN IMMEDIATE")
    try:
        row = db.execute("SELECT a.* FROM alerts a WHERE a.delivered_at IS NULL AND a.attempts<12 "
                         "AND a.next_at<=? AND (a.lease_until IS NULL OR a.lease_until<?) "
                         "AND NOT EXISTS (SELECT 1 FROM alerts prior WHERE prior.name=a.name "
                         "AND prior.sequence<a.sequence AND prior.delivered_at IS NULL) "
                         "ORDER BY a.created_at,a.name,a.sequence LIMIT 1", (now, now)).fetchone()
        if row is None:
            db.execute("COMMIT")
            return None
        token = secrets.token_hex(16)
        db.execute("UPDATE alerts SET attempts=attempts+1,lease_token=?,lease_until=? WHERE id=?",
                   (token, now + 60, row["id"]))
        db.execute("COMMIT")
        return dict(row) | {"attempts": row["attempts"] + 1, "lease_token": token}
    except BaseException:
        db.execute("ROLLBACK")
        raise


def deliver(row, url, key):
    body = json.dumps({"id": row["id"], "check": row["name"],
                       "sequence": row["sequence"], "state": row["state"],
                       "created_at": row["created_at"]}, separators=(",", ":")).encode()
    stamp = str(int(time.time()))
    signature = hmac.new(key, stamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    conn = http.client.HTTPSConnection(url.hostname, url.port or 443,
                                       context=ssl.create_default_context(), timeout=10)
    try:
        conn.request("POST", url.path, body=body, headers={
            "Content-Type": "application/json", "X-Dial-Alert-Id": row["id"],
            "X-Dial-Alert-Timestamp": stamp, "X-Dial-Alert-Signature": "v1=" + signature})
        response = conn.getresponse()
        response.read(4096)
        if response.status < 200 or response.status >= 300:
            raise RuntimeError("Alert receiver HTTP %d" % response.status)
    finally:
        conn.close()


def finalize(db, row, error=None, now=None):
    now = int(time.time() if now is None else now)
    db.execute("BEGIN IMMEDIATE")
    try:
        if error is None:
            changed = db.execute("UPDATE alerts SET delivered_at=?,lease_token=NULL,"
                                 "lease_until=NULL,last_error=NULL WHERE id=? AND lease_token=?",
                                 (now, row["id"], row["lease_token"]))
        else:
            delay = min(2 ** min(row["attempts"], 10), 3600)
            changed = db.execute("UPDATE alerts SET next_at=?,lease_token=NULL,"
                                 "lease_until=NULL,last_error=? WHERE id=? AND lease_token=?",
                                 (now + delay, str(error)[:160], row["id"], row["lease_token"]))
        db.execute("COMMIT")
        return changed.rowcount == 1
    except BaseException:
        db.execute("ROLLBACK")
        raise


def dispatch(db, url, key, limit=100):
    if not 32 <= len(key) <= 4096:
        raise ValueError("Alert signing key must contain 32–4096 bytes")
    count = 0
    for _ in range(limit):
        row = claim(db)
        if row is None:
            break
        try:
            deliver(row, url, key)
            finalize(db, row)
        except (OSError, ssl.SSLError, http.client.HTTPException, RuntimeError) as exc:
            finalize(db, row, type(exc).__name__ + ": " + str(exc))
        count += 1
    return count


def health(db, max_age=300):
    if not 60 <= max_age <= 86400:
        raise ValueError("Invalid alert age")
    now = int(time.time())
    rows = db.execute("SELECT name,id,attempts,created_at FROM alerts WHERE delivered_at IS NULL").fetchall()
    observations = {row["name"]: row["observed_at"] for row in
                    db.execute("SELECT name,observed_at FROM checks")}
    seen = observations.keys()
    stale_checks = sorted(name for name, observed_at in observations.items()
                          if observed_at > now + 60 or now - observed_at > max_age)
    return {"pending": len(rows), "dead": [row["id"] for row in rows if row["attempts"] >= 12],
            "stale": [row["id"] for row in rows if now - row["created_at"] > max_age],
            "checks_seen": sorted(seen), "checks_missing": sorted(CHECKS - seen),
            "checks_stale": stale_checks, "healthy": set(seen) == CHECKS and not stale_checks and
                       not any(row["attempts"] >= 12 or now - row["created_at"] > max_age for row in rows)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default="/var/lib/dial-hosting-monitor/alerts.sqlite3")
    sub = parser.add_subparsers(dest="action", required=True)
    runner = sub.add_parser("run")
    runner.add_argument("name", choices=sorted(CHECKS))
    runner.add_argument("--timeout", type=int, default=45)
    runner.add_argument("command", nargs=argparse.REMAINDER)
    sub.add_parser("dispatch")
    checker = sub.add_parser("health")
    checker.add_argument("--max-age", type=int, default=300)
    args = parser.parse_args()
    db = connect(args.database)
    if args.action == "run":
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        return run_check(db, args.name, command, args.timeout)
    if args.action == "health":
        result = health(db, args.max_age)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["healthy"] else 2
    key_file = Path(os.environ["ALERT_SIGNING_KEY_FILE"])
    if key_file.is_symlink() or not key_file.is_file() or key_file.stat().st_mode & 0o077:
        raise RuntimeError("Alert signing key must be a private regular file")
    key = key_file.read_bytes()
    url = destination(os.environ["ALERT_RECEIVER_URL"])
    print(json.dumps({"attempted": dispatch(db, url, key)}))
    return 0 if health(db)["healthy"] else 2


if __name__ == "__main__":
    sys.exit(main())

"""Ordered, at-least-once HTTPS delivery of committed control-plane audit facts."""
import hashlib
import hmac
import http.client
import json
import os
import ssl
import time
import uuid
from urllib.parse import urlsplit

import psycopg
from psycopg.rows import dict_row

from .__main__ import database_dsn
from .migrate import verify


def endpoint(value):
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid event sink port") from exc
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or
            parsed.fragment or parsed.query or not parsed.path.startswith("/") or
            parsed.hostname.endswith(".") or parsed.hostname == "localhost" or port == 0):
        raise ValueError("Event sink requires a fixed HTTPS URL with a path and no query or credentials")
    return parsed


def claim(conn, organization_id=None):
    """Lease the earliest available event in one tenant, with no earlier gap."""
    with conn.transaction():
        # A process may die after taking its tenth lease. Mark those rows dead
        # before claiming; incrementing once more would violate the bound.
        conn.execute(
            "UPDATE hosting.event_outbox SET state='DEAD',lease_token=NULL,lease_until=NULL,"
            "last_error='Delivery lease expired after final attempt' "
            "WHERE audit_event_id IN (SELECT audit_event_id FROM hosting.event_outbox "
            "WHERE state='PENDING' AND attempts=10 AND lease_until<now() "
            "ORDER BY lease_until FOR UPDATE SKIP LOCKED LIMIT 100)"
        )
        row = conn.execute(
            "SELECT o.audit_event_id,o.organization_id,o.attempts,a.actor_sub,a.action,"
            "a.resource_id,a.request_id,a.previous_hash,a.event_hash,a.created_at "
            "FROM hosting.event_outbox o JOIN hosting.audit_events a ON a.id=o.audit_event_id "
            "WHERE o.state='PENDING' AND o.next_attempt_at<=now() "
            "AND (%s::uuid IS NULL OR o.organization_id=%s) "
            "AND (o.lease_until IS NULL OR o.lease_until<now()) "
            "AND NOT EXISTS (SELECT 1 FROM hosting.event_outbox preceding "
            "WHERE preceding.organization_id=o.organization_id AND preceding.audit_event_id<o.audit_event_id "
            "AND preceding.state<>'DELIVERED') "
            "ORDER BY o.next_attempt_at,o.audit_event_id FOR UPDATE OF o SKIP LOCKED LIMIT 1",
            (organization_id, organization_id)
        ).fetchone()
        if not row:
            return None
        token = uuid.uuid4()
        conn.execute("UPDATE hosting.event_outbox SET attempts=attempts+1,lease_token=%s,"
                     "lease_until=now()+interval '60 seconds' WHERE audit_event_id=%s",
                     (token, row["audit_event_id"]))
        return row | {"attempts": row["attempts"] + 1, "lease_token": token}


def deliver(row, destination, secret, now=None):
    body = json.dumps({
        "id": row["audit_event_id"], "organization_id": str(row["organization_id"]),
        "actor_sub": row["actor_sub"], "action": row["action"],
        "resource_id": str(row["resource_id"]), "request_id": str(row["request_id"]),
        "previous_hash": row["previous_hash"], "event_hash": row["event_hash"],
        "created_at": row["created_at"].isoformat(),
    }, separators=(",", ":")).encode()
    timestamp = str(int(time.time() if now is None else now))
    signature = hmac.new(secret, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    context = ssl.create_default_context()
    connection = http.client.HTTPSConnection(destination.hostname, destination.port or 443,
                                             context=context, timeout=10)
    try:
        path = destination.path
        connection.request("POST", path, body=body, headers={
            "Content-Type": "application/json", "X-Dial-Event-Id": str(row["audit_event_id"]),
            "X-Dial-Event-Timestamp": timestamp, "X-Dial-Event-Signature": "v1=" + signature,
        })
        response = connection.getresponse()
        response.read(4096)
        if not 200 <= response.status < 300:
            raise RuntimeError("Event sink rejected delivery (HTTP %d)" % response.status)
    finally:
        connection.close()


def finalize(conn, row, failure=None):
    with conn.transaction():
        if failure is None:
            changed = conn.execute(
                "UPDATE hosting.event_outbox SET state='DELIVERED',delivered_at=now(),"
                "lease_token=NULL,lease_until=NULL,last_error=NULL WHERE audit_event_id=%s "
                "AND state='PENDING' AND lease_token=%s AND attempts=%s RETURNING audit_event_id",
                (row["audit_event_id"], row["lease_token"], row["attempts"])).fetchone()
        else:
            dead = row["attempts"] >= 10
            delay = min(2 ** min(row["attempts"], 8), 300)
            changed = conn.execute(
                "UPDATE hosting.event_outbox SET state=%s,next_attempt_at=now()+(%s * interval '1 second'),"
                "lease_token=NULL,lease_until=NULL,last_error=%s WHERE audit_event_id=%s "
                "AND state='PENDING' AND lease_token=%s AND attempts=%s RETURNING audit_event_id",
                ("DEAD" if dead else "PENDING", delay, str(failure)[:160], row["audit_event_id"],
                 row["lease_token"], row["attempts"])).fetchone()
        return changed is not None


def process_once(conn, destination, secret):
    row = claim(conn)
    if not row:
        return False
    try:
        deliver(row, destination, secret)
        finalize(conn, row)
    except (OSError, ssl.SSLError, http.client.HTTPException, RuntimeError) as exc:
        finalize(conn, row, type(exc).__name__ + ": " + str(exc))
    return True


def main():
    if os.environ.get("DB_USER") != "hosting_worker":
        raise RuntimeError("Event delivery requires the restricted worker role")
    destination = endpoint(os.environ["EVENT_SINK_URL"])
    with open(os.environ["EVENT_SINK_SECRET_FILE"], "rb") as file:
        secret = file.read()
    if len(secret) < 32 or len(secret) > 4096:
        raise RuntimeError("Event sink signing secret must contain 32–4096 bytes")
    with psycopg.connect(database_dsn(), connect_timeout=5) as conn:
        verify(conn)
    while True:
        try:
            with psycopg.connect(database_dsn(), row_factory=dict_row, autocommit=True,
                                 connect_timeout=5) as conn:
                did_work = process_once(conn, destination, secret)
            if not did_work:
                time.sleep(2)
        except psycopg.Error:
            time.sleep(5)


if __name__ == "__main__":
    main()

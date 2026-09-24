"""Operator-only targeted replay of one committed delivery; records who and why."""
import argparse
import os
import sys
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/api"))
from hosting_api.__main__ import database_dsn
from hosting_api.migrate import SERVICE_ROLES, verify


def replay(conn, event_id, operator, reason):
    if len(operator) not in range(1, 129) or len(reason) not in range(10, 501):
        raise ValueError("Operator name or reason length invalid")
    with conn.transaction():
        event = conn.execute("SELECT state,organization_id FROM hosting.event_outbox "
                             "WHERE audit_event_id=%s FOR UPDATE", (event_id,)).fetchone()
        if not event or event["state"] not in ("DEAD", "DELIVERED"):
            raise ValueError("Event must exist and be DEAD or DELIVERED")
        conn.execute("UPDATE hosting.event_outbox SET state='PENDING',attempts=0,"
                     "next_attempt_at=now(),lease_token=NULL,lease_until=NULL,delivered_at=NULL,last_error=NULL "
                     "WHERE audit_event_id=%s", (event_id,))
        conn.execute("INSERT INTO hosting.event_replays(audit_event_id,operator_name,reason) "
                     "VALUES (%s,%s,%s)", (event_id, operator, reason))
        return event["organization_id"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("event_id", type=int)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--confirm", required=True, choices=["replay_event"])
    args = parser.parse_args()
    if args.event_id < 1 or os.environ.get("DB_USER") in SERVICE_ROLES:
        raise RuntimeError("Positive event ID and protected operator database credentials required")
    with psycopg.connect(database_dsn(), row_factory=dict_row, connect_timeout=5) as conn:
        verify(conn)
        org = replay(conn, args.event_id, args.operator, args.reason)
    print(f"Event {args.event_id} queued for tenant {org}; receiver must deduplicate by event ID")


if __name__ == "__main__":
    main()

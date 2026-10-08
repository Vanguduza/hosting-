"""Machine-readable readiness probe for the committed-event delivery backlog."""
import argparse
import json
import os
import sys
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/api"))
from hosting_api.__main__ import database_dsn
from hosting_api.migrate import verify


def status(conn, max_age_seconds, max_pending):
    row = conn.execute(
        "SELECT count(*) FILTER (WHERE o.state='PENDING') AS pending,"
        "count(*) FILTER (WHERE o.state='DEAD') AS dead,"
        "coalesce(extract(epoch from now()-min(a.created_at) "
        "FILTER (WHERE o.state<>'DELIVERED')),0) AS oldest_outstanding_seconds "
        "FROM hosting.event_outbox o JOIN hosting.audit_events a ON a.id=o.audit_event_id"
    ).fetchone()
    result = {"pending": row["pending"], "dead": row["dead"],
              "oldest_outstanding_seconds": int(row["oldest_outstanding_seconds"]),
              "max_age_seconds": max_age_seconds, "max_pending": max_pending}
    result["healthy"] = (result["dead"] == 0 and result["pending"] <= max_pending and
                         result["oldest_outstanding_seconds"] <= max_age_seconds)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-age-seconds", type=int, default=300)
    parser.add_argument("--max-pending", type=int, default=1000)
    args = parser.parse_args()
    if args.max_age_seconds < 1 or args.max_pending < 0 or os.environ.get("DB_USER") != "hosting_worker":
        raise RuntimeError("Positive thresholds and restricted worker credentials required")
    with psycopg.connect(database_dsn(), row_factory=dict_row, connect_timeout=5) as conn:
        verify(conn)
        result = status(conn, args.max_age_seconds, args.max_pending)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["healthy"] else 2)


if __name__ == "__main__":
    main()

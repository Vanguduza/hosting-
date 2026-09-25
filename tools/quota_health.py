"""Read-only operator check for missing or below-reservation tenant quotas."""
import argparse
import json
import os
import sys
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/api"))
from hosting_api.__main__ import database_dsn
from hosting_api.migrate import SERVICE_ROLES, verify


def inspect(conn):
    rows = conn.execute(
        "SELECT o.id, q.cpu_milli_limit, q.memory_mb_limit,"
        "coalesce(sum(c.cpu_milli),0) AS cpu_milli_reserved,"
        "coalesce(sum(c.memory_mb),0) AS memory_mb_reserved "
        "FROM hosting.organizations o LEFT JOIN hosting.organization_quotas q "
        "ON q.organization_id=o.id LEFT JOIN hosting.capacity_intervals c "
        "ON c.organization_id=o.id AND c.ended_at IS NULL "
        "GROUP BY o.id,q.cpu_milli_limit,q.memory_mb_limit ORDER BY o.id"
    ).fetchall()
    missing = [str(row["id"]) for row in rows if row["cpu_milli_limit"] is None]
    over = [str(row["id"]) for row in rows if row["cpu_milli_limit"] is not None and
            (row["cpu_milli_reserved"] > row["cpu_milli_limit"] or
             row["memory_mb_reserved"] > row["memory_mb_limit"])]
    return {"organizations": len(rows), "unbounded": missing, "over_limit": over,
            "healthy": not missing and not over}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    if os.environ.get("DB_USER") in SERVICE_ROLES:
        raise RuntimeError("Protected operator read credentials required")
    with psycopg.connect(database_dsn(), row_factory=dict_row, connect_timeout=5) as conn:
        verify(conn)
        result = inspect(conn)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["healthy"] else 2)


if __name__ == "__main__":
    main()

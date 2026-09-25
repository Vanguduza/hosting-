#!/usr/bin/env python3
"""Read-only operator check for stale or unhealthy public release observations."""
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


def status(conn, max_age_seconds=180, min_applications=0):
    if not 30 <= max_age_seconds <= 86400 or not 0 <= min_applications <= 100000:
        raise ValueError("Invalid release health threshold")
    rows = conn.execute(
        "SELECT a.organization_id,a.id AS application_id,a.active_release_id,"
        "r.state AS release_state,h.state AS health_state,h.checked_at,"
        "(h.checked_at IS NULL OR h.checked_at < now()-(%s * interval '1 second')) AS stale "
        "FROM hosting.applications a LEFT JOIN hosting.releases r ON r.id=a.active_release_id "
        "LEFT JOIN hosting.release_health h ON h.release_id=a.active_release_id "
        "WHERE a.traffic_state='ACTIVE' AND a.active_release_id IS NOT NULL "
        "ORDER BY a.organization_id,a.id", (max_age_seconds,)).fetchall()
    result = {"active_applications": len(rows), "min_applications": min_applications,
              "max_age_seconds": max_age_seconds, "missing": [], "stale": [],
              "unavailable": [], "degraded": [], "inconsistent": []}
    for row in rows:
        identity = {"organization_id": str(row["organization_id"]),
                    "application_id": str(row["application_id"]),
                    "release_id": str(row["active_release_id"])}
        if row["release_state"] != "SERVING":
            result["inconsistent"].append(identity)
        if row["health_state"] is None:
            result["missing"].append(identity)
        elif row["stale"]:
            result["stale"].append(identity)
        elif row["health_state"] == "DOWN":
            result["unavailable"].append(identity)
        elif row["health_state"] in ("DEGRADED", "UNKNOWN"):
            result["degraded"].append(identity)
    result["healthy"] = (len(rows) >= min_applications and not any(result[key] for key in
                         ("missing", "stale", "unavailable", "degraded", "inconsistent")))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-age-seconds", type=int, default=180)
    parser.add_argument("--min-applications", type=int, default=0)
    args = parser.parse_args()
    if os.environ.get("DB_USER") != "hosting_worker":
        raise RuntimeError("Restricted worker read credentials required")
    with psycopg.connect(database_dsn(), row_factory=dict_row, connect_timeout=5) as conn:
        verify(conn)
        result = status(conn, args.max_age_seconds, args.min_applications)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["healthy"] else 2)


if __name__ == "__main__":
    main()

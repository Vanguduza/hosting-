#!/usr/bin/env python3
"""Read-only fleet check for stale node observations and missing ingress."""
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


def status(conn, max_age_seconds=300, min_nodes=1):
    if type(max_age_seconds) is not int or not 30 <= max_age_seconds <= 86400 or \
            type(min_nodes) is not int or not 0 <= min_nodes <= 100000:
        raise ValueError("Invalid node health threshold")
    rows = conn.execute(
        "SELECT id,public_ipv4,observed_at,cpu_milli,memory_mb,"
        "reserved_cpu_milli,reserved_memory_mb,"
        "observed_at<now()-(%s * interval '1 second') AS stale,"
        "observed_at>now()+interval '1 minute' AS future "
        "FROM hosting.nodes WHERE enabled ORDER BY id", (max_age_seconds,)).fetchall()
    result = {"enabled_nodes": len(rows), "min_nodes": min_nodes,
              "max_age_seconds": max_age_seconds, "stale": [], "future": [],
              "missing_ingress": [], "disabled_assigned": [], "available_capacity": []}
    for row in rows:
        node_id = str(row["id"])
        if row["stale"]:
            result["stale"].append(node_id)
        if row["future"]:
            result["future"].append(node_id)
        if row["public_ipv4"] is None:
            result["missing_ingress"].append(node_id)
        result["available_capacity"].append({
            "node_id": node_id,
            "cpu_milli": row["cpu_milli"] - row["reserved_cpu_milli"],
            "memory_mb": row["memory_mb"] - row["reserved_memory_mb"]})
    disabled = conn.execute(
        "SELECT n.id FROM hosting.nodes n WHERE NOT n.enabled AND ("
        "EXISTS (SELECT 1 FROM hosting.releases r WHERE r.node_id=n.id "
        "AND (r.state IN ('QUEUED','DEPLOYING','SERVING','SUPERSEDED') "
        "OR (r.state='FAILED' AND r.cleanup_at IS NULL))) OR "
        "EXISTS (SELECT 1 FROM hosting.postgres_instances p WHERE p.node_id=n.id) OR "
        "EXISTS (SELECT 1 FROM hosting.valkey_instances v WHERE v.node_id=n.id) OR "
        "EXISTS (SELECT 1 FROM hosting.object_storage_instances s WHERE s.node_id=n.id)) "
        "ORDER BY n.id").fetchall()
    result["disabled_assigned"] = [str(row["id"]) for row in disabled]
    result["healthy"] = (len(rows) >= min_nodes and not result["stale"] and
                         not result["future"] and not result["missing_ingress"] and
                         not result["disabled_assigned"])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-age-seconds", type=int, default=300)
    parser.add_argument("--min-nodes", type=int, default=1)
    args = parser.parse_args()
    if os.environ.get("DB_USER") != "hosting_worker":
        raise RuntimeError("Restricted worker read credentials required")
    with psycopg.connect(database_dsn(), row_factory=dict_row, connect_timeout=5) as conn:
        verify(conn)
        result = status(conn, args.max_age_seconds, args.min_nodes)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["healthy"] else 2)


if __name__ == "__main__":
    main()

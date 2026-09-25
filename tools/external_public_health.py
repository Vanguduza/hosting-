#!/usr/bin/env python3
"""Read-only public probes from a supervised operator monitor."""
import argparse
import concurrent.futures
import http.client
import json
import os
import ssl
import sys
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/api"))
from hosting_api.__main__ import database_dsn
from hosting_api.migrate import verify
from hosting_api.worker import address_proves, public_probe


def probe(row):
    """Return a bounded reason without emitting tenant hostnames or credentials."""
    if not row["hostname"] or not row["verified_at"] or not row["public_ipv4"]:
        return "configuration"
    if not address_proves(row["hostname"], row["public_ipv4"]):
        return "dns"
    try:
        if public_probe(row["hostname"], row["public_ipv4"],
                        row["release_id"], row["health_path"]):
            return None
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError):
        pass
    return "https"


def status(conn, min_applications=1):
    if type(min_applications) is not int or not 0 <= min_applications <= 100000:
        raise ValueError("Invalid active application floor")
    rows = conn.execute(
        "SELECT a.id AS application_id,r.id AS release_id,r.health_path,"
        "d.hostname,d.verified_at,n.public_ipv4 FROM hosting.applications a "
        "JOIN hosting.releases r ON r.id=a.active_release_id AND r.state='SERVING' "
        "LEFT JOIN hosting.domains d ON d.application_id=a.id "
        "LEFT JOIN hosting.nodes n ON n.id=r.node_id "
        "WHERE a.traffic_state='ACTIVE' ORDER BY a.id").fetchall()
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        reasons = list(pool.map(probe, rows))
    failures = [{"application_id": str(row["application_id"]), "reason": reason}
                for row, reason in zip(rows, reasons) if reason]
    return {"active_applications": len(rows), "min_applications": min_applications,
            "failed": failures, "healthy": len(rows) >= min_applications and not failures}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--min-applications", type=int, default=1)
    args = parser.parse_args()
    if os.environ.get("DB_USER") != "hosting_worker":
        raise RuntimeError("Restricted worker read credentials required")
    with psycopg.connect(database_dsn(), row_factory=dict_row, connect_timeout=5) as conn:
        verify(conn)
        result = status(conn, args.min_applications)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["healthy"] else 2)


if __name__ == "__main__":
    main()

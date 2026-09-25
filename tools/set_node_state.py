#!/usr/bin/env python3
"""Audited operator placement change for an empty node or live re-enrollment."""
import argparse
import ipaddress
import json
import os
import sys
import uuid

import psycopg
from psycopg.rows import dict_row

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "services", "api")))
from hosting_api.migrate import SERVICE_ROLES, verify
from hosting_api.worker import node_capacity


def set_state(conn, node_id, enabled, operator, reason, certificate=None):
    if not 2 <= len(operator) <= 120 or not 3 <= len(reason) <= 500:
        raise ValueError("Operator and reason required")
    # A live private mTLS observation is mandatory when returning a node to placement.
    observed = None
    if enabled:
        node = conn.execute("SELECT endpoint,server_name,public_ipv4 FROM hosting.nodes WHERE id=%s",
                            (node_id,)).fetchone()
        if not node or not node["public_ipv4"] or not ipaddress.IPv4Address(
                str(node["public_ipv4"])).is_global:
            raise ValueError("Registered public ingress required")
        if certificate is None:
            raise ValueError("Private mTLS certificate required")
        observed = node_capacity(node, certificate)
    with conn.transaction():
        locked = conn.execute("SELECT endpoint,server_name,public_ipv4,enabled,reserved_cpu_milli,"
                              "reserved_memory_mb FROM hosting.nodes WHERE id=%s FOR UPDATE",
                              (node_id,)).fetchone()
        if not locked:
            raise ValueError("Unknown node")
        if locked["enabled"] == enabled:
            return False
        if enabled:
            if (locked["endpoint"], locked["server_name"], locked["public_ipv4"]) != (
                    node["endpoint"], node["server_name"], node["public_ipv4"]):
                raise ValueError("Node identity changed during live probe")
            if (observed["cpu_milli"] < locked["reserved_cpu_milli"] or
                    observed["memory_mb"] < locked["reserved_memory_mb"]):
                raise ValueError("Live capacity below existing reservations")
            conn.execute("UPDATE hosting.nodes SET enabled=true,cpu_milli=%s,memory_mb=%s,"
                         "observed_at=now() WHERE id=%s",
                         (observed["cpu_milli"], observed["memory_mb"], node_id))
        else:
            assigned = conn.execute(
                "SELECT (EXISTS (SELECT 1 FROM hosting.releases WHERE node_id=%s "
                "AND (state IN ('QUEUED','DEPLOYING','SERVING','SUPERSEDED') "
                "OR (state='FAILED' AND cleanup_at IS NULL))) "
                "OR EXISTS (SELECT 1 FROM hosting.postgres_instances WHERE node_id=%s) "
                "OR EXISTS (SELECT 1 FROM hosting.valkey_instances WHERE node_id=%s) "
                "OR EXISTS (SELECT 1 FROM hosting.object_storage_instances WHERE node_id=%s)) AS busy",
                (node_id, node_id, node_id, node_id)).fetchone()["busy"]
            if assigned or locked["reserved_cpu_milli"] or locked["reserved_memory_mb"]:
                raise ValueError("Node still has assigned workloads or reservations")
            conn.execute("UPDATE hosting.nodes SET enabled=false WHERE id=%s", (node_id,))
        conn.execute("INSERT INTO hosting.node_state_changes(node_id,enabled,operator,reason) "
                     "VALUES (%s,%s,%s,%s)", (node_id, enabled, operator, reason))
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("node_id", type=uuid.UUID)
    parser.add_argument("--state", choices=("enabled", "disabled"), required=True)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--ca-file")
    parser.add_argument("--cert-file")
    parser.add_argument("--key-file")
    parser.add_argument("--confirm", choices=("set_node_state",), required=True)
    args = parser.parse_args()
    if args.state == "enabled" and not all((args.ca_file, args.cert_file, args.key_file)):
        parser.error("Live re-enrollment requires --ca-file, --cert-file and --key-file")
    dsn = os.environ.get("HOSTING_MIGRATION_DSN")
    if not dsn:
        parser.error("HOSTING_MIGRATION_DSN required")
    with psycopg.connect(dsn, row_factory=dict_row, connect_timeout=5, autocommit=True) as conn:
        role = conn.execute("SELECT current_user").fetchone()["current_user"]
        if role in SERVICE_ROLES:
            raise RuntimeError("Protected operator credentials required")
        verify(conn)
        changed = set_state(conn, args.node_id, args.state == "enabled", args.operator,
                            args.reason, {"ca": args.ca_file, "cert": args.cert_file,
                                          "key": args.key_file} if args.state == "enabled" else None)
    print(json.dumps({"node_id": str(args.node_id), "state": args.state, "changed": changed}))


if __name__ == "__main__":
    main()
